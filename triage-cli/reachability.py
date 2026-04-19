"""Phase 3: cross-file reachability analysis.

For each finding that Phase 1 classified as a true positive, walk the
caller graph upward (up to a fixed depth) and ask Claude whether untrusted
input can actually reach the sink.

This is where AI earns its keep over raw Semgrep: Semgrep's free tier does
per-file pattern matching, so it can't tell you that a vulnerable function
in `utils.py` is (a) called from a route handler that passes user input, or
(b) not called from anywhere at all and is therefore dead code.

The analysis is deliberately lightweight:
  - Caller discovery uses regex on the source files (no AST).
  - Depth is capped to keep token use bounded.
  - The LLM does the semantic work of deciding what's an "entry point"
    (route handler, CLI entry, task queue consumer, etc).
"""

from __future__ import annotations

import json
import pathlib
import re
import time
from dataclasses import dataclass
from typing import Optional

from anthropic import Anthropic


SOURCE_GLOBS = ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx")
MAX_CALLERS_PER_FUNCTION = 6  # avoid exploding context in huge codebases
MAX_DEPTH = 2                 # how far up the caller graph we walk
SNIPPET_RADIUS = 6            # lines of context around each call site


# ---------------------------------------------------------------------------
# Source navigation (no AST; grep-ish but good enough for a demo)
# ---------------------------------------------------------------------------

# Matches `def name(` (Python) or `function name(` or `name = ... =>` etc.
# We keep it simple: a leading `def ` / `function ` or a preceding `async`.
_DEF_PATTERNS = [
    re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
    re.compile(r"^\s*(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
    re.compile(r"^\s*(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*="),
]


def iter_source_files(root: pathlib.Path):
    for pat in SOURCE_GLOBS:
        yield from root.rglob(pat)


def _indent_of(s: str) -> int:
    """Number of leading spaces (tabs counted as 4). Blank/comment-only lines
    return a sentinel of -1 so callers can skip them."""
    stripped = s.lstrip(" \t")
    if not stripped:
        return -1
    # Expand tabs deterministically so mixed-indent files don't confuse us.
    expanded = s.expandtabs(4)
    return len(expanded) - len(expanded.lstrip(" "))


def containing_function(path: pathlib.Path, line: int) -> Optional[tuple[str, int]]:
    """Walk backward from `line` looking for the enclosing def/function header.

    Indentation-aware: a `def foo():` at indent N only contains line L if
    L is indented strictly more than N AND no intervening non-blank line
    has indent <= N (which would mean the function body has already ended
    before we reach L). Returns (name, def_line) or None for module scope.
    """
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if line < 1 or line > len(lines):
        return None

    target_indent = _indent_of(lines[line - 1])
    # If the target line is itself blank, fall back to its position in the
    # file but treat its indent as "unknown deep" so we still find a wrapper.
    if target_indent < 0:
        target_indent = 1 << 30

    # Track the smallest indent seen on the way back up among non-blank lines
    # strictly between the target and the candidate def. If we ever see a
    # line with indent <= a candidate def's indent, that def can't contain
    # the target line.
    min_body_indent = target_indent

    for i in range(line - 2, -1, -1):
        ind = _indent_of(lines[i])
        if ind < 0:
            continue  # blank line, skip
        for pat in _DEF_PATTERNS:
            m = pat.match(lines[i])
            if m:
                if ind < min_body_indent:
                    return (m.group(1), i + 1)
                # def at this indent doesn't actually contain the target
                # (the body ended before our target line). Keep walking.
                break
        # Track minimum indent of body lines we've crossed.
        if ind < min_body_indent:
            min_body_indent = ind
        # Once we've seen a top-level (indent 0) non-def line between us and
        # any potential def, we're definitely at module scope.
        if min_body_indent == 0:
            return None
    return None


def find_callers(
    repo_root: pathlib.Path, function_name: str, exclude: pathlib.Path,
) -> list[tuple[pathlib.Path, int, str]]:
    """Find every line that looks like a call to `function_name`.

    Returns up to MAX_CALLERS_PER_FUNCTION hits as (file, line, snippet).
    Excludes the definition itself and any appearance inside the same file
    that is the function declaration line. We do NOT try to resolve imports
    or aliases — the LLM will sort out noise from real calls.
    """
    name_re = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    hits: list[tuple[pathlib.Path, int, str]] = []
    for src in iter_source_files(repo_root):
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if not name_re.search(line):
                continue
            # Skip the definition line itself.
            if any(p.match(line) and function_name in line for p in _DEF_PATTERNS):
                continue
            # Skip likely noise: comments & docstrings on the same line.
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            hits.append((src, i, line.rstrip()))
            if len(hits) >= MAX_CALLERS_PER_FUNCTION * 4:
                break
    return hits[:MAX_CALLERS_PER_FUNCTION]


def snippet(path: pathlib.Path, line: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    lo = max(1, line - SNIPPET_RADIUS)
    hi = min(len(lines), line + SNIPPET_RADIUS)
    width = len(str(hi))
    return "\n".join(f"{i:>{width}}  {lines[i-1]}" for i in range(lo, hi + 1))


# ---------------------------------------------------------------------------
# Caller graph (BFS upward)
# ---------------------------------------------------------------------------

@dataclass
class CallSite:
    caller_function: Optional[str]  # None if module-level
    caller_file: str
    caller_line: int
    snippet: str


def build_caller_graph(
    repo_root: pathlib.Path, sink_file: pathlib.Path, sink_line: int,
) -> tuple[Optional[str], list[list[CallSite]]]:
    """Return (sink_function_name, layers) where `layers` is
    layers[0] = direct callers of the sink's containing function,
    layers[1] = their callers,
    up to MAX_DEPTH.
    """
    containing = containing_function(sink_file, sink_line)
    if not containing:
        return (None, [])
    func_name, _def_line = containing

    layers: list[list[CallSite]] = []
    current_names = {func_name}
    seen = {func_name}

    for _ in range(MAX_DEPTH):
        this_layer: list[CallSite] = []
        next_names: set[str] = set()
        for name in current_names:
            for cf, cl, line_text in find_callers(repo_root, name, exclude=sink_file):
                parent = containing_function(cf, cl)
                this_layer.append(CallSite(
                    caller_function=parent[0] if parent else None,
                    caller_file=str(cf.relative_to(repo_root)) if cf.is_relative_to(repo_root) else str(cf),
                    caller_line=cl,
                    snippet=snippet(cf, cl),
                ))
                if parent and parent[0] not in seen:
                    next_names.add(parent[0])
                    seen.add(parent[0])
        if not this_layer:
            break
        layers.append(this_layer)
        if not next_names:
            break
        current_names = next_names

    return (func_name, layers)


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

@dataclass
class ReachabilityResult:
    reachable: Optional[bool]            # None = unknown / not applicable
    exploit_path: list[str]              # ordered list of "file:line function()"
    adjusted_severity: Optional[str]     # None = preserve stage-1 severity
    reasoning: str


_SYSTEM_PROMPT = """You are an application security engineer performing
cross-file reachability analysis on a single SAST finding.

You will be shown:
  - The sink location (file and line containing the dangerous call).
  - The function that contains the sink.
  - Up to two layers of its callers, with snippets of each call site.

Your job is to decide:

  1. Is the sink REACHABLE from untrusted input? That means: is there any
     chain of callers leading from the sink back to an entry point that
     takes untrusted input (HTTP request handler, CLI arg parser, message
     consumer, etc.)?

  2. If reachable, produce the path as an ordered list of "file:line
     function_name" strings from the entry point to the sink.

  3. Adjust severity. If not reachable (dead code, or only called from
     tests/build scripts), severity should be `info` or `low` — the bug is
     real but there is no live exploit path. If reachable and input is
     untrusted, keep or raise severity. If reachable but the input is
     constrained by callers, use judgment.

Output MUST be a single JSON object, no markdown fences:
  {
    "reachable": true | false | null,
    "exploit_path": ["file:line funcA()", "file:line funcB()", ...],
    "adjusted_severity": "critical" | "high" | "medium" | "low" | "info",
    "reasoning": "2-5 sentences tying your answer to the specific callers shown"
  }

Use `null` for `reachable` ONLY when the caller layers are empty AND you
genuinely can't tell from the sink alone. Otherwise commit."""


def _format_layers(layers: list[list[CallSite]]) -> str:
    if not layers:
        return "(no callers found)"
    out: list[str] = []
    for depth, layer in enumerate(layers, 1):
        out.append(f"### Caller layer {depth}")
        if not layer:
            out.append("(empty)")
            continue
        for cs in layer:
            loc = f"{cs.caller_file}:{cs.caller_line}"
            fn = cs.caller_function or "<module-level>"
            out.append(f"\n**Call site {loc} — inside `{fn}`**\n")
            out.append("```")
            out.append(cs.snippet)
            out.append("```")
    return "\n".join(out)


def analyze(
    client: Anthropic,
    model: str,
    repo_root: pathlib.Path,
    sink_file: pathlib.Path,
    sink_line: int,
    sink_code: str,
) -> ReachabilityResult:
    func_name, layers = build_caller_graph(repo_root, sink_file, sink_line)

    # Short-circuit: findings at module scope (no containing function) are
    # almost always intrinsic vulnerabilities — hardcoded secrets, debug
    # flags, insecure binds, top-level config. Reachability via call graph
    # doesn't model these, so don't downgrade severity. Saves an LLM call
    # too.
    if func_name is None:
        return ReachabilityResult(
            reachable=None,
            exploit_path=[],
            adjusted_severity=None,
            reasoning=(
                "Finding is at module scope (not inside a function), so "
                "call-graph reachability does not apply. This is typically "
                "an intrinsic configuration issue (e.g. hardcoded secret, "
                "debug mode, insecure bind) where the vulnerability exists "
                "regardless of input flow. Stage-1 severity preserved."
            ),
        )

    user = (
        f"Sink: {sink_file.name}:{sink_line}\n"
        f"Containing function: `{func_name or '<unknown>'}`\n\n"
        f"### Sink snippet\n```\n{sink_code}\n```\n\n"
        f"{_format_layers(layers)}\n"
    )

    last_err: Optional[Exception] = None
    for attempt in range(3):
        try:
            resp = client.messages.create(
                model=model,
                max_tokens=600,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user}],
            )
            text = resp.content[0].text.strip()
            if text.startswith("```"):
                text = text.strip("`")
                if text.lower().startswith("json"):
                    text = text[4:]
                text = text.strip()
            data = json.loads(text)
            return ReachabilityResult(
                reachable=data.get("reachable"),
                exploit_path=list(data.get("exploit_path") or []),
                adjusted_severity=(
                    str(data["adjusted_severity"])
                    if data.get("adjusted_severity") else None
                ),
                reasoning=str(data.get("reasoning", "")),
            )
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(1.5 * (attempt + 1))
    return ReachabilityResult(
        reachable=None,
        exploit_path=[],
        adjusted_severity=None,  # preserve stage-1 severity on failure
        reasoning=f"reachability call failed after 3 attempts: {last_err}",
    )
