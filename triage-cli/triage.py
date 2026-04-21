#!/usr/bin/env python3
"""
Local Semgrep + LLM triage CLI (Phase 1 of the demo plan).

Flow:
  1. Run `semgrep --config auto --json` on the target path.
  2. For each finding, extract the code window around the sink.
  3. Ask the configured LLM provider for a structured JSON verdict.
  4. Write a machine-readable report.json and a human-readable report.md.

Providers (selected via env var `TRIAGE_PROVIDER`):
  anthropic  — Anthropic API (default). Needs ANTHROPIC_API_KEY.
  azure      — Azure AI Foundry via azure-ai-inference. Needs
               AZURE_AI_ENDPOINT, AZURE_AI_API_KEY, AZURE_AI_MODEL.
  See providers.py for the full env-var contract.

Usage:
  python triage.py <target-path> [--out REPORT_PREFIX] [--model MODEL]
                                 [--max N] [--concurrency K]

Requirements:
  pip install -r requirements.txt
  pip install semgrep
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from typing import Any, Optional

import reachability
from prompts import SYSTEM_PROMPT, USER_TEMPLATE
from providers import LLMProvider, get_provider


CONTEXT_RADIUS = 15  # lines before and after the finding to include


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------

def run_semgrep(
    target: pathlib.Path, baseline: Optional[str] = None
) -> list[dict[str, Any]]:
    """Run Semgrep free tier and return the parsed findings list.

    If `baseline` is a git ref, Semgrep only reports findings introduced
    since that commit. This is how CI runs stay cheap and relevant — a PR
    check should comment on what the PR changed, not on pre-existing debt.
    """
    if not target.exists():
        sys.exit(f"target path does not exist: {target}")

    cmd = ["semgrep", "--config", "auto", "--json", "--quiet"]
    if baseline:
        cmd += ["--baseline-commit", baseline]
    cmd.append(str(target))

    print(f"[semgrep] scanning {target} "
          f"(baseline={baseline or 'none'}) ...", file=sys.stderr)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        sys.exit("semgrep not found on PATH. Install with `pip install semgrep`.")

    # Semgrep returns non-zero exit when it finds issues — that's expected.
    if proc.returncode not in (0, 1):
        sys.stderr.write(proc.stderr)
        sys.exit(f"semgrep failed with exit code {proc.returncode}")

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        sys.exit(f"could not parse semgrep JSON: {exc}")

    findings = data.get("results", [])
    print(f"[semgrep] {len(findings)} finding(s)", file=sys.stderr)
    return findings


# ---------------------------------------------------------------------------
# Code-context extraction
# ---------------------------------------------------------------------------

LANGUAGE_BY_EXT = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "jsx", ".tsx": "tsx", ".go": "go", ".java": "java",
    ".rb": "ruby", ".php": "php", ".rs": "rust", ".c": "c", ".cpp": "cpp",
}


def code_window(path: pathlib.Path, start: int, end: int) -> str:
    """Return the file lines [start-radius, end+radius] with line numbers."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "(could not read file)"

    lo = max(1, start - CONTEXT_RADIUS)
    hi = min(len(lines), end + CONTEXT_RADIUS)
    width = len(str(hi))
    return "\n".join(
        f"{i:>{width}}  {lines[i-1]}" for i in range(lo, hi + 1)
    )


# ---------------------------------------------------------------------------
# LLM triage
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule_id: str  # primary rule ID; additional ones in merged_rule_ids
    rule_message: str
    severity: str
    file_path: str
    line_start: int
    line_end: int
    code_context: str
    language: str
    merged_rule_ids: list[str]  # all rules that fired at (file, line_start, line_end)


@dataclass
class Verdict:
    verdict: str
    confidence: float
    severity: str
    reasoning: str
    suggested_fix_sketch: Optional[str]
    # Phase 3: filled in by reachability pass for true_positive findings only.
    reachable: Optional[bool] = None
    exploit_path: Optional[list[str]] = None
    adjusted_severity: Optional[str] = None
    reachability_reasoning: Optional[str] = None

    @property
    def effective_severity(self) -> str:
        """Severity after reachability adjustment, falling back to stage-1."""
        return self.adjusted_severity or self.severity


def finding_from_semgrep(raw: dict[str, Any], repo_root: pathlib.Path) -> Finding:
    path = pathlib.Path(raw["path"])
    start = int(raw["start"]["line"])
    end = int(raw["end"]["line"])
    ext = path.suffix.lower()
    abs_path = path if path.is_absolute() else (repo_root / path).resolve()
    rid = str(raw.get("check_id", ""))
    return Finding(
        rule_id=rid,
        rule_message=str((raw.get("extra") or {}).get("message", "")),
        severity=str((raw.get("extra") or {}).get("severity", "INFO")),
        file_path=str(path),
        line_start=start,
        line_end=end,
        code_context=code_window(abs_path, start, end),
        language=LANGUAGE_BY_EXT.get(ext, ""),
        merged_rule_ids=[rid],
    )


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "ERROR": 3, "WARNING": 2,
                 "MEDIUM": 2, "LOW": 1, "INFO": 0}


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse findings at the same (file, line_start, line_end) into one.

    Semgrep's rulesets overlap — e.g. a single SQL injection line can trip
    both `python.django.*` and `python.flask.*` rules. Paying for two triage
    calls on identical code is waste. We keep the highest-severity primary
    rule and stash the others in `merged_rule_ids` so the model still sees
    the full signal.
    """
    by_key: dict[tuple[str, int, int], Finding] = {}
    for f in findings:
        key = (f.file_path, f.line_start, f.line_end)
        if key not in by_key:
            by_key[key] = f
            continue
        existing = by_key[key]
        existing.merged_rule_ids.append(f.rule_id)
        # Promote to the higher-severity rule if applicable.
        if SEVERITY_RANK.get(f.severity.upper(), 0) > \
                SEVERITY_RANK.get(existing.severity.upper(), 0):
            f.merged_rule_ids = existing.merged_rule_ids
            by_key[key] = f
    return list(by_key.values())


def triage_one(provider: LLMProvider, f: Finding) -> Verdict:
    # If multiple rules fired on the same line, show them all to the model;
    # it's useful context and avoids hiding the union of ruleset opinions.
    rule_id_field = f.rule_id if len(f.merged_rule_ids) == 1 else \
        f.rule_id + " (also: " + ", ".join(
            r for r in f.merged_rule_ids if r != f.rule_id
        ) + ")"
    user = USER_TEMPLATE.format(
        rule_id=rule_id_field,
        rule_message=f.rule_message,
        severity=f.severity,
        file_path=f.file_path,
        line_start=f.line_start,
        line_end=f.line_end,
        language=f.language,
        code_context=f.code_context,
    )
    # Retry on transient errors (network blips, 429s, model timeouts).
    last_err: Optional[Exception] = None
    for attempt in range(3):
        try:
            text = provider.chat(
                system=SYSTEM_PROMPT, user=user, max_tokens=600,
            ).strip()
            # Tolerate accidental ``` fences (some models wrap JSON).
            if text.startswith("```"):
                text = text.strip("`")
                if text.lower().startswith("json"):
                    text = text[4:]
                text = text.strip()
            data = json.loads(text)
            return Verdict(
                verdict=str(data.get("verdict", "needs_review")),
                confidence=float(data.get("confidence", 0.5)),
                severity=str(data.get("severity", f.severity.lower())),
                reasoning=str(data.get("reasoning", "")),
                suggested_fix_sketch=data.get("suggested_fix_sketch"),
            )
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(1.5 * (attempt + 1))
    return Verdict(
        verdict="needs_review",
        confidence=0.0,
        severity=f.severity.lower(),
        reasoning=f"triage call failed after 3 attempts: {last_err}",
        suggested_fix_sketch=None,
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_reports(pairs: list[tuple[Finding, Verdict]], out_prefix: pathlib.Path) -> None:
    # JSON report
    json_path = out_prefix.with_suffix(".json")
    json_path.write_text(json.dumps(
        [{"finding": asdict(f), "verdict": asdict(v)} for f, v in pairs],
        indent=2,
    ))

    # Markdown summary, grouped by verdict.
    md_path = out_prefix.with_suffix(".md")
    groups: dict[str, list[tuple[Finding, Verdict]]] = {
        "true_positive": [], "false_positive": [], "needs_review": [],
    }
    for f, v in pairs:
        groups.setdefault(v.verdict, []).append((f, v))

    lines: list[str] = []
    total = len(pairs)
    tp = len(groups.get("true_positive", []))
    fp = len(groups.get("false_positive", []))
    nr = len(groups.get("needs_review", []))
    # Hidden marker so PR comment updaters (e.g. peter-evans/create-or-update-comment)
    # can find and replace the previous comment instead of posting a new one.
    lines.append("<!-- ai-triage-report -->")
    lines.append("# AI Triage Report\n")

    # Summary framed around the AI's *actions*, not just verdict counts.
    # A green check with "0 TP, 1 FP" under a small header reads as
    # "nothing happened" — but the AI actually rejected a Semgrep finding,
    # and we want that work to be visible to a PR reviewer without
    # scrolling.
    summary_bits: list[str] = [f"Reviewed **{total}** Semgrep finding(s)."]
    if tp:
        summary_bits.append(
            f"**{tp} confirmed** as true positive(s) — action required."
        )
    if fp:
        summary_bits.append(
            f"**{fp} rejected** as false positive(s) — Semgrep flagged these, "
            f"but AI triage determined they are not exploitable. "
            f"Details below for auditability."
        )
    if nr:
        summary_bits.append(
            f"**{nr} flagged for manual review** — model was unsure."
        )
    lines.append(" ".join(summary_bits))
    lines.append("")

    # TL;DR of rejected rules, so a skim reader can see the AI's saves
    # without expanding every card.
    fp_items = groups.get("false_positive", [])
    if fp_items:
        lines.append(
            "> **AI rejected the following Semgrep finding(s):** " +
            ", ".join(
                f"`{f.rule_id}` at `{f.file_path}:{f.line_start}`"
                for f, _ in fp_items
            )
        )
        lines.append("")

    # Section order: TP first (what you must fix), then FP (what the AI
    # saved you from — always render when present), then needs-review.
    SECTION_ORDER = [
        ("true_positive",  "Confirmed vulnerabilities"),
        ("false_positive", "Rejected by AI triage (false positives)"),
        ("needs_review",   "Needs manual review"),
    ]

    for verdict, title in SECTION_ORDER:
        items = groups.get(verdict, [])
        if not items:
            continue
        lines.append(f"## {title} ({len(items)})\n")
        for f, v in items:
            lines.append(f"### `{f.rule_id}` — {f.file_path}:{f.line_start}\n")
            if verdict == "false_positive":
                # Frame Semgrep vs AI so the contrast is explicit.
                lines.append(f"- **Semgrep flagged:** {f.rule_message}")
                lines.append(
                    f"- **AI verdict:** false positive "
                    f"(confidence {v.confidence:.2f})"
                )
                lines.append(f"- **Why rejected:** {v.reasoning}")
            else:
                lines.append(f"- **Rule message:** {f.rule_message}")
                # Show severity change if reachability adjusted it.
                sev_display = v.severity
                if v.adjusted_severity and v.adjusted_severity != v.severity:
                    sev_display = (
                        f"{v.severity} -> **{v.adjusted_severity}** "
                        f"(adjusted by reachability)"
                    )
                lines.append(
                    f"- **Severity:** {sev_display}   "
                    f"**Confidence:** {v.confidence:.2f}"
                )
                lines.append(f"- **Reasoning:** {v.reasoning}")
                if v.suggested_fix_sketch:
                    lines.append(f"- **Fix sketch:** {v.suggested_fix_sketch}")
                # Reachability block (only when stage-2 ran on this finding).
                if v.reachable is not None or v.exploit_path or v.reachability_reasoning:
                    lines.append("- **Reachability:**")
                    if v.reachable is True:
                        lines.append("  - Reachable from untrusted input: **yes**")
                    elif v.reachable is False:
                        lines.append("  - Reachable from untrusted input: **no** (dead code or internal-only)")
                    else:
                        # reachable is None: module-scope intrinsic vuln,
                        # or the LLM call genuinely couldn't decide.
                        lines.append("  - Reachable from untrusted input: not applicable / unknown")
                    if v.exploit_path:
                        lines.append("  - Exploit path: " + " -> ".join(f"`{p}`" for p in v.exploit_path))
                    if v.reachability_reasoning:
                        lines.append(f"  - Reasoning: {v.reachability_reasoning}")
            lines.append("")
            lines.append("```" + f.language)
            lines.append(f.code_context)
            lines.append("```")
            lines.append("")

    md_path.write_text("\n".join(lines))
    print(f"[report] wrote {json_path}", file=sys.stderr)
    print(f"[report] wrote {md_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Semgrep + LLM triage")
    ap.add_argument("target", type=pathlib.Path, help="Path to scan.")
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path("report"),
                    help="Output prefix (produces <prefix>.json and <prefix>.md).")
    ap.add_argument("--model", default=None,
                    help="Anthropic model to use (overrides ANTHROPIC_MODEL "
                         "env; ignored for non-Anthropic providers, which "
                         "take the deployment/model name from their own "
                         "env vars — see providers.py).")
    ap.add_argument("--max", type=int, default=0,
                    help="Max findings to triage (0 = all).")
    ap.add_argument("--concurrency", type=int, default=4,
                    help="Parallel triage calls.")
    ap.add_argument("--baseline", default=None,
                    help="Git ref to diff against; only triage findings "
                         "introduced after this commit. Used in CI.")
    ap.add_argument("--fail-on", default=None,
                    choices=[None, "any-tp", "high-tp"],
                    help="Exit nonzero if any finding matches: 'any-tp' = "
                         "any true_positive; 'high-tp' = true_positive with "
                         "effective severity in {high, critical} and "
                         "confidence>=0.8. Effective severity is post-"
                         "reachability, so unreachable sinks don't trip.")
    ap.add_argument("--no-reachability", action="store_true",
                    help="Skip the Phase 3 reachability pass.")
    args = ap.parse_args()

    # Build the provider FIRST so configuration errors (missing keys, bad
    # endpoint, unknown provider) surface before we spend time running
    # Semgrep across the repo.
    provider = get_provider(anthropic_model_cli=args.model)
    print(f"[triage] provider={provider.name} model={provider.model}",
          file=sys.stderr)

    target = args.target.resolve()
    findings_raw = run_semgrep(target, baseline=args.baseline)
    if args.max > 0:
        findings_raw = findings_raw[: args.max]
    findings = [finding_from_semgrep(r, target) for r in findings_raw]
    before = len(findings)
    findings = dedupe_findings(findings)
    if before != len(findings):
        print(
            f"[triage] deduped {before} -> {len(findings)} finding(s) "
            f"(same file+line merged)",
            file=sys.stderr,
        )

    if not findings:
        print("[triage] nothing to do.", file=sys.stderr)
        # Include the sticky marker so this comment still gets edited in
        # place on the next run, rather than posted as a new one.
        args.out.with_suffix(".md").write_text(
            "<!-- ai-triage-report -->\n"
            "# AI Triage Report\n\n"
            "No Semgrep findings to triage on this PR.\n"
        )
        args.out.with_suffix(".json").write_text("[]")
        return 0

    print(f"[triage] calling {provider.name}:{provider.model} on "
          f"{len(findings)} finding(s) with concurrency={args.concurrency} ...",
          file=sys.stderr)

    pairs: list[tuple[Finding, Verdict]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = {ex.submit(triage_one, provider, f): f for f in findings}
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            f = futures[fut]
            v = fut.result()
            pairs.append((f, v))
            print(
                f"[triage] {i}/{len(findings)}  {v.verdict:<15}  "
                f"conf={v.confidence:.2f}  {f.rule_id}",
                file=sys.stderr,
            )

    # ---- Phase 3: reachability on TPs and needs_review (skip FPs) ----
    # needs_review gets the pass too, because many of those are "is this
    # dead code?" cases that only reachability can resolve.
    if not args.no_reachability:
        tps = [
            (f, v) for f, v in pairs
            if v.verdict in ("true_positive", "needs_review")
        ]
        if tps:
            print(
                f"[reachability] analyzing {len(tps)} true positive(s) "
                f"with concurrency={args.concurrency} ...",
                file=sys.stderr,
            )
            def _reach_one(f: Finding, v: Verdict) -> tuple[Finding, Verdict]:
                abs_path = pathlib.Path(f.file_path)
                if not abs_path.is_absolute():
                    abs_path = (target / abs_path).resolve()
                r = reachability.analyze(
                    provider=provider,
                    repo_root=target, sink_file=abs_path,
                    sink_line=f.line_start, sink_code=f.code_context,
                )
                v.reachable = r.reachable
                v.exploit_path = r.exploit_path
                v.adjusted_severity = r.adjusted_severity
                v.reachability_reasoning = r.reasoning
                return (f, v)

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=args.concurrency
            ) as ex:
                rfutures = {ex.submit(_reach_one, f, v): (f, v) for f, v in tps}
                for i, fut in enumerate(
                    concurrent.futures.as_completed(rfutures), 1
                ):
                    f, v = fut.result()
                    path_str = " -> ".join(v.exploit_path) if v.exploit_path else "-"
                    if v.adjusted_severity is None:
                        sev_str = f"sev={v.severity} (preserved)"
                    else:
                        sev_str = f"sev={v.severity}->{v.adjusted_severity}"
                    reach_str = {True: "yes", False: "no",
                                 None: "n/a"}[v.reachable]
                    print(
                        f"[reachability] {i}/{len(tps)}  reachable={reach_str}  "
                        f"{sev_str}  "
                        f"{f.file_path}:{f.line_start}  path={path_str}",
                        file=sys.stderr,
                    )

    # Preserve original semgrep order in the report.
    pairs.sort(key=lambda fv: (fv[0].file_path, fv[0].line_start))
    write_reports(pairs, args.out)

    # CI gate: decide exit code from verdicts, honoring adjusted severity.
    if args.fail_on:
        def is_gate_hit(v: Verdict) -> bool:
            if args.fail_on == "any-tp":
                # Unreachable TPs don't trip "any-tp" either.
                return v.verdict == "true_positive" and v.reachable is not False
            if args.fail_on == "high-tp":
                return (
                    v.verdict == "true_positive"
                    and v.effective_severity.lower() in ("high", "critical")
                    and v.confidence >= 0.8
                    and v.reachable is not False
                )
            return False

        hits = [f.rule_id for f, v in pairs if is_gate_hit(v)]
        if hits:
            print(
                f"[gate] {len(hits)} finding(s) match --fail-on={args.fail_on}; "
                f"failing build.",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
