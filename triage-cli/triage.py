#!/usr/bin/env python3
"""
SAST triage CLI — parse scanner SARIF output, triage each finding with an
LLM, and write a machine-readable report.json and human-readable report.md.

Flow:
  1. Accept SARIF from any scanner via --sarif / --sarif-dir, or fetch
     GitHub Code Scanning alerts via --scanners github-code-scanning.
  2. For each finding, extract the code window around the sink.
  3. Ask the configured LLM provider for a structured JSON verdict.
  4. Write report.json and report.md.

Providers (selected via env var `TRIAGE_PROVIDER`):
  anthropic  — Anthropic API (default). Needs ANTHROPIC_API_KEY.
  azure      — Azure AI Foundry via azure-ai-inference. Needs
               AZURE_AI_ENDPOINT, AZURE_AI_API_KEY, AZURE_AI_MODEL.
  See providers.py for the full env-var contract.

Usage:
  python triage.py <target-path> --sarif <file> [--out PREFIX]
                                 [--baseline REF] [--fail-on high-tp]

Requirements:
  pip install -r requirements.txt
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import pathlib
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from typing import Any, Optional

import codeql as _codeql
import reachability
from prompts import SYSTEM_PROMPT, USER_TEMPLATE
from providers import LLMProvider, get_provider


CONTEXT_RADIUS = 15  # lines before and after the finding to include


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
    scanner: str = ""
    codeql_alert_number: Optional[int] = None  # set by finding_from_codeql(); None for Semgrep


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


def finding_from_codeql(alert: dict[str, Any], repo_root: pathlib.Path) -> Finding:
    instance = alert.get("most_recent_instance") or {}
    location = instance.get("location") or {}
    rule = alert.get("rule") or {}

    file_path = str(location.get("path") or "")
    line_start = int(location.get("start_line") or 1)
    line_end = int(location.get("end_line") or line_start)
    rid = str(rule.get("id") or alert.get("number") or "")
    message = str(
        (instance.get("message") or {}).get("text")
        or rule.get("description")
        or ""
    )

    raw_sev = str(
        rule.get("security_severity_level") or rule.get("severity") or "medium"
    ).upper()
    if raw_sev in ("NONE", ""):
        raw_sev = "INFO"

    ext = pathlib.Path(file_path).suffix.lower() if file_path else ""
    abs_path = (repo_root / file_path).resolve() if file_path else repo_root

    return Finding(
        rule_id=rid,
        rule_message=message,
        severity=raw_sev,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        code_context=code_window(abs_path, line_start, line_end),
        language=LANGUAGE_BY_EXT.get(ext, ""),
        merged_rule_ids=[rid],
        scanner="codeql",
        codeql_alert_number=int(alert["number"]) if alert.get("number") else None,
    )


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "ERROR": 3, "WARNING": 2,
                 "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _get_changed_files(baseline: str) -> set[str]:
    """Return paths of files changed between baseline and HEAD."""
    proc = subprocess.run(
        ["git", "diff", "--name-only", baseline, "HEAD"],
        capture_output=True, text=True, check=False,
    )
    return set(proc.stdout.strip().splitlines())


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse findings at the same (file, line_start, line_end) into one.

    SAST rulesets overlap — e.g. a single SQL injection line can trip
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
                system=SYSTEM_PROMPT, user=user, max_tokens=2000,
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
    _SCANNER_DISPLAY = {"codeql": "CodeQL", "github-code-scanning": "GitHub Code Scanning"}
    scanners_used = sorted({f.scanner for f, _ in pairs if f.scanner})
    scanner_label = " + ".join(_SCANNER_DISPLAY.get(s, s) for s in scanners_used) if scanners_used else "SAST"
    summary_bits: list[str] = [f"Reviewed **{total}** {scanner_label} finding(s)."]
    if tp:
        summary_bits.append(
            f"**{tp} confirmed** as true positive(s) — action required."
        )
    if fp:
        summary_bits.append(
            f"**{fp} rejected** as false positive(s) — "
            f"AI triage determined these are not exploitable. "
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
            "> **AI rejected the following finding(s):** " +
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
                _SCANNER_DISPLAY = {"codeql": "CodeQL", "github-code-scanning": "GitHub Code Scanning"}
                scanner_name = _SCANNER_DISPLAY.get(f.scanner, f.scanner or "SAST tool")
                lines.append(f"- **{scanner_name} flagged:** {f.rule_message}")
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
    ap = argparse.ArgumentParser(description="SAST + LLM triage")
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
                    help="Git ref to diff against; filters SARIF findings to "
                         "files changed since this commit. Used in CI.")
    ap.add_argument("--fail-on", default=None,
                    choices=[None, "any-tp", "high-tp"],
                    help="Exit nonzero if any finding matches: 'any-tp' = "
                         "any true_positive; 'high-tp' = true_positive with "
                         "effective severity in {high, critical} and "
                         "confidence>=0.8. Effective severity is post-"
                         "reachability, so unreachable sinks don't trip.")
    ap.add_argument("--no-reachability", action="store_true",
                    help="Skip the Phase 3 reachability pass.")
    ap.add_argument("--scanners", default="",
                    help="Comma-separated scanner integrations: "
                         "github-code-scanning (alias: codeql) — fetch alerts "
                         "from the GitHub Code Scanning API. "
                         "For all other tools, run the scanner yourself and "
                         "pass the SARIF output via --sarif / --sarif-dir.")
    ap.add_argument("--sarif", default=None, metavar="FILE",
                    help="Path to a SARIF output file to triage (any SAST tool).")
    ap.add_argument("--sarif-dir", default=None, metavar="DIR",
                    help="Directory containing *.sarif files to triage.")
    ap.add_argument("--github-repo", default=None,
                    help="GitHub repo as 'owner/repo'. Required for --scanners codeql.")
    ap.add_argument("--github-ref", default=None,
                    help="PR head SHA for CodeQL alert lookup. Required for codeql.")
    ap.add_argument("--github-token", default=None,
                    help="GitHub token (defaults to GITHUB_TOKEN env var).")
    ap.add_argument("--backlog", action="store_true",
                    help="Backlog mode: fetch ALL open GitHub Code Scanning alerts "
                         "for the repo (no --github-ref needed). Disables --fail-on.")
    ap.add_argument("--skip-alerts", default="",
                    help="Comma-separated CodeQL alert numbers to skip (already "
                         "triaged). Used by the backlog workflow's skip-cache.")
    ap.add_argument("--dismiss-fps", action="store_true",
                    help="After triage, dismiss FP-verdicted CodeQL alerts via the "
                         "GitHub API. Requires security-events:write on GITHUB_TOKEN. "
                         "Only meaningful with --backlog.")
    ap.add_argument("--post-comments", action="store_true",
                    help="After triage, post one verdict comment per alert on the "
                         "summary issue (--summary-issue). Skips alerts already "
                         "commented. Requires issues:write on GITHUB_TOKEN.")
    ap.add_argument("--summary-issue", type=int, default=None,
                    help="GitHub Issue number for the triage summary. Required when "
                         "--post-comments is set.")
    args = ap.parse_args()

    # ---- Backlog mode: fetch all open GitHub Code Scanning alerts ----
    if args.backlog:
        github_token = args.github_token or os.environ.get("GITHUB_TOKEN")
        if not github_token:
            sys.exit("--backlog requires GITHUB_TOKEN env var or --github-token.")
        if not args.github_repo:
            sys.exit("--backlog requires --github-repo (e.g. owner/repo).")

        provider = get_provider(anthropic_model_cli=args.model)
        print(f"[triage] provider={provider.name} model={provider.model}",
              file=sys.stderr)

        target = args.target.resolve()

        print(f"[codeql] fetching ALL open alerts for {args.github_repo} ...",
              file=sys.stderr)
        try:
            raw_alerts = _codeql.run_codeql_alerts(
                repo=args.github_repo, token=github_token, ref=None,
            )
        except RuntimeError as exc:
            sys.exit(f"[codeql] failed: {exc}")

        # Build url map for use in per-alert comments.
        alert_html_url_map: dict[int, str] = {
            int(a["number"]): a.get("html_url", "")
            for a in raw_alerts if a.get("number")
        }

        if args.post_comments:
            # Skip alerts that already have a triage comment (alert-direct or issue fallback).
            filtered: list[dict] = []
            for a in raw_alerts:
                n = int(a.get("number") or 0)
                if not n:
                    continue
                already = _codeql.has_alert_triage_comment(args.github_repo, github_token, n)
                if not already and args.summary_issue:
                    try:
                        already = _codeql.has_alert_comment_on_issue(
                            args.github_repo, github_token, args.summary_issue, n,
                        )
                    except RuntimeError:
                        pass
                if already:
                    print(f"[comments] #{n} already commented, skipping", file=sys.stderr)
                    continue
                filtered.append(a)
            raw_alerts = filtered
        else:
            # Label-based skip-cache (no --post-comments): avoid re-triaging
            # alerts already processed in a prior run.
            skip_set: set[int] = set()
            if args.skip_alerts:
                for part in args.skip_alerts.split(","):
                    part = part.strip()
                    if part.isdigit():
                        skip_set.add(int(part))
            if skip_set:
                before_skip = len(raw_alerts)
                raw_alerts = [a for a in raw_alerts if a.get("number") not in skip_set]
                print(
                    f"[codeql] skipped {before_skip - len(raw_alerts)} already-triaged alert(s)",
                    file=sys.stderr,
                )

        if not raw_alerts:
            msg = (
                "All alerts already have triage comments."
                if args.post_comments else
                "No new CodeQL alerts to triage — all open alerts already triaged in a previous run."
            )
            print(f"[codeql] {msg}", file=sys.stderr)
            args.out.with_suffix(".md").write_text(f"# AI Backlog Triage\n\n{msg}\n")
            args.out.with_suffix(".json").write_text("[]")
            return 0

        findings = dedupe_findings(
            [finding_from_codeql(a, target) for a in raw_alerts]
        )
        print(f"[codeql] {len(findings)} finding(s) to triage", file=sys.stderr)

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

        if not args.no_reachability:
            tps = [(f, v) for f, v in pairs if v.verdict in ("true_positive", "needs_review")]
            if tps:
                print(f"[reachability] analyzing {len(tps)} finding(s) ...", file=sys.stderr)
                def _reach_backlog(f: Finding, v: Verdict) -> tuple[Finding, Verdict]:
                    abs_path = pathlib.Path(f.file_path)
                    if not abs_path.is_absolute():
                        abs_path = (target / abs_path).resolve()
                    r = reachability.analyze(
                        provider=provider, repo_root=target,
                        sink_file=abs_path, sink_line=f.line_start,
                        sink_code=f.code_context,
                    )
                    v.reachable = r.reachable
                    v.exploit_path = r.exploit_path
                    v.adjusted_severity = r.adjusted_severity
                    v.reachability_reasoning = r.reasoning
                    return (f, v)
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
                    rfutures = {ex.submit(_reach_backlog, f, v): (f, v) for f, v in tps}
                    for i, fut in enumerate(concurrent.futures.as_completed(rfutures), 1):
                        f, v = fut.result()
                        reach_str = {True: "yes", False: "no", None: "n/a"}[v.reachable]
                        print(
                            f"[reachability] {i}/{len(tps)}  reachable={reach_str}  "
                            f"{f.file_path}:{f.line_start}",
                            file=sys.stderr,
                        )

        pairs.sort(key=lambda fv: (fv[0].file_path, fv[0].line_start))
        write_reports(pairs, args.out)

        if args.dismiss_fps:
            fps = [(f, v) for f, v in pairs if v.verdict == "false_positive"
                   and f.codeql_alert_number is not None]
            if fps:
                print(f"[dismiss] dismissing {len(fps)} false positive(s) ...", file=sys.stderr)
            for f, v in fps:
                try:
                    _codeql.dismiss_alert(
                        args.github_repo, github_token,
                        f.codeql_alert_number,
                        comment=f"AI triage: {v.reasoning[:200]}",
                    )
                    print(f"[dismiss] #{f.codeql_alert_number} {f.rule_id}", file=sys.stderr)
                except RuntimeError as exc:
                    print(f"[dismiss] warning: {exc}", file=sys.stderr)

        if args.post_comments:
            print("[comments] posting triage verdicts ...", file=sys.stderr)
            for f, v in pairs:
                if f.codeql_alert_number is None:
                    continue
                n = f.codeql_alert_number
                comment_kwargs = dict(
                    verdict=v.verdict,
                    confidence=v.confidence,
                    severity=v.effective_severity,
                    reasoning=v.reasoning,
                    fix_sketch=v.suggested_fix_sketch,
                    reachable=v.reachable,
                    exploit_path=v.exploit_path or [],
                    reachability_reasoning=v.reachability_reasoning,
                )
                try:
                    _codeql.add_alert_triage_comment(
                        repo=args.github_repo, token=github_token,
                        alert_number=n, **comment_kwargs,
                    )
                    print(f"[comments] #{n} → alert comment  {v.verdict}", file=sys.stderr)
                except RuntimeError:
                    if args.summary_issue:
                        try:
                            _codeql.add_alert_comment_to_issue(
                                repo=args.github_repo, token=github_token,
                                issue_num=args.summary_issue, alert_num=n,
                                alert_html_url=alert_html_url_map.get(n, ""),
                                **comment_kwargs,
                            )
                            print(
                                f"[comments] #{n} → issue #{args.summary_issue}  {v.verdict}",
                                file=sys.stderr,
                            )
                        except RuntimeError as exc2:
                            print(f"[comments] warning: #{n}: {exc2}", file=sys.stderr)
                    else:
                        print(
                            f"[comments] #{n}: alert comment failed (GHAS required); "
                            f"pass --summary-issue for fallback",
                            file=sys.stderr,
                        )

        return 0

    scanners = [s.strip().lower() for s in args.scanners.split(",") if s.strip()]

    if not scanners and not args.sarif and not args.sarif_dir:
        sys.exit(
            "error: no input source specified. "
            "Provide --sarif <file>, --sarif-dir <dir>, or --scanners <list>.\n"
            "       Run your scanner first and pass the SARIF output with --sarif."
        )

    # Build the provider FIRST so configuration errors (missing keys, bad
    # endpoint, unknown provider) surface before parsing any SARIF input.
    provider = get_provider(anthropic_model_cli=args.model)
    print(f"[triage] provider={provider.name} model={provider.model}",
          file=sys.stderr)

    target = args.target.resolve()
    findings: list[Finding] = []

    # ---- SARIF file / directory input ----
    if args.sarif or args.sarif_dir:
        import sarif as _sarif
        sarif_files: list[pathlib.Path] = []
        if args.sarif:
            sarif_files.append(pathlib.Path(args.sarif))
        if args.sarif_dir:
            sarif_files.extend(sorted(pathlib.Path(args.sarif_dir).glob("*.sarif")))
        for sf in sarif_files:
            parsed = _sarif.sarif_to_findings(sf, target)
            print(f"[sarif] {sf.name}: {len(parsed)} finding(s)", file=sys.stderr)
            findings.extend(parsed)
        # Post-filter to files changed in the diff when a baseline is provided.
        if args.baseline and findings:
            changed = _get_changed_files(args.baseline)
            before_filter = len(findings)
            findings = [
                f for f in findings
                if f.file_path in changed
                or pathlib.Path(f.file_path).name in {pathlib.Path(c).name for c in changed}
            ]
            if before_filter != len(findings):
                print(
                    f"[sarif] baseline filter: {before_filter} → {len(findings)} "
                    f"finding(s) in changed files",
                    file=sys.stderr,
                )

    # "github-code-scanning" is the canonical name; "codeql" is a backwards-compat alias.
    if "codeql" in scanners or "github-code-scanning" in scanners:
        github_token = args.github_token or os.environ.get("GITHUB_TOKEN")
        if not github_token:
            sys.exit(
                "CodeQL scanner requires a GitHub token. "
                "Set GITHUB_TOKEN env var or use --github-token."
            )
        if not args.github_repo:
            sys.exit("--github-repo (e.g. owner/repo) is required for --scanners codeql.")
        ref = args.github_ref or args.baseline or ""
        if not ref:
            sys.exit("--github-ref (PR head SHA) is required for --scanners codeql.")
        print(
            f"[codeql] fetching alerts for {args.github_repo} at {ref} ...",
            file=sys.stderr,
        )
        try:
            raw_alerts = _codeql.run_codeql_alerts(
                repo=args.github_repo, token=github_token, ref=ref,
            )
        except RuntimeError as exc:
            print(f"[codeql] warning: {exc}", file=sys.stderr)
            raw_alerts = []
        codeql_findings = [finding_from_codeql(a, target) for a in raw_alerts]
        print(f"[codeql] {len(codeql_findings)} finding(s)", file=sys.stderr)
        findings.extend(codeql_findings)

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
            "No findings to triage on this PR.\n"
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

    # Preserve stable order in the report (file path + line).
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
