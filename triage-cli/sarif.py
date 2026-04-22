"""SARIF 2.1.0 → Finding adapter.

Accepts output from any SAST tool that writes SARIF:
  Semgrep (--sarif), Snyk Code (--sarif), Trivy (--format sarif),
  Checkov (--output sarif), gosec (-fmt sarif), ESLint (sarif formatter), etc.

Usage:
  from sarif import sarif_to_findings
  findings = sarif_to_findings(pathlib.Path("report.sarif"), repo_root)
"""

from __future__ import annotations

import json
import pathlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from triage import Finding


def sarif_to_findings(
    sarif_path: pathlib.Path,
    repo_root: pathlib.Path,
) -> list:
    """Parse a SARIF 2.1.0 file and return a list of Finding objects."""
    # Import here to avoid circular imports at module load time.
    from triage import Finding, LANGUAGE_BY_EXT, code_window  # noqa: PLC0415

    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not parse SARIF file {sarif_path}: {exc}") from exc

    findings: list[Finding] = []

    for run in data.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool_name = (driver.get("name") or "unknown").lower().replace(" ", "-")

        # Build rule-id → rule dict for severity lookups.
        rules: dict[str, dict] = {
            r["id"]: r
            for r in (driver.get("rules") or [])
            if r.get("id")
        }

        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or ""
            rule_obj = rules.get(rule_id, {})

            msg_obj = result.get("message") or {}
            message = msg_obj.get("text") or msg_obj.get("markdown") or ""

            level = result.get("level") or "warning"
            sev = _sarif_severity(level, rule_obj)

            locations = result.get("locations") or [{}]
            phys = ((locations[0] or {}).get("physicalLocation")) or {}
            uri = ((phys.get("artifactLocation") or {}).get("uri") or "").lstrip("/")

            if not uri:
                continue

            region = phys.get("region") or {}
            start_line = int(region.get("startLine") or 1)
            end_line = int(region.get("endLine") or start_line)

            path = pathlib.Path(uri)
            abs_path = path if path.is_absolute() else (repo_root / path).resolve()
            ext = path.suffix.lower()

            findings.append(Finding(
                rule_id=rule_id,
                rule_message=message,
                severity=sev,
                file_path=str(path),
                line_start=start_line,
                line_end=end_line,
                code_context=code_window(abs_path, start_line, end_line),
                language=LANGUAGE_BY_EXT.get(ext, ""),
                merged_rule_ids=[rule_id],
                scanner=tool_name,
            ))

    return findings


def _sarif_severity(level: str, rule_obj: dict) -> str:
    """Map a SARIF result to a severity string.

    Priority:
    1. Numeric CVSS score in rule.properties.security-severity (Semgrep, CodeQL, Snyk)
    2. SARIF level field (error/warning/note/none)
    """
    props = rule_obj.get("properties") or {}
    score_str = str(props.get("security-severity") or "").strip()
    if score_str:
        try:
            score = float(score_str)
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"
        except ValueError:
            pass

    return {
        "error": "HIGH",
        "warning": "MEDIUM",
        "note": "LOW",
        "none": "INFO",
    }.get(level.lower(), "MEDIUM").upper()
