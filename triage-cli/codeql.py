"""Fetch and manage CodeQL code-scanning alerts via the GitHub API.

Returns raw alert dicts; finding_from_codeql() in triage.py converts them
to Finding objects. This module owns only the I/O — no Finding dependency,
no circular imports.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Optional

GITHUB_API = "https://api.github.com"


def run_codeql_alerts(
    repo: str,
    token: str,
    ref: Optional[str] = None,
) -> list[dict]:
    """Return all open code-scanning alerts for `repo`.

    `repo` is "owner/repo". `ref` is a PR head ref like "refs/pull/2/head"
    (PR mode) or None to fetch all open alerts on the repo (backlog mode).
    Paginates automatically (100 alerts per page).
    Returns [] if code-scanning is not enabled (404) or no alerts exist.
    Raises RuntimeError on other HTTP errors.
    """
    alerts: list[dict] = []
    page = 1
    while True:
        base = f"{GITHUB_API}/repos/{repo}/code-scanning/alerts?state=open&per_page=100&page={page}"
        url = f"{base}&ref={ref}" if ref else base
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                batch = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            # 404 means code-scanning is not enabled on this repo — treat
            # it as "no alerts" rather than a hard failure, so a repo that
            # only has Semgrep doesn't break when --scanners includes codeql.
            if exc.code == 404:
                return []
            raise RuntimeError(
                f"GitHub code-scanning API {exc.code}: {body[:300]}"
            ) from exc

        if not isinstance(batch, list) or not batch:
            break
        alerts.extend(batch)
        if len(batch) < 100:
            break
        page += 1

    return alerts


TRIAGE_COMMENT_MARKER = "<!-- ai-triage-verdict -->"

_VERDICT_EMOJI = {
    "true_positive": "🔴",
    "false_positive": "✅",
    "needs_review": "🔍",
}


def _gh_request(url: str, token: str, method: str = "GET",
                payload: Optional[dict] = None) -> dict | list:
    data = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if data else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(f"GitHub API {method} {url}: HTTP {exc.code}: {body[:300]}") from exc


def find_or_create_alert_issue(
    repo: str,
    token: str,
    alert_number: int,
    rule_id: str,
    file_path: str,
    line_start: int,
    alert_html_url: str,
) -> int:
    """Return the GitHub Issue number for this CodeQL alert, creating one if needed.

    Issues are identified by the label `codeql-alert-{N}`. If no open issue
    with that label exists, a new one is created and labelled.
    Requires `issues: write` permission on the token.
    """
    label = f"codeql-alert-{alert_number}"
    # Search for an existing open issue with this alert's label.
    search_url = (
        f"{GITHUB_API}/repos/{repo}/issues"
        f"?labels={label}&state=open&per_page=1"
    )
    issues = _gh_request(search_url, token)
    if isinstance(issues, list) and issues:
        return int(issues[0]["number"])

    # No existing issue — create one.
    body = (
        f"**CodeQL alert:** [{rule_id}]({alert_html_url})\n"
        f"**Location:** `{file_path}:{line_start}`\n\n"
        f"This issue was automatically created to track the AI triage result "
        f"for CodeQL alert #{alert_number}."
    )
    new_issue = _gh_request(
        f"{GITHUB_API}/repos/{repo}/issues",
        token, method="POST",
        payload={
            "title": f"[CodeQL #{alert_number}] {rule_id} — {file_path}:{line_start}",
            "body": body,
            "labels": [label],
        },
    )
    return int(new_issue["number"])


def has_triage_comment(repo: str, token: str, issue_number: int) -> bool:
    """Return True if the issue already has an AI triage comment."""
    url = f"{GITHUB_API}/repos/{repo}/issues/{issue_number}/comments?per_page=100"
    comments = _gh_request(url, token)
    if not isinstance(comments, list):
        return False
    return any(TRIAGE_COMMENT_MARKER in (c.get("body") or "") for c in comments)


def add_triage_comment(
    repo: str,
    token: str,
    issue_number: int,
    verdict: str,
    confidence: float,
    severity: str,
    reasoning: str,
    fix_sketch: Optional[str],
    reachable: Optional[bool],
    exploit_path: list[str],
    reachability_reasoning: Optional[str],
) -> None:
    """Post the AI triage verdict as a comment on the issue."""
    emoji = _VERDICT_EMOJI.get(verdict, "🔍")
    verdict_label = verdict.replace("_", " ").title()

    lines = [
        TRIAGE_COMMENT_MARKER,
        f"## {emoji} AI Triage Verdict: {verdict_label}",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Verdict** | {verdict_label} |",
        f"| **Confidence** | {confidence:.0%} |",
        f"| **Severity** | {severity} |",
        "",
        f"**Reasoning:** {reasoning}",
    ]
    if fix_sketch:
        lines += ["", f"**Fix sketch:** {fix_sketch}"]
    if reachable is not None or exploit_path or reachability_reasoning:
        lines.append("")
        lines.append("**Reachability analysis:**")
        if reachable is True:
            lines.append("- Reachable from untrusted input: **yes**")
        elif reachable is False:
            lines.append("- Reachable from untrusted input: **no** (dead code or internal-only)")
        else:
            lines.append("- Reachable from untrusted input: not applicable / unknown")
        if exploit_path:
            lines.append("- Exploit path: " + " → ".join(f"`{p}`" for p in exploit_path))
        if reachability_reasoning:
            lines.append(f"- {reachability_reasoning}")

    _gh_request(
        f"{GITHUB_API}/repos/{repo}/issues/{issue_number}/comments",
        token, method="POST",
        payload={"body": "\n".join(lines)},
    )


def dismiss_alert(
    repo: str,
    token: str,
    alert_number: int,
    comment: str = "",
) -> None:
    """Dismiss a code-scanning alert as a false positive.

    Requires `security-events: write` permission on the token.
    Raises RuntimeError on non-2xx HTTP responses.
    """
    url = f"{GITHUB_API}/repos/{repo}/code-scanning/alerts/{alert_number}"
    payload = json.dumps({
        "state": "dismissed",
        "dismissed_reason": "false positive",
        "dismissed_comment": comment[:280],  # GitHub caps at 280 chars
    }).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        method="PATCH",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30):
            pass
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(
            f"dismiss alert #{alert_number}: HTTP {exc.code}: {body[:200]}"
        ) from exc
