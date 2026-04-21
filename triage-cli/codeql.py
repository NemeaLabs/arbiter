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
