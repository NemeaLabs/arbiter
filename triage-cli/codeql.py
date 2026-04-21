"""Fetch CodeQL code-scanning alerts from the GitHub API.

Returns raw alert dicts; finding_from_codeql() in triage.py converts them
to Finding objects. This module owns only the I/O — no Finding dependency,
no circular imports.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

GITHUB_API = "https://api.github.com"


def run_codeql_alerts(repo: str, ref: str, token: str) -> list[dict]:
    """Return all open code-scanning alerts for `repo` at `ref`.

    `repo` is "owner/repo". `ref` is a PR head SHA or full ref string like
    "refs/pull/2/head". Paginates automatically (100 alerts per page).
    Raises RuntimeError on HTTP errors; returns [] if code-scanning is not
    enabled or the ref has no alerts.
    """
    alerts: list[dict] = []
    page = 1
    while True:
        url = (
            f"{GITHUB_API}/repos/{repo}/code-scanning/alerts"
            f"?ref={ref}&state=open&per_page=100&page={page}"
        )
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
