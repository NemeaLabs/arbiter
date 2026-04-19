# GitHub Actions — AI Vulnerability Triage

Phase 2 of the demo. This is the workflow you drop into a real repository to
get the AI triage running on every PR, with results posted as a sticky PR
comment.

## What it does on a PR

1. Checks out the PR with full git history.
2. Runs Semgrep against **only the code the PR changed**, using
   `--baseline-commit <base>`. Pre-existing findings on `main` are ignored
   so the check talks about what this PR is adding.
3. Triages each finding with Claude (same logic as Phase 1 local CLI).
4. Posts a sticky Markdown comment on the PR. The comment is *replaced* on
   re-runs, not duplicated.
5. Fails the check if any finding is classified `true_positive` with
   `severity` in `{high, critical}` and `confidence >= 0.8`. This gate is
   controlled by `--fail-on high-tp` — tune in `triage.yml` as your risk
   tolerance requires.

## Install on a real repo

1. Copy `triage-cli/` into the repo root (or publish it as an internal
   package — the workflow just needs `python triage-cli/triage.py` to work).
2. Copy `.github/workflows/triage.yml` into the target repo at the same path.
3. In the target repo: **Settings → Secrets and variables → Actions → New
   repository secret**
   - Name: `ANTHROPIC_API_KEY`
   - Value: your Anthropic API key
4. Open a PR. The workflow will trigger, the comment will appear, and the
   check will pass or fail depending on what's in the diff.

## Tuning knobs

| In `triage.yml` | What it does |
|---|---|
| `on.pull_request.branches` | Which target branches trigger the check. Default `[main, master]`. |
| `on.pull_request.paths-ignore` | Skip the check entirely for docs-only PRs. |
| `--fail-on high-tp` | How strict the gate is. `any-tp` fails on any TP (noisy); omit entirely to always pass. |
| `fetch-depth: 0` | Full git history. Required for `--baseline-commit`. |
| `concurrency.cancel-in-progress: true` | Cancel older runs on rapid pushes so you don't pay for stale triages. |

## Testing the workflow locally

Before installing on a real repo, prove the logic works by running the CLI
against a simulated "PR" against the seed repo:

```bash
cd seed-repos/vuln-flask-app
git init -q && git add -A && git commit -q -m "baseline (no vulns)"
# Pretend the TRUE vulnerabilities are a new PR:
# (everything already added above — pretend baseline was empty for this test)
cd ../..
python triage-cli/triage.py seed-repos/vuln-flask-app \
  --out local-pr-report --fail-on high-tp
echo "exit: $?"      # expect nonzero, because the repo is full of TPs
```

## Cost shape in CI

Typical small-to-medium PR touches 1–5 files. On the seed repos, that would
scan as maybe 3–8 findings, one Claude call per finding at ~1k input tokens
each — pennies per run. A monorepo with thousands of engineers running
hundreds of PRs a day would want to add a cache keyed by
`(rule_id, file_sha, start_line)` so unchanged findings never re-hit the
model. Not needed in Phase 2.
