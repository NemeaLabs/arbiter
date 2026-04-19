# triage-cli

Phase 1 of the demo: a local CLI that runs free-tier Semgrep against a target
repo and asks Claude for a structured verdict on every finding.

## Install

```bash
pip install -r requirements.txt
pip install semgrep
export ANTHROPIC_API_KEY=sk-ant-...
```

## Run

```bash
# Triage the Flask seed repo
python triage.py ../seed-repos/vuln-flask-app --out ../flask-report

# Triage the Node seed repo
python triage.py ../seed-repos/vuln-node-app --out ../node-report

# Only triage the first 5 findings, use Opus for tougher reasoning
python triage.py ../seed-repos/vuln-flask-app --max 5 --model claude-opus-4-6
```

Output:

- `<prefix>.json` — structured results (one entry per finding with
  `{finding, verdict}`).
- `<prefix>.md` — human-readable summary grouped by verdict.

## What to look at in the output

For each seed repo, compare the Markdown summary against the repo's
`README.md` ground-truth table:

- Every row labeled `TP` should land in "True Positive".
- The single row labeled `FP-trap` should land in "False Positive" with a
  rationale that names the allowlist / constant input that makes it safe.
- `needs_review` should be rare — if there are more than a couple, the
  prompt needs tightening.

## Tunables

| Flag              | Default               | What it does |
|-------------------|-----------------------|--------------|
| `--out PREFIX`    | `report`              | Output prefix; produces `.json` and `.md`. |
| `--model NAME`    | `claude-sonnet-4-6`   | Any Anthropic model string. |
| `--max N`         | `0` (all)             | Stop after N findings (useful while iterating). |
| `--concurrency K` | `4`                   | Parallel triage calls. Raise cautiously to respect rate limits. |

## Known limitations (by design for Phase 1)

- Code context is a ±8-line window around the sink. Phase 3 will widen to
  multi-file reachability.
- No caching. If you re-run you pay again. Easy addition: hash
  `(rule_id, file_sha, start, end)` and memoize the verdict.
- SAST only. Phase 5 adds SCA.
