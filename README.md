# AI Vulnerability Triage Demo

A working reproduction of the core idea from Synthesia's "Scaling Vulnerability
Management with AI" — layer an LLM on top of free-tier Semgrep to cut SAST
noise, produce reasoned verdicts, and (eventually) open fix PRs.

```
.
├── DEMO-PLAN.md          # Phased roadmap (read this first)
├── triage-cli/           # Phase 1 — local CLI: Semgrep → Claude → report
├── seed-repos/
│   ├── vuln-flask-app/   # Python/Flask with seeded, documented vulns
│   └── vuln-node-app/    # Node/Express with seeded, documented vulns
└── .github/workflows/    # Phase 2 — GitHub Actions wrapper (coming)
```

## Quickstart

```bash
# 1. Install the CLI + Semgrep free tier
cd triage-cli
pip install -r requirements.txt
pip install semgrep

# 2. Provide your Claude API key
export ANTHROPIC_API_KEY=sk-ant-...

# 3. Triage one of the seed repos
python triage.py ../seed-repos/vuln-flask-app --out ../flask-report

# 4. Read the summary
cat ../flask-report.md
```

## What the seed repos are for

Each seed repo has a `README.md` listing every intentional vulnerability with
a label: `TP` (true positive, the AI should confirm), `TP-subtle` (testing
reasoning depth), or `FP-trap` (looks dangerous but isn't — the AI should
reject it).

That gives you ground truth to measure the triage's quality against, not just
vibes.

## Model and cost

- Default model: `claude-sonnet-4-6` (good code reasoning, fast, cheap).
- Typical seed-repo run: ~15–30 findings, under a minute, cents per run.
- Swap with `--model claude-opus-4-6` for tougher reasoning cases.

## Status

- [x] Phase 0 — seed repos
- [x] Phase 1 — local triage CLI
- [x] Phase 2 — GitHub Actions wrapper
- [x] Phase 3 — reachability/exploitability analysis
- [ ] Phase 4 — auto-fix PRs
- [ ] Phase 5 — SCA triage
- [ ] Phase 6 — ticketing + metrics

See `DEMO-PLAN.md` for the full breakdown.

# re-trigger B after workflow push 1776725503
