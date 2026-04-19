# Demo Plan: AI-Assisted Vulnerability Management (Synthesia-style)

## What the Synthesia article describes

Synthesia's team faced the classic AppSec problem: too many SAST/SCA findings, not
enough humans, and a backlog that grows faster than it shrinks. They built an
AI-assisted pipeline that does three things scanners don't:

1. **Triage** — decide whether a finding is a true positive, false positive,
   or "needs-review", with a written justification tied to the actual code.
2. **Validate / prioritize** — reason about reachability and exploitability
   (can this code actually be hit by untrusted input?), then set severity
   accordingly rather than trusting the rule's default.
3. **Remediate** — draft a fix and open a PR for a human to review.

This plan breaks that ambition into shippable phases so you get something
working end-to-end quickly, then layer sophistication on top.

---

## Phases at a glance

| Phase | Deliverable | Time to build | What it proves |
|-------|-------------|---------------|----------------|
| 0 | Two seeded vulnerable repos (Flask + Express) | shipped here | Known ground truth to measure triage quality against. |
| 1 | Local CLI: Semgrep → Claude triage → Markdown report | shipped here | AI can cut Semgrep noise meaningfully on real code. |
| 2 | GitHub Actions wrapper that comments on PRs | ~half a day | Developer-visible in a real workflow. |
| 3 | Reachability / exploitability layer | 1–2 days | Severity reflects real risk, not default rule severity. |
| 4 | Auto-fix PR generation | 2–3 days | Closes the loop. |
| 5 | SCA triage (dependency CVEs) alongside SAST | 1 day | Matches Synthesia's SAST + SCA scope. |
| 6 | Ticketing + metrics | 1 day | Observable improvement over time. |

Everything in phases 0–2 stays on the free Semgrep tier (`semgrep --config auto`).

---

## Phase 0 — Seed repos (shipped)

Two small apps under `seed-repos/` carrying a deliberate, documented mix of
vulnerabilities. Each repo's `README.md` lists every intentional finding, its
severity, whether it's a true positive or a "false-positive trap" designed to
test the AI's reasoning:

- `vuln-flask-app/` — Python/Flask: SQLi, command injection, weak crypto,
  hardcoded secret, pickle deserialization, SSRF, plus one false-positive trap
  (command execution with an enforced allowlist).
- `vuln-node-app/` — Node/Express: reflected XSS, prototype pollution, SSRF,
  command injection, open redirect, hardcoded JWT secret, plus one
  false-positive trap (shell command built from a constant).

These give you ground truth: you know the correct answer for every finding, so
triage quality is measurable instead of vibes-based.

**Success criterion:** `semgrep --config auto` finds at least 8 issues per repo.

---

## Phase 1 — Local triage CLI (shipped)

`triage-cli/triage.py` is the minimum viable pipeline:

```
semgrep --config auto --json  →  triage.py  →  report.json + report.md
                                     │
                                     └── per-finding call to Claude with:
                                         - rule ID + message
                                         - file path + ±8 lines of context
                                         - ask for JSON: {verdict, confidence,
                                           reasoning, suggested_fix_sketch}
```

Output is both machine-readable (`report.json`) and human-readable
(`report.md`), grouped by verdict.

**Success criterion:** On the seed repos, the AI correctly suppresses the
false-positive trap in each, and every true positive lands in the TP bucket
with a rationale a developer would take seriously.

**Cost guardrail:** Typical run on the seed repos is ~15–30 findings × ~1k
input tokens each. With `claude-sonnet-4-6` that's cents per run.

---

## Phase 2 — GitHub Actions wrapper (next)

Tiny workflow that:

1. Installs Semgrep and the CLI.
2. Runs triage on the PR's changed files only (pass `--paths` to Semgrep).
3. Posts the Markdown summary as a PR comment via `actions/github-script`.
4. Fails the build if any finding is classified `true_positive` with
   `severity=high` and `confidence>=0.8`.

The secret you'll need is `ANTHROPIC_API_KEY`. The workflow and a sample PR to
test it on will come in the next turn.

**Success criterion:** On a PR that introduces a real bug, the comment
appears and the check fails. On a PR with a looks-bad-but-safe change, the
comment appears as "false positive" and the check passes.

---

## Phase 3 — Reachability / exploitability

This is where the AI starts earning its keep versus plain Semgrep. For each
true-positive finding, have a second agent call that:

- Pulls the function containing the sink.
- Walks backward through callers (grep-and-read works surprisingly well at
  small repo scale).
- Asks Claude: "Does untrusted input reach this sink? If yes, through which
  entry points?"
- Downgrades severity if no untrusted path exists, upgrades if the sink is in
  an authenticated admin endpoint but reachable via a documented CSRF/auth
  bypass pattern, etc.

Architecturally this is a second agent over the same finding, with a richer
context gathering step (multi-file reads) before the verdict call. Output
schema gets two extra fields: `reachable_from_untrusted_input: bool` and
`exploit_path: string[]`.

**Success criterion:** At least one seed-repo finding has its severity
adjusted vs. Semgrep's default based on reachability reasoning.

---

## Phase 4 — Auto-fix PRs

For each true-positive with `confidence >= 0.8`:

1. Agent reads the file, proposes a patch as a unified diff.
2. CLI applies the diff on a new branch `ai-fix/<rule-id>-<hash>`.
3. Runs the repo's tests (if a `test` script exists) to catch obvious regressions.
4. Opens a PR with the original finding, the patch rationale, and a
   "please review" note.

Guardrails that matter here:

- Never auto-merge. A human approves every fix.
- Limit scope: one finding per PR, so reverts are cheap.
- Re-run Semgrep post-fix; if the original rule still fires, abort.

**Success criterion:** For the SQLi in `vuln-flask-app`, the AI opens a PR
that swaps the raw query for a parameterized one, tests still pass, and
re-scanning no longer flags that line.

---

## Phase 5 — SCA triage alongside SAST

Semgrep's free tier does SAST well but not SCA. Add a second scanner:

- **Python:** `pip-audit` → JSON of vulnerable packages with CVEs.
- **Node:** `npm audit --json` or `osv-scanner` (better, language-agnostic).

Then feed each CVE + the local usage context (which of your files actually
`import`s the vulnerable package, and which specific symbols) to Claude to
answer: "Is the vulnerable code path reachable from this codebase?" This is
the same reachability pattern as Phase 3 but over dependency CVEs.

This is where Synthesia saw a lot of their noise reduction — most CVEs in
your lockfile aren't actually exploitable because you don't use the affected
function.

**Success criterion:** A known-vulnerable `requests` or `lodash` version is
pinned in the seed repos; the AI correctly distinguishes between "you use the
vulnerable function" vs. "this is a false alarm for your usage."

---

## Phase 6 — Ticketing + metrics

Once the triage output is trustworthy, wire it to where the work actually
happens:

- Push true-positives to Linear/Jira via their REST API with a link back to
  the PR and the triage rationale.
- Record per-run metrics to a flat file or SQLite: findings seen, % classified
  TP, % FP, % suppressed, cost in tokens. Chart the trend over time.

The metric that matters is **% of findings a developer takes seriously** —
track that by whether the ticket gets closed as "won't fix" vs. fixed.

---

## What's shipped in this turn

- `DEMO-PLAN.md` — this file.
- `README.md` — repo-level orientation.
- `seed-repos/vuln-flask-app/` — Python seed repo.
- `seed-repos/vuln-node-app/` — Node seed repo.
- `triage-cli/` — local CLI for Phase 1.

## What to do next

1. `cd triage-cli && pip install -r requirements.txt && pip install semgrep`
2. `export ANTHROPIC_API_KEY=sk-...`
3. `python triage.py ../seed-repos/vuln-flask-app --out ./flask-report`
4. Open `flask-report.md` and eyeball the verdicts. That's Phase 1 done.
5. Come back and we'll add the GitHub Actions wrapper (Phase 2).

## Notes on model choice

The CLI defaults to `claude-sonnet-4-6` — strong code reasoning at roughly a
fifth of Opus pricing, and fast enough that scanning 20–30 findings takes
under a minute. Swap to `claude-opus-4-6` for the reachability phase if the
multi-file reasoning struggles.
