# Arbiter

> **Data handling:** Arbiter sends code snippets from your repository to the LLM provider you configure (Anthropic or Azure). No data passes through NemeaLabs. Ensure your organization's policies permit sending source code to your chosen provider before use. See [Data handling](#data-handling) for details.

AI-powered SAST triage as a GitHub Actions composite action. Run any SAST scanner, pass its SARIF output to Arbiter, and get AI verdicts (true positive / false positive / needs review) posted as a PR comment — with an optional build gate that blocks merges on high-confidence vulnerabilities.

## How it works

```
Your scanner (Semgrep / Trivy / Bandit / etc.)
        │
        ▼  SARIF file
   NemeaLabs/arbiter@v1
        │
        ├─ Phase 1: Parse findings from SARIF
        ├─ Phase 2: AI triage — verdict + confidence + reasoning per finding
        ├─ Phase 3: Reachability analysis — is the sink actually reachable?
        └─ Output: report.md (PR comment) + report.json (machine-readable)
```

Arbiter does not run any scanner itself. You run the scanner in a prior step and hand off the SARIF file.

---

## Quick start — PR triage

```yaml
# .github/workflows/triage.yml
name: Security Triage

on:
  pull_request:
    branches: [main]

jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }

      # Step 1: run your scanner and produce a SARIF file
      - name: Run Semgrep
        run: |
          pip install semgrep
          semgrep scan --config auto --sarif \
            --baseline-commit ${{ github.event.pull_request.base.sha }} \
            --output semgrep.sarif . || true

      # Step 2: triage with Arbiter
      - name: Run Arbiter
        uses: NemeaLabs/arbiter@v1
        env:
          GITHUB_TOKEN:      ${{ secrets.GITHUB_TOKEN }}
          TRIAGE_PROVIDER:   ${{ secrets.TRIAGE_PROVIDER }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        with:
          mode: pr
          github-token: ${{ secrets.GITHUB_TOKEN }}
          sarif-file: semgrep.sarif
          baseline: ${{ github.event.pull_request.base.sha }}
          fail-on: high-tp
```

---

## Inputs

### Required

| Input | Description |
|-------|-------------|
| `github-token` | GitHub token — needs `pull-requests: write` for PR comments |

### Scanner input (one required in PR mode)

| Input | Description |
|-------|-------------|
| `sarif-file` | Path to a single SARIF file from any scanner |
| `sarif-dir` | Directory of `*.sarif` files (all are merged) |
| `scanners` | `github-code-scanning` — pull alerts from the GitHub Code Scanning API (CodeQL). |

### PR mode options

| Input | Default | Description |
|-------|---------|-------------|
| `mode` | `pr` | Run mode: `pr` or `backlog` |
| `baseline` | — | Base commit SHA; filters SARIF findings to files changed in this PR |
| `fail-on` | — | `high-tp` — fail when a high/critical true positive with confidence ≥ 0.8 is found. `any-tp` — fail on any true positive. |
| `github-ref` | — | PR head ref (e.g. `refs/pull/N/head`). Required for `scanners: github-code-scanning`. |

### Backlog mode options

| Input | Default | Description |
|-------|---------|-------------|
| `post-comments` | `false` | Post per-alert triage comments on GitHub Code Scanning alerts |
| `dismiss-fps` | `false` | Auto-dismiss false-positive CodeQL alerts (requires `security-events: write`) |
| `skip-alerts` | — | Comma-separated alert numbers to skip (already triaged) |
| `summary-issue` | — | Issue number for fallback per-alert comments |

### LLM provider

Pass credentials via `env:` on the `uses:` step (see provider setup below).

| Env var | Description |
|---------|-------------|
| `TRIAGE_PROVIDER` | `anthropic` (default), `azure`, or `azure-openai` |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `ANTHROPIC_MODEL` | Model override (default: `claude-sonnet-4-6`) |
| `AZURE_AI_ENDPOINT` | Azure AI Foundry or Azure OpenAI endpoint URL |
| `AZURE_AI_API_KEY` | Azure API key |
| `AZURE_AI_MODEL` | Azure deployment name |
| `AZURE_AI_API_VERSION` | Azure API version (optional) |

### Shared options

| Input | Default | Description |
|-------|---------|-------------|
| `target` | `.` | Path to the repository root |
| `out` | `arbiter-report` | Output file prefix — produces `<prefix>.md` and `<prefix>.json` |
| `concurrency` | `4` | Parallel LLM triage calls |
| `no-reachability` | `false` | Skip the reachability analysis pass |

---

## Outputs

| Output | Description |
|--------|-------------|
| `report-md` | Path to the generated Markdown report |
| `report-json` | Path to the generated JSON report |
| `exit-code` | `0` = pass, `1` = fail-on gate triggered |

---

## Provider setup

### Anthropic

```yaml
env:
  TRIAGE_PROVIDER:   anthropic   # or omit — it's the default
  ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  ANTHROPIC_MODEL:   claude-sonnet-4-6   # optional
```

### Azure AI Foundry

Use when your endpoint is `https://<project>.services.ai.azure.com/models`.

```yaml
env:
  TRIAGE_PROVIDER:   azure
  AZURE_AI_ENDPOINT: ${{ secrets.AZURE_AI_ENDPOINT }}
  AZURE_AI_API_KEY:  ${{ secrets.AZURE_AI_API_KEY }}
  AZURE_AI_MODEL:    ${{ secrets.AZURE_AI_MODEL }}
```

### Azure OpenAI

Use when your endpoint ends in `.openai.azure.com`.

```yaml
env:
  TRIAGE_PROVIDER:   azure-openai
  AZURE_AI_ENDPOINT: ${{ secrets.AZURE_AI_ENDPOINT }}
  AZURE_AI_API_KEY:  ${{ secrets.AZURE_AI_API_KEY }}
  AZURE_AI_MODEL:    ${{ secrets.AZURE_AI_MODEL }}
```

---

## Examples

### Trivy (filesystem scan)

```yaml
      - name: Run Trivy
        uses: aquasecurity/trivy-action@v0.35.0
        with:
          scan-type: fs
          format: sarif
          output: trivy.sarif
          exit-code: '0'

      - name: Run Arbiter
        uses: NemeaLabs/arbiter@v1
        env:
          GITHUB_TOKEN:      ${{ secrets.GITHUB_TOKEN }}
          TRIAGE_PROVIDER:   ${{ secrets.TRIAGE_PROVIDER }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        with:
          mode: pr
          github-token: ${{ secrets.GITHUB_TOKEN }}
          sarif-file: trivy.sarif
          baseline: ${{ github.event.pull_request.base.sha }}
          fail-on: high-tp
```

### GitHub Code Scanning / CodeQL

```yaml
      - name: Run Arbiter
        uses: NemeaLabs/arbiter@v1
        env:
          GITHUB_TOKEN:      ${{ secrets.GITHUB_TOKEN }}
          TRIAGE_PROVIDER:   ${{ secrets.TRIAGE_PROVIDER }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        with:
          mode: pr
          github-token: ${{ secrets.GITHUB_TOKEN }}
          scanners: github-code-scanning
          github-ref: refs/pull/${{ github.event.pull_request.number }}/head
          fail-on: high-tp
```

### Weekly backlog triage (single repo, in-repo workflow)

Add this to the repository you want to triage. `GITHUB_TOKEN` has the right permissions automatically.

```yaml
on:
  schedule:
    - cron: '0 9 * * 1'   # Monday 09:00 UTC

jobs:
  backlog:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      issues: write

    steps:
      - uses: actions/checkout@v4

      - name: Run Arbiter
        uses: NemeaLabs/arbiter@v1
        env:
          GITHUB_TOKEN:      ${{ secrets.GITHUB_TOKEN }}
          TRIAGE_PROVIDER:   ${{ secrets.TRIAGE_PROVIDER }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        with:
          mode: backlog
          github-token: ${{ secrets.GITHUB_TOKEN }}
          post-comments: 'true'
          dismiss-fps: 'false'
```

### Scheduled backlog triage across multiple repos (dedicated runner)

For teams managing multiple repositories, run Arbiter from a **dedicated runner repo** that has a single `TRIAGE_GITHUB_TOKEN` (a PAT or app token with `security-events: read` on every target repo). This keeps triage credentials in one place and lets you triage repos that don't have Arbiter in their own workflows.

**Runner repo layout:**
```
.github/workflows/backlog.yml   # workflow below
repos.txt                       # one owner/repo per line
```

**`repos.txt`:**
```
# one owner/repo per line; lines starting with # are ignored
acme/api-service
acme/web-frontend
acme/data-pipeline
```

**`.github/workflows/backlog.yml`:**
```yaml
name: Backlog Triage

on:
  schedule:
    - cron: '0 9 * * 1'   # Monday 09:00 UTC
  workflow_dispatch:
    inputs:
      repos:
        description: 'Repos to triage (comma-separated owner/repo). Defaults to repos.txt.'
        required: false
      dismiss_fps:
        description: 'Auto-dismiss AI-confirmed false positives'
        type: boolean
        default: false

jobs:
  setup:
    runs-on: ubuntu-latest
    outputs:
      matrix: ${{ steps.repos.outputs.matrix }}
    steps:
      - uses: actions/checkout@v4
      - name: Build repo matrix
        id: repos
        run: |
          if [ -n "${{ inputs.repos }}" ]; then
            RAW="${{ inputs.repos }}"
          else
            RAW=$(grep -v '^\s*#' repos.txt | grep -v '^\s*$' | tr '\n' ',')
          fi
          MATRIX=$(echo "$RAW" | tr ',\n' '\n' | sed 's/[[:space:]]//g' \
            | grep -v '^$' | jq -R -s -c 'split("\n") | map(select(length > 0))')
          echo "matrix=$MATRIX" >> "$GITHUB_OUTPUT"

  triage:
    needs: setup
    runs-on: ubuntu-latest
    strategy:
      matrix:
        repo: ${{ fromJson(needs.setup.outputs.matrix) }}
      fail-fast: false
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ matrix.repo }}
          token: ${{ secrets.TRIAGE_GITHUB_TOKEN }}

      - name: Run Arbiter backlog
        uses: NemeaLabs/arbiter@v1
        env:
          GITHUB_TOKEN:      ${{ secrets.TRIAGE_GITHUB_TOKEN }}
          TRIAGE_PROVIDER:   ${{ secrets.TRIAGE_PROVIDER }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        with:
          mode: backlog
          github-token: ${{ secrets.TRIAGE_GITHUB_TOKEN }}
          github-repo: ${{ matrix.repo }}
          post-comments: 'true'
          dismiss-fps: ${{ inputs.dismiss_fps || 'false' }}

      - uses: actions/upload-artifact@v4
        with:
          name: report-${{ matrix.repo }}
          path: arbiter-report.*
```

**Required secrets in the runner repo:**

| Secret | Description |
|--------|-------------|
| `TRIAGE_GITHUB_TOKEN` | PAT or app token with `security-events: read` (and `security-events: write` if using `dismiss-fps`) on all target repos |
| `TRIAGE_PROVIDER` | `anthropic`, `azure`, or `azure-openai` |
| `ANTHROPIC_API_KEY` | When `TRIAGE_PROVIDER=anthropic` |

You can also trigger a one-off run manually from the Actions tab and override the repo list inline — useful for triaging a single repo without editing `repos.txt`.

### Multiple scanners in one PR check

```yaml
      - name: Run Semgrep
        run: |
          pip install semgrep
          semgrep scan --config auto --sarif \
            --baseline-commit ${{ github.event.pull_request.base.sha }} \
            --output semgrep.sarif . || true

      - name: Run Trivy
        uses: aquasecurity/trivy-action@v0.35.0
        with:
          scan-type: fs
          format: sarif
          output: trivy.sarif
          exit-code: '0'

      - name: Run Arbiter (both SARIF files)
        uses: NemeaLabs/arbiter@v1
        env:
          GITHUB_TOKEN:      ${{ secrets.GITHUB_TOKEN }}
          TRIAGE_PROVIDER:   ${{ secrets.TRIAGE_PROVIDER }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        with:
          mode: pr
          github-token: ${{ secrets.GITHUB_TOKEN }}
          sarif-dir: .        # picks up *.sarif in the workspace root
          baseline: ${{ github.event.pull_request.base.sha }}
          fail-on: high-tp
```

---

## Required secrets

Set these under **Settings → Secrets and variables → Actions** in your repo:

| Secret | When required |
|--------|---------------|
| `TRIAGE_PROVIDER` | Always (`anthropic`, `azure`, or `azure-openai`) |
| `ANTHROPIC_API_KEY` | When `TRIAGE_PROVIDER=anthropic` |
| `AZURE_AI_ENDPOINT` | When using Azure |
| `AZURE_AI_API_KEY` | When using Azure |
| `AZURE_AI_MODEL` | When using Azure |

`GITHUB_TOKEN` is provided automatically by GitHub Actions — no secret needed.

---

## Local usage

To run the triage CLI directly without GitHub Actions:

```bash
cd triage-cli
pip install -r requirements.txt

# Set your provider credentials
export TRIAGE_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...

# Run your scanner first
semgrep scan --config auto --sarif --output semgrep.sarif /path/to/repo

# Triage the SARIF output
python triage.py /path/to/repo --sarif semgrep.sarif --out report
cat report.md
```

To triage GitHub Code Scanning alerts directly (no local scanner):

```bash
export GITHUB_TOKEN=ghp_...
python triage.py /path/to/repo \
  --scanners github-code-scanning \
  --github-repo owner/repo \
  --out report
```

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--sarif FILE` | — | SARIF file to triage |
| `--sarif-dir DIR` | — | Directory of `*.sarif` files to triage |
| `--scanners LIST` | — | `github-code-scanning` (alias: `codeql`) |
| `--github-repo` | — | `owner/repo` — required for `github-code-scanning` |
| `--github-ref` | — | PR head ref for CodeQL alert lookup |
| `--github-token` | env | GitHub token (defaults to `GITHUB_TOKEN` env var) |
| `--baseline REF` | — | Git ref; filters SARIF findings to files changed since this commit |
| `--backlog` | off | Fetch and triage all open CodeQL alerts (no baseline needed) |
| `--fail-on MODE` | — | `high-tp` or `any-tp` — exit nonzero when gate trips |
| `--out PREFIX` | `report` | Output prefix → `<prefix>.md` and `<prefix>.json` |
| `--model NAME` | env | Anthropic model override |
| `--max N` | 0 (all) | Cap findings triaged |
| `--concurrency K` | 4 | Parallel LLM calls |
| `--no-reachability` | off | Skip cross-file reachability pass |
| `--dismiss-fps` | off | Dismiss FP CodeQL alerts via API (backlog mode) |
| `--post-comments` | off | Post per-alert verdict comments (backlog mode) |

### Running tests

```bash
pytest triage-cli/tests/ -v
```

---

## Data handling

Arbiter sends code snippets (file paths, line numbers, and surrounding source code) from your repository to the LLM provider you configure — Anthropic or Azure. No data is sent to NemeaLabs or any third party beyond your chosen provider.

- **Anthropic:** subject to [Anthropic's usage policies](https://www.anthropic.com/legal/usage-policy).
- **Azure AI / Azure OpenAI:** subject to your Azure subscription's data processing terms.

Ensure your organization's data handling and code confidentiality policies permit sending source code to your chosen provider before enabling this action.

---

## License

MIT
