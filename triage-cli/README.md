# triage-cli

The Python CLI that powers the Arbiter GitHub Action. You can also run it directly for local triage without GitHub Actions.

## Install

```bash
pip install -r requirements.txt
```

To use Semgrep as your scanner:
```bash
pip install semgrep
```

## Local usage

Run your scanner first, then pass the SARIF output to the CLI:

```bash
# 1. Run your scanner
semgrep scan --config auto --sarif --output semgrep.sarif /path/to/repo

# 2. Triage
python triage.py /path/to/repo --sarif semgrep.sarif --out report

# 3. Read results
cat report.md
```

Or triage GitHub Code Scanning alerts directly (no local scanner needed):

```bash
export GITHUB_TOKEN=ghp_...
python triage.py /path/to/repo \
  --scanners github-code-scanning \
  --github-repo owner/repo \
  --out report
```

## Providers

Set `TRIAGE_PROVIDER` to select the LLM backend. All other env vars are read automatically.

### Anthropic (default)

```bash
export TRIAGE_PROVIDER=anthropic      # or omit
export ANTHROPIC_API_KEY=sk-ant-...
export ANTHROPIC_MODEL=claude-sonnet-4-6   # optional
```

### Azure AI Foundry

```bash
export TRIAGE_PROVIDER=azure
export AZURE_AI_ENDPOINT="https://<project>.services.ai.azure.com/models"
export AZURE_AI_API_KEY="<key>"
export AZURE_AI_MODEL="<deployment-name>"
```

### Azure OpenAI

```bash
export TRIAGE_PROVIDER=azure-openai
export AZURE_AI_ENDPOINT="https://<resource>.openai.azure.com"
export AZURE_AI_API_KEY="<key>"
export AZURE_AI_MODEL="<deployment-name>"
```

## CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--sarif FILE` | — | SARIF file to triage |
| `--sarif-dir DIR` | — | Directory of `*.sarif` files to triage |
| `--scanners LIST` | — | `semgrep`, `github-code-scanning` (alias: `codeql`) |
| `--github-repo` | — | `owner/repo` — required for `github-code-scanning` |
| `--github-ref` | — | PR head ref for CodeQL alert lookup |
| `--baseline REF` | — | Git ref; filters SARIF findings to files changed since this commit |
| `--backlog` | off | Fetch and triage all open CodeQL alerts (no baseline needed) |
| `--fail-on MODE` | — | `high-tp` or `any-tp` — exit nonzero when gate is tripped |
| `--out PREFIX` | `report` | Output prefix → `<prefix>.md` and `<prefix>.json` |
| `--model NAME` | env | Anthropic model override |
| `--max N` | 0 (all) | Cap findings triaged (useful while iterating) |
| `--concurrency K` | 4 | Parallel LLM calls |
| `--no-reachability` | off | Skip cross-file reachability pass |
| `--dismiss-fps` | off | Dismiss FP-verdicted CodeQL alerts via API (backlog mode) |
| `--post-comments` | off | Post per-alert verdict comments (backlog mode) |

## Output

- `<prefix>.json` — array of `{finding, verdict}` objects
- `<prefix>.md` — human-readable report grouped by verdict (true positive / false positive / needs review)

## Tests

```bash
pytest tests/ -v
```
