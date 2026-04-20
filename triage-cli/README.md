# triage-cli

Phase 1 of the demo: a local CLI that runs free-tier Semgrep against a target
repo and asks an LLM for a structured verdict on every finding.

## Install

```bash
pip install -r requirements.txt
pip install semgrep
```

## Providers

The CLI is LLM-agnostic. Pick a provider by setting `TRIAGE_PROVIDER`.

### Anthropic (default)

```bash
export TRIAGE_PROVIDER=anthropic     # or omit - it's the default
export ANTHROPIC_API_KEY=sk-ant-...
# optional: override the model
export ANTHROPIC_MODEL=claude-sonnet-4-6
```

You can also override the Anthropic model per-run with `--model`:

```bash
python triage.py ../vuln-flask-app --model claude-opus-4-6
```

### Azure AI Foundry (via `azure-ai-inference`)

Use this when your Foundry project exposes the unified `/models` inference
endpoint. Works for both Azure OpenAI deployments (gpt-4o, gpt-5) and
catalog models (Llama-3.3, Mistral Large, Phi-4) through the same API.

```bash
export TRIAGE_PROVIDER=azure
export AZURE_AI_ENDPOINT="https://<your-project>.services.ai.azure.com/models"
export AZURE_AI_API_KEY="<your-foundry-project-key>"
export AZURE_AI_MODEL="<deployment-name>"   # e.g. gpt-4o, Llama-3.3-70B-Instruct
# optional:
export AZURE_AI_API_VERSION="2024-10-21"
```

### Azure OpenAI (via `openai` SDK)

Use this when your Azure resource is a plain Azure OpenAI resource
(hostname ends in `.openai.azure.com`) and doesn't expose the Foundry
`/models` surface. Accepts either the classic resource URL or the newer
`/openai/v1` preview endpoint - the extra path is stripped automatically.

```bash
export TRIAGE_PROVIDER=azure-openai
export AZURE_AI_ENDPOINT="https://<resource>.openai.azure.com/openai/v1"
# ^ or just https://<resource>.openai.azure.com/ - both work
export AZURE_AI_API_KEY="<resource-api-key>"
export AZURE_AI_MODEL="<deployment-name>"   # NOT the base model name
# optional:
export AZURE_AI_API_VERSION="2024-10-21"
```

**Which Azure mode do I need?** Try the Foundry `/models` endpoint first.
If this curl returns a 404 with a valid API key...

```bash
curl -sS \
  "$AZURE_AI_ENDPOINT/chat/completions?api-version=2024-10-21" \
  -H "api-key: $AZURE_AI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"'"$AZURE_AI_MODEL"'","messages":[{"role":"user","content":"ping"}],"max_tokens":5}'
```

...then your resource is a plain Azure OpenAI one - use `azure-openai`. If
it returns a completion, use `azure`.

### In GitHub Actions

Set the env vars from repo secrets. Example snippet (add to
`.github/workflows/ai-triage.yml`):

```yaml
      - name: Run Semgrep + LLM triage on PR changes
        env:
          TRIAGE_PROVIDER:      ${{ secrets.TRIAGE_PROVIDER }}       # anthropic | azure | azure-openai
          ANTHROPIC_API_KEY:    ${{ secrets.ANTHROPIC_API_KEY }}     # if anthropic
          ANTHROPIC_MODEL:      ${{ secrets.ANTHROPIC_MODEL }}       # optional
          AZURE_AI_ENDPOINT:    ${{ secrets.AZURE_AI_ENDPOINT }}     # if azure or azure-openai
          AZURE_AI_API_KEY:     ${{ secrets.AZURE_AI_API_KEY }}      # if azure or azure-openai
          AZURE_AI_MODEL:       ${{ secrets.AZURE_AI_MODEL }}        # if azure or azure-openai
          AZURE_AI_API_VERSION: ${{ secrets.AZURE_AI_API_VERSION }}  # optional
        run: |
          python triage-cli/triage.py . \
            --baseline "${{ steps.base.outputs.sha }}" \
            --out report \
            --fail-on high-tp
```

Only the vars for the provider you've chosen need to be set; unused ones
can be empty.

## Run

```bash
# Triage the Flask seed repo
python triage.py ../vuln-flask-app --out ../flask-report

# Triage the Node seed repo
python triage.py ../vuln-node-app --out ../node-report

# Only triage the first 5 findings
python triage.py ../vuln-flask-app --max 5
```

Output:

- `<prefix>.json` - structured results (one entry per finding with
  `{finding, verdict}`).
- `<prefix>.md` - human-readable summary grouped by verdict.

The first line of CLI output tells you which provider/model was picked:

```
[triage] provider=anthropic model=claude-sonnet-4-6
...
[triage] provider=azure-openai model=gpt-4o
```

## What to look at in the output

For each seed repo, compare the Markdown summary against the repo's
`README.md` ground-truth table:

- Every row labeled `TP` should land in "Confirmed vulnerabilities".
- Rows labeled `FP-trap` should land in "Rejected by AI triage (false
  positives)" with a rationale that names the allowlist / constant input
  that makes it safe.
- `Needs manual review` should be rare - if there are more than a couple,
  the prompt needs tightening.

## Tunables

| Flag              | Default               | What it does |
|-------------------|-----------------------|--------------|
| `--out PREFIX`    | `report`              | Output prefix; produces `.json` and `.md`. |
| `--model NAME`    | (env / provider)      | Anthropic model override. Ignored for Azure providers - they take their deployment from `AZURE_AI_MODEL`. |
| `--max N`         | `0` (all)             | Stop after N findings (useful while iterating). |
| `--concurrency K` | `4`                   | Parallel triage calls. Raise cautiously to respect rate limits. |
| `--baseline REF`  | none                  | Only triage findings introduced since git ref `REF`. Used in CI. |
| `--fail-on MODE`  | none                  | Exit nonzero on `any-tp` or `high-tp`. Honors reachability. |
| `--no-reachability` | off                 | Skip Phase 3 cross-file reachability pass. |

## Known limitations (by design for Phase 1)

- Code context is a +/-15-line window around the sink. Phase 3 already
  widens to multi-file reachability for true-positive findings.
- No caching. If you re-run you pay again. Easy addition: hash
  `(rule_id, file_sha, start, end)` and memoize the verdict.
- SAST only. Phase 5 adds SCA.
- The provider abstraction targets chat completions only (no streaming,
  tools, or vision). That's all Phase 1/3 need; adding a new backend
  means implementing one `chat()` method in `providers.py`.
