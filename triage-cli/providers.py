"""LLM provider abstraction.

Why this exists
---------------
Phase 1/3 of the CLI hardcoded `anthropic.Anthropic`. That's fine for one
model but locks us out of two real-world scenarios:

  1. Customers on Azure who can only send data to an Azure-hosted endpoint
     (compliance, billing, BYO-model).
  2. Evaluating the same triage prompts on non-Anthropic models (Llama,
     Mistral, Phi) to measure quality vs cost.

The abstraction is tiny on purpose: both stages of the pipeline (triage
and reachability) only need "take a system prompt + a user prompt, return
a string" - no streaming, no tools, no vision. So the provider interface
is one method: `chat(system, user, max_tokens) -> str`.

Supported backends
------------------
- anthropic    : direct Anthropic API (existing behavior).

- azure        : Azure AI Foundry via `azure-ai-inference`. This client
                 is the unified Foundry SDK - it talks to both
                 OpenAI-compatible deployments (gpt-4o, gpt-5) and
                 non-OpenAI catalog models (Llama 3.3, Mistral Large,
                 Phi-4) through one interface. Requires the Foundry
                 `/models` inference surface to be enabled on the
                 resource.

- azure-openai : Azure OpenAI via the `openai` SDK (`AzureOpenAI`
                 client). Use this when your Azure resource only
                 exposes the classic `.openai.azure.com/...` or the
                 newer `/openai/v1` OpenAI-SDK-compatible endpoint.
                 Works with both URL shapes; the SDK fills in paths.

Not sure which Azure mode you need? If hitting
`<endpoint>/models/chat/completions` returns 404 with a valid API key,
use `azure-openai`. If it returns a completion, use `azure`.

Configuration (env vars)
------------------------
  TRIAGE_PROVIDER       = "anthropic" (default) | "azure" | "azure-openai"

  # Anthropic
  ANTHROPIC_API_KEY     = sk-ant-...
  ANTHROPIC_MODEL       = claude-sonnet-4-6  (optional; CLI --model wins)

  # Azure AI Foundry  (TRIAGE_PROVIDER=azure)
  AZURE_AI_ENDPOINT     = https://<project>.services.ai.azure.com/models
  AZURE_AI_API_KEY      = <foundry project key>
  AZURE_AI_MODEL        = gpt-4o | Llama-3.3-70B-Instruct | ...

  # Azure OpenAI  (TRIAGE_PROVIDER=azure-openai)
  AZURE_AI_ENDPOINT     = https://<resource>.openai.azure.com/
                          (the /openai/v1 or /openai suffix is stripped
                          automatically - paste whichever URL the portal
                          shows)
  AZURE_AI_API_KEY      = <resource api key>
  AZURE_AI_MODEL        = <deployment-name>  (not the base model name)
  AZURE_AI_API_VERSION  = 2024-10-21  (optional; default supplied)
"""

from __future__ import annotations

import os
from typing import Optional, Protocol


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

class LLMProvider(Protocol):
    """The only thing the triage and reachability stages need from a model."""

    name: str      # short identifier for logs, e.g. "anthropic" / "azure"
    model: str     # model / deployment name, for logs & reports

    def chat(self, system: str, user: str, max_tokens: int = 600) -> str:
        """Send a single-turn message. Return the assistant's text content."""
        ...


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------

class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str):
        # Import lazily so a user on Azure-only doesn't need the SDK installed.
        try:
            from anthropic import Anthropic
        except ImportError as exc:
            raise RuntimeError(
                "TRIAGE_PROVIDER=anthropic but the `anthropic` package is "
                "not installed. Run: pip install anthropic"
            ) from exc
        self.model = model
        try:
            self._client = Anthropic()
        except TypeError as exc:
            # Legacy anthropic + httpx>=0.28 combo - clearer error than the
            # raw TypeError about `proxies=`.
            if "proxies" in str(exc):
                raise RuntimeError(
                    "Incompatible anthropic SDK / httpx versions detected.\n"
                    "Fix with:  pip install --upgrade anthropic\n"
                    "Fallback:  pip install 'httpx<0.28'\n"
                    f"(original error: {exc})"
                ) from exc
            raise

    def chat(self, system: str, user: str, max_tokens: int = 600) -> str:
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        # The Anthropic SDK always returns a list of content blocks; for
        # single-turn text completions the first block is the assistant text.
        return resp.content[0].text


# ---------------------------------------------------------------------------
# Azure AI Foundry (azure-ai-inference)
# ---------------------------------------------------------------------------

class AzureAIFoundryProvider:
    """Azure AI Foundry via azure-ai-inference.

    This SDK is deliberately model-agnostic: the same `ChatCompletionsClient`
    call works whether the Foundry deployment is an Azure OpenAI model
    (gpt-4o) or a catalog model (Llama-3.3). That's why we standardize on
    it rather than the OpenAI-specific `openai.AzureOpenAI` client - swapping
    between providers via env var should just work.

    Requires the resource to expose the Foundry `/models` inference surface.
    If `POST <endpoint>/chat/completions` returns 404, your resource is a
    plain Azure OpenAI one - use `AzureOpenAIProvider` instead.
    """

    name = "azure"

    def __init__(self, endpoint: str, api_key: str, model: str,
                 api_version: Optional[str] = None):
        try:
            from azure.ai.inference import ChatCompletionsClient
            from azure.core.credentials import AzureKeyCredential
        except ImportError as exc:
            raise RuntimeError(
                "TRIAGE_PROVIDER=azure but `azure-ai-inference` is not "
                "installed. Run: pip install azure-ai-inference"
            ) from exc
        self.model = model  # deployment name in Foundry
        kwargs = {
            "endpoint": endpoint,
            "credential": AzureKeyCredential(api_key),
        }
        if api_version:
            kwargs["api_version"] = api_version
        self._client = ChatCompletionsClient(**kwargs)

    def chat(self, system: str, user: str, max_tokens: int = 600) -> str:
        from azure.ai.inference.models import SystemMessage, UserMessage
        resp = self._client.complete(
            messages=[
                SystemMessage(content=system),
                UserMessage(content=user),
            ],
            model=self.model,
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content


# ---------------------------------------------------------------------------
# Azure OpenAI (openai SDK)
# ---------------------------------------------------------------------------

class AzureOpenAIProvider:
    """Azure OpenAI via the OpenAI SDK's AzureOpenAI client.

    Use this for Azure OpenAI resources (hostname ends in
    `.openai.azure.com`) regardless of whether you're hitting the classic
    `/openai/deployments/<name>` surface or the newer `/openai/v1` preview.

    The SDK appends the right path itself, so we strip `/openai/v1` or
    `/openai` from whatever endpoint the user pasted and hand the base URL
    to `AzureOpenAI`. This means all three of these URLs in
    `AZURE_AI_ENDPOINT` do the same thing:

      https://<resource>.openai.azure.com
      https://<resource>.openai.azure.com/openai
      https://<resource>.openai.azure.com/openai/v1

    The deployment name goes in `AZURE_AI_MODEL` and is passed as the
    `model` parameter on each call - Azure routes to the matching
    deployment.
    """

    name = "azure-openai"

    _DEFAULT_API_VERSION = "2024-10-21"

    def __init__(self, endpoint: str, api_key: str, model: str,
                 api_version: Optional[str] = None):
        try:
            from openai import AzureOpenAI
        except ImportError as exc:
            raise RuntimeError(
                "TRIAGE_PROVIDER=azure-openai but `openai` is not "
                "installed. Run: pip install openai"
            ) from exc

        # Normalize endpoint: AzureOpenAI wants the bare resource URL.
        # Portal shows various shapes; strip what the SDK will re-add.
        normalized = endpoint.rstrip("/")
        for suffix in ("/openai/v1", "/openai"):
            if normalized.endswith(suffix):
                normalized = normalized[: -len(suffix)]
                break

        self.model = model  # deployment name in the Azure OpenAI resource
        self._client = AzureOpenAI(
            azure_endpoint=normalized,
            api_key=api_key,
            api_version=api_version or self._DEFAULT_API_VERSION,
        )

    def chat(self, system: str, user: str, max_tokens: int = 600) -> str:
        resp = self._client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def _require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise SystemExit(f"{name} is not set.")
    return val


def get_provider(anthropic_model_cli: Optional[str] = None) -> LLMProvider:
    """Construct the configured provider.

    `anthropic_model_cli` is the CLI --model value; it wins over
    ANTHROPIC_MODEL env so `--model` overrides still work. Azure providers
    ignore this parameter - their deployment name comes from
    AZURE_AI_MODEL.
    """
    choice = (os.environ.get("TRIAGE_PROVIDER") or "anthropic").strip().lower()

    if choice == "anthropic":
        _require_env("ANTHROPIC_API_KEY")
        model = (
            anthropic_model_cli
            or os.environ.get("ANTHROPIC_MODEL")
            or "claude-sonnet-4-6"
        )
        return AnthropicProvider(model=model)

    if choice == "azure":
        endpoint = _require_env("AZURE_AI_ENDPOINT")
        api_key = _require_env("AZURE_AI_API_KEY")
        model = _require_env("AZURE_AI_MODEL")
        api_version = os.environ.get("AZURE_AI_API_VERSION") or None
        return AzureAIFoundryProvider(
            endpoint=endpoint, api_key=api_key,
            model=model, api_version=api_version,
        )

    if choice == "azure-openai":
        endpoint = _require_env("AZURE_AI_ENDPOINT")
        api_key = _require_env("AZURE_AI_API_KEY")
        model = _require_env("AZURE_AI_MODEL")
        api_version = os.environ.get("AZURE_AI_API_VERSION") or None
        return AzureOpenAIProvider(
            endpoint=endpoint, api_key=api_key,
            model=model, api_version=api_version,
        )

    raise SystemExit(
        f"Unknown TRIAGE_PROVIDER={choice!r}. "
        f"Expected one of: anthropic, azure, azure-openai."
    )
