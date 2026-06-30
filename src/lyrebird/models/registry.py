# SPDX-License-Identifier: GPL-3.0-or-later
"""Provider registry / factory.

Resolves a config block like::

    models:
      provider: local          # anthropic | openai | gemini | local | mock
      model: "llama3.1"
      base_url: "http://localhost:11434/v1"   # local only

into a concrete ``ModelProvider``. Selecting ``local`` keeps everything on-host
for air-gapped analysis; the frontier providers are there for richer triage when
the lab policy permits egress to those APIs.
"""

from __future__ import annotations

from typing import Any

from .base import ModelProvider
from .anthropic import AnthropicProvider
from .openai import OpenAIProvider
from .gemini import GeminiProvider
from .local import LocalProvider
from .mock import MockProvider

_PROVIDERS: dict[str, type[ModelProvider]] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
    "local": LocalProvider,
    "mock": MockProvider,
}


def build_provider(cfg: dict[str, Any]) -> ModelProvider:
    name = (cfg or {}).get("provider", "local").lower()
    cls = _PROVIDERS.get(name)
    if cls is None:
        raise ValueError(f"unknown model provider '{name}'. "
                         f"choose from {sorted(_PROVIDERS)}")
    opts = {k: v for k, v in (cfg or {}).items() if k not in ("provider", "model")}
    model = (cfg or {}).get("model")
    return cls(model=model, **opts) if model else cls(**opts)


def provider_names() -> list[str]:
    return sorted(_PROVIDERS)