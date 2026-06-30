# SPDX-License-Identifier: GPL-3.0-or-later
"""Model provider abstraction.

A thin, uniform interface over frontier APIs (Anthropic, OpenAI, Gemini) and
local runtimes (Ollama / any OpenAI-compatible local server). Everything else
in Lyrebird talks to ``ModelProvider`` and never to a specific vendor SDK, so a
lab can run fully offline by selecting the ``local`` provider.

Two consumers:
  * analysis  — read captured traffic, summarize, draft detections (default use)
  * responder — optional, guardrailed generation of benign service responses
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any


@dataclass
class ModelResult:
    text: str
    provider: str
    model: str
    raw: dict[str, Any] | None = None


class ModelProvider(abc.ABC):
    """Uniform completion interface. Implementations live alongside this file."""

    name: str = "base"

    def __init__(self, model: str, **opts: Any) -> None:
        self.model = model
        self.opts = opts

    @abc.abstractmethod
    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024,
                 temperature: float = 0.2) -> ModelResult:
        """Return a single completion. Implementations should be synchronous and
        raise on transport/auth failure so callers can degrade gracefully."""

    def available(self) -> bool:
        """Cheap check that the provider is usable (key present / endpoint up).
        Default True; providers override where a quick check is possible."""
        return True