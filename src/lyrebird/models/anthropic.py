# SPDX-License-Identifier: GPL-3.0-or-later
"""Anthropic (Claude) provider."""
from __future__ import annotations
import os
from typing import Any
import requests
from .base import ModelProvider, ModelResult

API = "https://api.anthropic.com/v1/messages"


class AnthropicProvider(ModelProvider):
    name = "anthropic"

    def __init__(self, model: str = "claude-sonnet-4-6", **opts: Any) -> None:
        super().__init__(model, **opts)
        self.api_key = opts.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")

    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024,
                 temperature: float = 0.2) -> ModelResult:
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        r = requests.post(API, timeout=60, headers={
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }, json={
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        })
        r.raise_for_status()
        data = r.json()
        text = "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text")
        return ModelResult(text=text, provider=self.name, model=self.model, raw=data)