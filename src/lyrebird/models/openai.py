# SPDX-License-Identifier: GPL-3.0-or-later
"""OpenAI provider (Chat Completions)."""
from __future__ import annotations
import os
from typing import Any
import requests
from .base import ModelProvider, ModelResult

API = "https://api.openai.com/v1/chat/completions"


class OpenAIProvider(ModelProvider):
    name = "openai"

    def __init__(self, model: str = "gpt-4o-mini", **opts: Any) -> None:
        super().__init__(model, **opts)
        self.api_key = opts.get("api_key") or os.environ.get("OPENAI_API_KEY", "")

    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024,
                 temperature: float = 0.2) -> ModelResult:
        if not self.api_key:
            raise RuntimeError("OPENAI_API_KEY not set")
        r = requests.post(API, timeout=60, headers={
            "Authorization": f"Bearer {self.api_key}",
            "content-type": "application/json",
        }, json={
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        })
        r.raise_for_status()
        data = r.json()
        text = data["choices"][0]["message"]["content"]
        return ModelResult(text=text, provider=self.name, model=self.model, raw=data)