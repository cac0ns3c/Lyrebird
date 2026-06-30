# SPDX-License-Identifier: GPL-3.0-or-later
"""Local model provider.

Talks to any OpenAI-compatible local server: Ollama (`/v1`), LM Studio,
llama.cpp's server, vLLM, etc. Default endpoint is Ollama. This is the path for
air-gapped labs — no data leaves the host.
"""
from __future__ import annotations
import os
from typing import Any
import requests
from .base import ModelProvider, ModelResult


class LocalProvider(ModelProvider):
    name = "local"

    def __init__(self, model: str = "llama3.1", **opts: Any) -> None:
        super().__init__(model, **opts)
        self.base_url = (opts.get("base_url")
                         or os.environ.get("LYREBIRD_LOCAL_URL", "http://localhost:11434/v1"))
        self.api_key = opts.get("api_key") or os.environ.get("LYREBIRD_LOCAL_KEY", "not-needed")

    def available(self) -> bool:
        try:
            requests.get(self.base_url.rsplit("/v1", 1)[0], timeout=2)
            return True
        except Exception:
            return False

    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024,
                 temperature: float = 0.2) -> ModelResult:
        r = requests.post(f"{self.base_url}/chat/completions", timeout=120, headers={
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