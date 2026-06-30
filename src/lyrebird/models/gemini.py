# SPDX-License-Identifier: GPL-3.0-or-later
"""Google Gemini provider."""
from __future__ import annotations
import os
from typing import Any
import requests
from .base import ModelProvider, ModelResult

BASE = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiProvider(ModelProvider):
    name = "gemini"

    def __init__(self, model: str = "gemini-1.5-flash", **opts: Any) -> None:
        super().__init__(model, **opts)
        self.api_key = opts.get("api_key") or os.environ.get("GEMINI_API_KEY", "")

    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024,
                 temperature: float = 0.2) -> ModelResult:
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY not set")
        url = f"{BASE}/{self.model}:generateContent?key={self.api_key}"
        r = requests.post(url, timeout=60, headers={"content-type": "application/json"},
                          json={
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature},
        })
        r.raise_for_status()
        data = r.json()
        text = "".join(p.get("text", "")
                       for p in data["candidates"][0]["content"]["parts"])
        return ModelResult(text=text, provider=self.name, model=self.model, raw=data)