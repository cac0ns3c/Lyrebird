# SPDX-License-Identifier: GPL-3.0-or-later
"""Deterministic offline provider for tests and dry-runs (no network)."""
from __future__ import annotations
import json
from typing import Any
from .base import ModelProvider, ModelResult


class MockProvider(ModelProvider):
    name = "mock"

    def __init__(self, model: str = "mock-1", **opts: Any) -> None:
        super().__init__(model, **opts)

    def complete(self, system: str, prompt: str, *, max_tokens: int = 1024,
                 temperature: float = 0.2) -> ModelResult:
        # If a JSON object is expected, return a minimal valid analysis shape.
        if "JSON" in system or "json" in system:
            text = json.dumps({
                "summary": "mock analysis: observed HTTP/DNS activity",
                "verdict": "suspicious",
                "indicators": [],
                "suggested_detections": [],
            })
        else:
            text = "OK"
        return ModelResult(text=text, provider=self.name, model=self.model)