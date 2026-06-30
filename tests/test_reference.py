# SPDX-License-Identifier: GPL-3.0-or-later
"""REFERENCE.md is generated and must stay in sync with the source.

Mirrors the lint_sigma / pairing-guard philosophy: the reference can't silently
drift from events.py or the Sigma rules — if it does, this test fails and tells
you to regenerate it.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

import gen_reference  # noqa: E402


def test_reference_is_current():
    out = ROOT / "REFERENCE.md"
    assert out.exists(), "REFERENCE.md missing — run: python scripts/gen_reference.py"
    assert out.read_text(encoding="utf-8") == gen_reference.render(), (
        "REFERENCE.md is stale — run: python scripts/gen_reference.py"
    )


def test_reference_covers_schema_and_detections():
    text = gen_reference.render()
    assert "Event schema" in text and "Detection catalog" in text
    # a couple of representative anchors so an empty/broken render is caught
    assert "`service`" in text
    assert "sni-host-mismatch" in text
