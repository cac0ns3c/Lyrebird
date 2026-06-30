# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for GREASE / TLS-1.3 detection and JA4 raw enrichment."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.tls import ClientHello, grease_present, offers_tls13  # noqa: E402


def test_grease_present_true_when_grease_in_ciphers():
    ch = ClientHello(ciphers=[0x0a0a, 0x1301])
    assert grease_present(ch) is True


def test_grease_present_false_without_grease():
    ch = ClientHello(ciphers=[0x1301], extensions=[0x002b], supported_versions=[0x0304])
    assert grease_present(ch) is False


def test_offers_tls13_true():
    ch = ClientHello(supported_versions=[0x0303, 0x0304])
    assert offers_tls13(ch) is True


def test_offers_tls13_false_when_only_12():
    ch = ClientHello(supported_versions=[0x0303])
    assert offers_tls13(ch) is False
