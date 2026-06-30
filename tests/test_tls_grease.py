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


from lyrebird.tls import ja4, ja4_raw  # noqa: E402


def _sample_ch():
    return ClientHello(legacy_version=0x0303, ciphers=[0x1302, 0x1301],
                       extensions=[0x0000, 0x002b, 0x000d],
                       sig_algs=[0x0403], supported_versions=[0x0304])


def test_ja4_unchanged_shape():
    # JA4 is three underscore-separated parts; b and c are 12-hex-char hashes.
    parts = ja4(_sample_ch()).split("_")
    assert len(parts) == 3
    assert len(parts[1]) == 12 and len(parts[2]) == 12


def test_ja4_raw_shares_prefix_and_is_unhashed():
    ch = _sample_ch()
    raw = ja4_raw(ch)
    assert raw.split("_")[0] == ja4(ch).split("_")[0]          # same ja4_a prefix
    # raw cipher list is the literal sorted hex, not a 12-char hash
    assert raw.split("_")[1] == "1301,1302"
