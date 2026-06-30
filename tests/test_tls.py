# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for TLS ClientHello parsing and JA3/JA4."""

import hashlib
import struct
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.tls import parse_client_hello, ja3, ja4, fingerprint  # noqa: E402


def _ext(etype, data):
    return struct.pack("!HH", etype, len(data)) + data


def _build_ch(version, ciphers, exts):
    body = struct.pack("!H", version) + b"\x00" * 32 + b"\x00"
    cs = b"".join(struct.pack("!H", c) for c in ciphers)
    body += struct.pack("!H", len(cs)) + cs + b"\x01\x00"
    eb = b"".join(_ext(t, d) for t, d in exts)
    body += struct.pack("!H", len(eb)) + eb
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _sample():
    return _build_ch(0x0303, [0x0a0a, 0x1301, 0x002f], [
        (0x0000, struct.pack("!H", 11) + b"\x00" + struct.pack("!H", 8) + b"lab.test"),
        (0x000a, struct.pack("!H", 4) + struct.pack("!HH", 29, 23)),
        (0x000b, b"\x01\x00"),
    ])


def test_parse_basic_fields():
    ch = parse_client_hello(_sample())
    assert ch is not None
    assert ch.legacy_version == 0x0303
    assert ch.sni == "lab.test"
    assert 29 in ch.groups and 23 in ch.groups


def test_ja3_string_and_grease_filtered():
    ch = parse_client_hello(_sample())
    s, h = ja3(ch)
    # GREASE cipher 0x0a0a (2570) excluded; 0x1301=4865, 0x002f=47
    assert s == "771,4865-47,0-10-11,29-23,0", s
    assert h == hashlib.md5(s.encode()).hexdigest()


def test_ja4_structure():
    ch = parse_client_hello(_sample())
    fp = ja4(ch)
    a, b, c = fp.split("_")
    assert a.startswith("t12d")     # TLS1.2, SNI present
    assert a[4:6] == "02"           # 2 ciphers after GREASE
    assert len(b) == 12 and len(c) == 12


def test_fingerprint_on_garbage_returns_none():
    assert fingerprint(b"not a tls hello") is None
