# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the Phase 3 traffic-mimicry / encryption-tell analytic."""

import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.mimicry import (  # noqa: E402
    shannon_entropy, protocol_fingerprint, analyze_mimicry)


def test_entropy_low_vs_high():
    assert shannon_entropy(b"A" * 1000) < 1.0
    assert shannon_entropy(os.urandom(4096)) > 7.5


def test_protocol_fingerprint():
    assert protocol_fingerprint(b"\x16\x03\x01\x00\x50") == "tls"
    assert protocol_fingerprint(b"SSH-2.0-OpenSSH_9") == "ssh"
    assert protocol_fingerprint(b"GET / HTTP/1.1\r\n") == "http"
    assert protocol_fingerprint(b"random noise") is None


def test_protocol_on_unexpected_port():
    ev = {"service": "tcp_sink", "src_ip": "10.0.0.5", "dst_port": 1080,
          "event_type": "capture",
          "request": {"preview": (b"\x16\x03\x01\x00\x50").hex()}}
    rep = analyze_mimicry([ev])
    assert any(f["type"] == "protocol-on-unexpected-port" for f in rep["findings"])


def test_domain_fronting_heuristic():
    ev = {"service": "http", "src_ip": "10.0.0.6", "event_type": "request",
          "tags": ["missing-user-agent"],
          "request": {"method": "GET", "path": "/x", "host": "d123.cloudfront.net",
                      "headers": {}, "body_len": 0}}
    rep = analyze_mimicry([ev])
    assert any(f["type"] == "possible-domain-fronting" for f in rep["findings"])


def test_encrypted_body_detected(tmp_path):
    blob = os.urandom(2048)
    artpath = tmp_path / "art.bin"
    artpath.write_bytes(blob)
    ev = {"service": "http", "src_ip": "10.0.0.7", "event_type": "request",
          "tags": [],
          "request": {"method": "POST", "path": "/up", "host": "x",
                      "headers": {"content-type": "text/plain"}, "body_len": 2048},
          "artifacts": [{"kind": "upload", "path": str(artpath),
                         "sha256": "x", "size": 2048}]}
    rep = analyze_mimicry([ev])
    assert any(f["type"] == "encrypted-body" for f in rep["findings"])


def test_browser_ua_but_bot():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.0 Safari/537.36"
    evs = [{"service": "http", "src_ip": "10.0.0.8", "event_type": "request",
            "tags": [],
            "request": {"method": "GET", "path": "/beacon", "host": "h",
                        "headers": {"user-agent": ua}, "body_len": 0}}
           for _ in range(6)]
    rep = analyze_mimicry(evs)
    assert any(f["type"] == "browser-ua-but-bot" for f in rep["findings"])
