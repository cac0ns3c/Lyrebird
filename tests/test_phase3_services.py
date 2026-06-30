# SPDX-License-Identifier: GPL-3.0-or-later
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.orchestrator import REGISTRY  # noqa: E402
from lyrebird.mimicry import analyze_mimicry  # noqa: E402


def test_new_services_registered():
    for name in ("imap", "dns_tcp", "tls_capture"):
        assert name in REGISTRY


def test_sni_host_mismatch_flagged():
    events = [
        {"service": "tls_capture", "src_ip": "10.0.0.9", "event_type": "request",
         "request": {"sni": "cdn.fastly.net", "ja3": "x", "ja4": "y"}},
        {"service": "http", "src_ip": "10.0.0.9", "event_type": "request", "tags": [],
         "request": {"method": "GET", "path": "/", "host": "evil-c2.example",
                     "headers": {}, "body_len": 0}},
    ]
    rep = analyze_mimicry(events)
    assert any(f["type"] == "sni-host-mismatch" for f in rep["findings"])
