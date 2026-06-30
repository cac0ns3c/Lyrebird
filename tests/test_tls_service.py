# SPDX-License-Identifier: GPL-3.0-or-later
"""Integration test: the tls service fingerprints a real handshake and detects a
same-connection SNI-vs-Host mismatch (domain fronting)."""

import asyncio
import json
import socket
import ssl
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.certs import LabCA  # noqa: E402
from lyrebird.events import EventSink  # noqa: E402
from lyrebird.orchestrator import REGISTRY  # noqa: E402
from lyrebird.services.tls import TlsService  # noqa: E402


def _wait_for_events(log: Path, timeout: float = 10.0):
    """Poll the JSONL log until at least one event is flushed, or timeout.

    The tls service handles each connection on a background thread pool, so the
    event is emitted asynchronously relative to the client socket closing.
    EventSink flushes per emit(), so polling the file is a deterministic
    synchronization point — far more reliable than a fixed sleep on a loaded
    CI runner.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log.exists():
            lines = [l for l in log.read_text().splitlines() if l.strip()]
            if lines:
                return [json.loads(l) for l in lines]
        time.sleep(0.05)
    return []


def test_tls_service_registered():
    assert "tls" in REGISTRY


def test_tls_fingerprint_and_same_connection_mismatch(tmp_path):
    ca = LabCA(tmp_path / "ca")
    ca.ensure()
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = TlsService(cfg={"port": 0}, sink=sink, bind_address="127.0.0.1",
                     data_dir=tmp_path, tls={}, ca=ca)
    asyncio.run(svc.start())
    port = svc._sock.getsockname()[1]
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        c = socket.create_connection(("127.0.0.1", port), timeout=5)
        s = ctx.wrap_socket(c, server_hostname="front.example.com")
        s.sendall(b"GET / HTTP/1.1\r\nHost: evil-c2.example\r\n\r\n")
        s.recv(128)
        s.close()
        # Wait for the background handler to flush its event rather than
        # racing a fixed sleep (the handler runs in a thread pool, so its
        # timing varies on loaded CI runners).
        events = _wait_for_events(log, timeout=10.0)
    finally:
        asyncio.run(svc.stop())
        sink.close()

    assert events, "tls service emitted no events"
    e = events[0]
    assert e["request"]["sni"] == "front.example.com"
    assert e["request"]["host"] == "evil-c2.example"
    assert e["request"]["ja4"]
    assert "sni-host-mismatch" in e["tags"]
