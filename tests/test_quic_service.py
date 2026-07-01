# SPDX-License-Identifier: GPL-3.0-or-later
"""Integration tests: QUIC/HTTP-3 service captures h3 requests (aioquic client)."""
import asyncio
import json
import ssl
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aioquic.asyncio import connect  # noqa: E402
from aioquic.asyncio.protocol import QuicConnectionProtocol  # noqa: E402
from aioquic.h3.connection import H3Connection  # noqa: E402
from aioquic.h3.events import DataReceived  # noqa: E402
from aioquic.quic.configuration import QuicConfiguration  # noqa: E402
from aioquic.quic.events import ProtocolNegotiated  # noqa: E402

from lyrebird.events import EventSink  # noqa: E402
from lyrebird.services.quic import QuicService  # noqa: E402


def _wait_for_events(log: Path, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log.exists():
            lines = [l for l in log.read_text().splitlines() if l.strip()]
            if lines:
                return [json.loads(l) for l in lines]
        time.sleep(0.05)
    return []


def _mksvc(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = QuicService(cfg={"port": 0}, sink=sink, bind_address="127.0.0.1",
                      data_dir=tmp_path, tls={})
    return svc, sink, log


class _Client(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._http = None
        self.done = asyncio.get_event_loop().create_future()
        self._n = 0
        self._want = 1

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic)
        if self._http is None:
            return
        for ev in self._http.handle_event(event):
            if isinstance(ev, DataReceived) and ev.stream_ended:
                self._n += 1
                if self._n >= self._want and not self.done.done():
                    self.done.set_result(True)


async def _drive(port, requests):
    conf = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    conf.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", port, configuration=conf,
                       create_protocol=_Client) as client:
        await client.wait_connected()
        client._want = len(requests)
        for headers, body in requests:
            sid = client._quic.get_next_available_stream_id()
            client._http.send_headers(sid, headers, end_stream=(body is None))
            if body is not None:
                client._http.send_data(sid, body, end_stream=True)
        client.transmit()
        await asyncio.wait_for(client.done, timeout=5)


def _run(svc, requests):
    async def scenario():
        await svc.start()
        port = svc._server._transport.get_extra_info("sockname")[1]
        await _drive(port, requests)
        await svc.stop()
    asyncio.run(scenario())


def test_quic_captures_h3_request(tmp_path):
    svc, sink, log = _mksvc(tmp_path)
    _run(svc, [([(b":method", b"GET"), (b":scheme", b"https"),
                 (b":authority", b"evil.example"), (b":path", b"/beacon"),
                 (b"user-agent", b"bot/1.0")], None)])
    sink.close()
    events = _wait_for_events(log)
    h3 = [e for e in events if "http3-transport" in e.get("tags", [])]
    assert h3, "no http3-transport event"
    r = h3[0]["request"]
    assert r["method"] == "GET"
    assert r["path"] == "/beacon"
    assert r["authority"] == "evil.example"
    assert h3[0]["service"] == "quic"
    assert "missing-user-agent" not in h3[0]["tags"]   # UA present


def test_quic_missing_user_agent_and_body_capture(tmp_path):
    svc, sink, log = _mksvc(tmp_path)
    _run(svc, [([(b":method", b"POST"), (b":scheme", b"https"),
                 (b":authority", b"c2.bad"), (b":path", b"/up")], b"payload-bytes")])
    sink.close()
    events = _wait_for_events(log)
    h3 = [e for e in events if "http3-transport" in e.get("tags", [])]
    assert h3, "no http3-transport event"
    assert "missing-user-agent" in h3[0]["tags"]        # no UA header
    assert h3[0]["request"]["body_len"] == len(b"payload-bytes")
