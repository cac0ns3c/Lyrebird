# SPDX-License-Identifier: GPL-3.0-or-later
"""QUIC / HTTP-3 emulation service.

Malware uses HTTP/3 (QUIC over UDP) for C2 because it evades most TCP/TLS network
inspection. This service terminates QUIC with a lab cert, speaks HTTP/3, captures
each request, and answers benignly — so the sample keeps talking. It executes and
fetches nothing.
"""
from __future__ import annotations

from typing import Any

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated

from ..base import BaseService
from ..certs import LabCA


class _H3Protocol(QuicConnectionProtocol):
    def __init__(self, *args: Any, service: "QuicService", **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._service = service
        self._http: H3Connection | None = None
        self._hdr: dict[int, list[tuple[str, str]]] = {}
        self._body: dict[int, bytearray] = {}
        self._peer: tuple[str, int] = ("?", 0)

    def datagram_received(self, data: bytes, addr) -> None:
        self._peer = addr
        super().datagram_received(data, addr)

    def quic_event_received(self, event) -> None:
        if isinstance(event, ProtocolNegotiated) and event.alpn_protocol == "h3":
            self._http = H3Connection(self._quic)
        if self._http is None:
            return
        for h3_event in self._http.handle_event(event):
            if isinstance(h3_event, HeadersReceived):
                self._hdr[h3_event.stream_id] = [
                    (k.decode("utf-8", "replace"), v.decode("utf-8", "replace"))
                    for k, v in h3_event.headers]
                self._body.setdefault(h3_event.stream_id, bytearray())
                if h3_event.stream_ended:
                    self._finish(h3_event.stream_id)
            elif isinstance(h3_event, DataReceived):
                self._body.setdefault(h3_event.stream_id, bytearray()).extend(
                    h3_event.data)
                if h3_event.stream_ended:
                    self._finish(h3_event.stream_id)

    def _finish(self, stream_id: int) -> None:
        headers = self._hdr.pop(stream_id, [])
        body = bytes(self._body.pop(stream_id, b""))
        try:
            self._service.on_request(self._peer, headers, body)
        except Exception:
            pass
        if self._http is not None:
            self._http.send_headers(
                stream_id,
                [(b":status", b"200"), (b"content-type", b"text/plain")])
            self._http.send_data(stream_id, self._service.body, end_stream=True)
            self.transmit()


class QuicService(BaseService):
    name = "quic"

    def __init__(self, *args: Any, ca: LabCA | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._server: Any = None
        # QUIC always needs TLS, so be self-sufficient if the orchestrator has no CA.
        self.ca = ca or LabCA(self.tls.get("ca_dir", self.data_dir / "ca"))
        self.port = int(self.cfg.get("port", 443))
        self.body = str(self.cfg.get("body", "OK")).encode()

    def on_request(self, peer, headers: list[tuple[str, str]], body: bytes) -> None:
        h = dict(headers)
        method = h.get(":method", "")
        authority = h.get(":authority", "")
        path = h.get(":path", "")
        ua = h.get("user-agent")
        tags = ["quic", "http3-transport"]
        if not ua:
            tags.append("missing-user-agent")
        req: dict[str, Any] = {
            "method": method, "authority": authority, "path": path,
            "scheme": h.get(":scheme", ""), "user_agent": ua,
            "headers": h, "body_len": len(body),
        }
        if body:
            try:
                self.capture_dir.mkdir(parents=True, exist_ok=True)
                dest = self.capture_dir / f"h3-{peer[1]}-{len(body)}.bin"
                dest.write_bytes(body)
                req["body_path"] = str(dest)
            except Exception:
                pass
        self.emit(transport="quic", src_ip=peer[0], src_port=peer[1],
                  dst_port=self.port, event_type="request",
                  summary=f"h3 {method} {authority}{path}",
                  request=req, tags=tags)

    async def start(self) -> None:
        config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
        cert, key = self.ca.leaf("lab.local")
        config.load_cert_chain(str(cert), str(key))
        self._server = await serve(
            self.bind_address, self.port, configuration=config,
            create_protocol=lambda *a, **k: _H3Protocol(*a, service=self, **k))

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
