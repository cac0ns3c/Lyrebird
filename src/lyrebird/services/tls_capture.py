# SPDX-License-Identifier: GPL-3.0-or-later
"""TLS fingerprinting capture service.

A passive tap: it reads the ClientHello a sample sends, computes JA3/JA4 and pulls
the SNI, emits an event, then closes the connection. It does **not** terminate
TLS or serve content — that's the HTTP service's job. Run this when you want
client fingerprints (e.g. to match malware against JA3/JA4 threat intel) instead
of full HTTPS content emulation on a given port.

Trade-off: because it captures the hello and closes, the sample's TLS connection
won't complete here. Point fingerprinting traffic at this port, or use the HTTP
TLS terminator (port 443) for content emulation — not both on the same port.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..base import BaseService
from ..tls import fingerprint, fp_event_fields


class TlsCaptureService(BaseService):
    name = "tls_capture"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        port = int(self.cfg.get("port", 8443))
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=5)
        except (asyncio.TimeoutError, ConnectionError):
            data = b""

        fp = fingerprint(data) if data else None
        if fp:
            tags = ["tls", "fingerprint"]
            if fp.get("no_grease_signal"):
                tags.append("no-grease")
            self.emit(
                transport="tcp", src_ip=peer[0], src_port=peer[1], dst_port=port,
                event_type="request",
                summary=f"tls hello ja4={fp['ja4']} sni={fp.get('sni')}",
                request={"sni": fp.get("sni"), "alpn": fp.get("alpn"),
                         "ja3": fp["ja3"], "ja4": fp["ja4"],
                         "cipher_count": fp["cipher_count"],
                         **fp_event_fields(fp)},
                tags=tags)
        else:
            self.emit(
                transport="tcp", src_ip=peer[0], src_port=peer[1], dst_port=port,
                event_type="request", summary="tls hello (unparsed)",
                request={"bytes": len(data)}, tags=["tls"])

        # Send a TLS "handshake_failure" alert, then close.
        try:
            writer.write(b"\x15\x03\x03\x00\x02\x02\x28")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, host=self.bind_address, port=int(self.cfg.get("port", 8443)))

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
