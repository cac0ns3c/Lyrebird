# SPDX-License-Identifier: GPL-3.0-or-later
"""Generic TCP sink.

Binds a list of extra ports and logs everything sent to them. This is the
catch-all that captures traffic to services we don't model in depth yet
(IRC, POP3, custom C2 ports, etc.) — the equivalent of INetSim's Dummy module.
Whatever bytes arrive get stored as an artifact for later analysis.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..base import BaseService
from ..events import Artifact


class TcpSinkService(BaseService):
    name = "tcp_sink"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._servers: list[asyncio.AbstractServer] = []
        self.ports: list[int] = list(self.cfg.get("ports", []))

    def _make_handler(self, port: int):
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peer = writer.get_extra_info("peername") or ("?", 0)
            chunks: list[bytes] = []
            try:
                # Read whatever the client sends, with a short idle timeout so we
                # don't hang on connections that wait for a server greeting.
                while True:
                    data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                    if not data:
                        break
                    chunks.append(data)
                    if sum(len(c) for c in chunks) > 1_000_000:
                        break
            except (asyncio.TimeoutError, ConnectionError):
                pass

            blob = b"".join(chunks)
            artifacts = []
            if blob:
                artifacts.append(Artifact.from_bytes("sink", blob, self.capture_dir,
                                                      note=f"port={port}"))
            self.emit(
                transport="tcp",
                src_ip=peer[0],
                src_port=peer[1],
                dst_port=port,
                event_type="capture",
                summary=f"sink port {port}: {len(blob)} bytes",
                request={"port": port, "bytes": len(blob),
                         "preview": blob[:64].hex()},
                artifacts=artifacts,
                tags=["sink"],
            )
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        return handle

    async def start(self) -> None:
        for port in self.ports:
            server = await asyncio.start_server(
                self._make_handler(port), host=self.bind_address, port=port)
            self._servers.append(server)

    async def stop(self) -> None:
        for s in self._servers:
            s.close()
            try:
                await s.wait_closed()
            except Exception:
                pass