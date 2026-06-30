# SPDX-License-Identifier: GPL-3.0-or-later
"""IMAP emulation service. Fake mailbox; logs LOGIN credentials and commands."""

from __future__ import annotations

import asyncio
from typing import Any

from ..base import BaseService


class ImapService(BaseService):
    name = "imap"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        port = int(self.cfg.get("port", 143))
        writer.write(b"* OK Lab IMAP ready\r\n")
        await writer.drain()
        try:
            while True:
                raw = await asyncio.wait_for(reader.readline(), timeout=30)
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").strip()
                tag, _, rest = line.partition(" ")
                cmd, _, arg = rest.partition(" ")
                cmd = cmd.upper()

                if cmd == "LOGIN":
                    user = arg.split(" ")[0].strip('"') if arg else ""
                    self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                              dst_port=port, event_type="auth",
                              summary=f"imap LOGIN user='{user}'",
                              request={"user": user}, tags=["credentials"])
                    writer.write(f"{tag} OK LOGIN completed\r\n".encode())
                elif cmd == "CAPABILITY":
                    writer.write(b"* CAPABILITY IMAP4rev1\r\n")
                    writer.write(f"{tag} OK\r\n".encode())
                elif cmd == "SELECT":
                    writer.write(b"* 0 EXISTS\r\n")
                    writer.write(f"{tag} OK [READ-WRITE] SELECT completed\r\n".encode())
                elif cmd == "IDLE":
                    writer.write(b"+ idling\r\n")
                    await writer.drain()
                    # wait for DONE (clients hold IDLE open for push); log the wait
                    try:
                        done = await asyncio.wait_for(reader.readline(), timeout=60)
                        if done.strip().upper() == b"DONE":
                            writer.write(f"{tag} OK IDLE terminated\r\n".encode())
                    except asyncio.TimeoutError:
                        writer.write(f"{tag} OK IDLE timeout\r\n".encode())
                elif cmd == "LOGOUT":
                    writer.write(b"* BYE\r\n")
                    writer.write(f"{tag} OK LOGOUT completed\r\n".encode())
                    await writer.drain()
                    break
                else:
                    writer.write(f"{tag} OK\r\n".encode())
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            try:
                writer.close(); await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, host=self.bind_address, port=int(self.cfg.get("port", 143)))

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
