# SPDX-License-Identifier: GPL-3.0-or-later
"""POP3 emulation service.

Serves a fake mailbox so a sample that checks mail (or abuses POP3 as a C2 / data
channel) proceeds and reveals itself. Captured credentials and commands are
logged; RETR returns a placeholder message.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..base import BaseService

_FAKE_MSG = (
    b"From: postmaster@lab.local\r\n"
    b"Subject: Mailbox notice\r\n"
    b"\r\n"
    b"This mailbox is served by a lab emulator.\r\n.\r\n"
)


class Pop3Service(BaseService):
    name = "pop3"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        user = {"name": None}
        writer.write(b"+OK Lab POP3 ready\r\n")
        await writer.drain()
        try:
            while True:
                raw = await asyncio.wait_for(reader.readline(), timeout=30)
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").strip()
                cmd, _, arg = line.partition(" ")
                cmd = cmd.upper()

                if cmd == "USER":
                    user["name"] = arg
                    writer.write(b"+OK\r\n")
                elif cmd == "PASS":
                    self.emit(
                        transport="tcp", src_ip=peer[0], src_port=peer[1],
                        dst_port=int(self.cfg.get("port", 110)),
                        event_type="auth",
                        summary=f"pop3 login user='{user['name']}'",
                        request={"user": user["name"], "pass_len": len(arg)},
                        response={"status": "+OK"}, tags=["credentials"],
                    )
                    writer.write(b"+OK logged in\r\n")
                elif cmd == "STAT":
                    writer.write(b"+OK 1 %d\r\n" % len(_FAKE_MSG))
                elif cmd == "LIST":
                    writer.write(b"+OK 1 messages\r\n1 %d\r\n.\r\n" % len(_FAKE_MSG))
                elif cmd == "RETR":
                    writer.write(b"+OK %d octets\r\n" % len(_FAKE_MSG) + _FAKE_MSG)
                elif cmd in ("DELE", "NOOP", "RSET"):
                    writer.write(b"+OK\r\n")
                elif cmd == "QUIT":
                    writer.write(b"+OK bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"-ERR unknown command\r\n")
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, host=self.bind_address, port=int(self.cfg.get("port", 110)))

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass