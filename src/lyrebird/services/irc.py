# SPDX-License-Identifier: GPL-3.0-or-later
"""IRC emulation service.

IRC is a classic botnet command channel. This emulator completes the handshake,
acknowledges JOINs, and logs everything the bot says — the nick it picks, the
channels it joins, and the PRIVMSG traffic — which is exactly the C2 behaviour an
analyst wants to observe. It never issues commands of its own; it only mirrors
the protocol and records.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..base import BaseService

SERVER = "lab.irc.local"


class IrcService(BaseService):
    name = "irc"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        port = int(self.cfg.get("port", 6667))
        nick = {"value": "*"}

        def send(line: str) -> None:
            writer.write((line + "\r\n").encode("utf-8", "replace"))

        try:
            while True:
                raw = await asyncio.wait_for(reader.readline(), timeout=120)
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if not line:
                    continue
                cmd, _, rest = line.partition(" ")
                cmd = cmd.upper()

                if cmd == "NICK":
                    nick["value"] = rest.strip() or "*"
                    self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                              dst_port=port, event_type="request",
                              summary=f"irc NICK {nick['value']}",
                              request={"cmd": "NICK", "nick": nick["value"]}, tags=["irc"])
                elif cmd == "USER":
                    # Registration complete -> send the welcome burst.
                    n = nick["value"]
                    send(f":{SERVER} 001 {n} :Welcome")
                    send(f":{SERVER} 004 {n} {SERVER} lab 0 0")
                elif cmd == "PING":
                    send(f":{SERVER} PONG {SERVER} :{rest.lstrip(':')}")
                elif cmd == "JOIN":
                    channel = rest.split()[0] if rest else "#unknown"
                    send(f":{nick['value']} JOIN {channel}")
                    send(f":{SERVER} 366 {nick['value']} {channel} :End of /NAMES")
                    self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                              dst_port=port, event_type="request",
                              summary=f"irc JOIN {channel}",
                              request={"cmd": "JOIN", "channel": channel},
                              tags=["irc", "channel-join"])
                elif cmd == "PRIVMSG":
                    target, _, msg = rest.partition(" ")
                    self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                              dst_port=port, event_type="request",
                              summary=f"irc PRIVMSG {target}: {msg.lstrip(':')[:80]}",
                              request={"cmd": "PRIVMSG", "target": target,
                                       "message": msg.lstrip(":")},
                              tags=["irc", "privmsg"])
                elif cmd == "QUIT":
                    send("ERROR :bye")
                    await writer.drain()
                    break
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
            self._handle, host=self.bind_address, port=int(self.cfg.get("port", 6667)))

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass