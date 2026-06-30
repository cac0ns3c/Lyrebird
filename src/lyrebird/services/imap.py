# SPDX-License-Identifier: GPL-3.0-or-later
"""IMAP emulation service. Fake mailbox; logs LOGIN credentials and commands."""

from __future__ import annotations

import asyncio
import time
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
                    # A parked IDLE is the mailbox-as-C2 long-poll pattern. Push an
                    # unsolicited EXISTS to simulate the server delivering tasking,
                    # then record how the wait ended.
                    writer.write(b"+ idling\r\n")
                    await writer.drain()
                    idle_start = time.monotonic()
                    push_delay = float(self.cfg.get("idle_push_delay", 2.0))
                    idle_max = float(self.cfg.get("idle_max", 60))
                    state = {"pushed": False}

                    async def _push() -> None:
                        try:
                            await asyncio.sleep(push_delay)
                            writer.write(b"* 1 EXISTS\r\n")
                            await writer.drain()
                            state["pushed"] = True
                        except Exception:
                            pass  # connection may have closed mid-push

                    push_task = asyncio.create_task(_push())
                    ended = "timeout"
                    try:
                        done = await asyncio.wait_for(reader.readline(), timeout=idle_max)
                        if not done:
                            ended = "closed"
                        elif done.strip().upper() == b"DONE":
                            writer.write(f"{tag} OK IDLE terminated\r\n".encode())
                            ended = "done"
                    except asyncio.TimeoutError:
                        writer.write(f"{tag} OK IDLE timeout\r\n".encode())
                    finally:
                        push_task.cancel()
                        try:
                            await push_task
                        except BaseException:
                            pass
                    idle_seconds = round(time.monotonic() - idle_start, 2)
                    self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                              dst_port=port, event_type="request",
                              summary=f"imap IDLE {ended} after {idle_seconds}s pushed={state['pushed']}",
                              request={"idle_seconds": idle_seconds,
                                       "pushed": state["pushed"], "ended": ended},
                              tags=["imap-idle"])
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
