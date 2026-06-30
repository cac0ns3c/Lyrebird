# SPDX-License-Identifier: GPL-3.0-or-later
"""FTP emulation service.

Emulates an FTP server's control channel and a passive data channel so that a
sample logging in and uploading (STOR) — e.g. exfiltrating collected data or
dropping a secondary file — has its upload captured as an artifact. RETR/LIST
return placeholders. Credentials and commands are logged.

Passive mode only (the common case for clients behind NAT); active-mode PORT is
a documented next addition.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from ..base import BaseService
from ..events import Artifact

_FAKE_LISTING = b"-rw-r--r-- 1 lab lab 0 Jan 01 00:00 readme.txt\r\n"


class _FtpSession:
    def __init__(self, service: "FtpService", reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter) -> None:
        self.svc = service
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername") or ("?", 0)
        self.local_ip = (writer.get_extra_info("sockname") or ("127.0.0.1", 0))[0]
        self.user: Optional[str] = None
        self._data_server: Optional[asyncio.AbstractServer] = None
        self._data_conn: "asyncio.Future[tuple]" = asyncio.get_running_loop().create_future()
        self.active_addr: Optional[tuple[str, int]] = None   # set by PORT (active mode)

    def reply(self, line: str) -> None:
        self.writer.write((line + "\r\n").encode("utf-8", "replace"))

    async def get_data_streams(self) -> tuple:
        """Return (reader, writer) for the data channel in whichever mode the
        client negotiated: active (we dial back to the PORT address) or passive
        (we accept the connection on the port we advertised)."""
        if self.active_addr is not None:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(*self.active_addr), timeout=15)
            self.active_addr = None
            return r, w
        return await asyncio.wait_for(self._data_conn, timeout=15)

    async def open_passive(self) -> int:
        # reset the future for a fresh transfer
        loop = asyncio.get_running_loop()
        self._data_conn = loop.create_future()

        def on_conn(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            if not self._data_conn.done():
                self._data_conn.set_result((r, w))

        self._data_server = await asyncio.start_server(
            on_conn, host=self.svc.bind_address, port=0)
        port = self._data_server.sockets[0].getsockname()[1]
        return port

    async def close_data(self) -> None:
        if self._data_server:
            self._data_server.close()
            try:
                await self._data_server.wait_closed()
            except Exception:
                pass
            self._data_server = None

    async def run(self) -> None:
        port = int(self.svc.cfg.get("port", 21))
        self.reply("220 Lab FTP ready")
        await self.writer.drain()
        try:
            while True:
                raw = await asyncio.wait_for(self.reader.readline(), timeout=60)
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").strip()
                cmd, _, arg = line.partition(" ")
                cmd = cmd.upper()

                if cmd == "USER":
                    self.user = arg
                    self.reply("331 password required")
                elif cmd == "PASS":
                    self.svc.emit(
                        transport="tcp", src_ip=self.peer[0], src_port=self.peer[1],
                        dst_port=port, event_type="auth",
                        summary=f"ftp login user='{self.user}'",
                        request={"user": self.user, "pass_len": len(arg)},
                        response={"status": "230"}, tags=["credentials"])
                    self.reply("230 logged in")
                elif cmd == "SYST":
                    self.reply("215 UNIX Type: L8")
                elif cmd in ("PWD", "XPWD"):
                    self.reply('257 "/" is current directory')
                elif cmd == "TYPE":
                    self.reply("200 type set")
                elif cmd == "CWD":
                    self.reply("250 ok")
                elif cmd == "PASV":
                    dport = await self.open_passive()
                    h = self.local_ip.replace(".", ",")
                    p1, p2 = dport >> 8, dport & 0xFF
                    self.reply(f"227 Entering Passive Mode ({h},{p1},{p2})")
                elif cmd == "EPSV":
                    dport = await self.open_passive()
                    self.reply(f"229 Entering Extended Passive Mode (|||{dport}|)")
                elif cmd == "PORT":
                    # active mode: client gives h1,h2,h3,h4,p1,p2 to dial back to
                    try:
                        nums = [int(x) for x in arg.split(",")]
                        ip = ".".join(str(n) for n in nums[:4])
                        dport = (nums[4] << 8) + nums[5]
                        self.active_addr = (ip, dport)
                        self.reply("200 PORT command successful")
                    except (ValueError, IndexError):
                        self.reply("501 bad PORT")
                elif cmd == "EPRT":
                    # extended active: |proto|addr|port|
                    try:
                        fields = arg.split("|")
                        self.active_addr = (fields[2], int(fields[3]))
                        self.reply("200 EPRT command successful")
                    except (ValueError, IndexError):
                        self.reply("501 bad EPRT")
                elif cmd == "STOR":
                    self.reply("150 ok to send")
                    await self.writer.drain()
                    try:
                        r, w = await self.get_data_streams()
                        blob = await asyncio.wait_for(r.read(10_000_000), timeout=30)
                        art = Artifact.from_bytes("ftp-upload", blob, self.svc.capture_dir,
                                                  note=f"STOR {arg}")
                        self.svc.emit(
                            transport="tcp", src_ip=self.peer[0], src_port=self.peer[1],
                            dst_port=port, event_type="capture",
                            summary=f"ftp STOR {arg} ({len(blob)} bytes)",
                            request={"cmd": "STOR", "filename": arg, "size": len(blob)},
                            artifacts=[art], tags=["upload"])
                        w.close()
                        self.reply("226 transfer complete")
                    except Exception:
                        self.reply("426 transfer failed")
                    finally:
                        await self.close_data()
                elif cmd == "RETR":
                    self.reply("150 opening data connection")
                    await self.writer.drain()
                    try:
                        r, w = await self.get_data_streams()
                        w.write(b"")          # placeholder: empty file
                        await w.drain()
                        w.close()
                        self.reply("226 transfer complete")
                    except Exception:
                        self.reply("426 transfer failed")
                    finally:
                        await self.close_data()
                elif cmd in ("LIST", "NLST"):
                    self.reply("150 here comes the listing")
                    await self.writer.drain()
                    try:
                        r, w = await self.get_data_streams()
                        w.write(_FAKE_LISTING)
                        await w.drain()
                        w.close()
                        self.reply("226 directory sent")
                    except Exception:
                        self.reply("426 failed")
                    finally:
                        await self.close_data()
                elif cmd == "QUIT":
                    self.reply("221 bye")
                    await self.writer.drain()
                    break
                else:
                    self.reply("200 ok")
                await self.writer.drain()
        except (asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            await self.close_data()
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass


class FtpService(BaseService):
    name = "ftp"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _FtpSession(self, reader, writer).run()

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, host=self.bind_address, port=int(self.cfg.get("port", 21)))

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass