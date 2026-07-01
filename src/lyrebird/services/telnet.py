# SPDX-License-Identifier: GPL-3.0-or-later
"""Telnet honeypot.

Plaintext IoT/Mirai-style Telnet: captures brute-force credentials, then — after
a threshold or a weak-credential match — a fake shell that logs commands (reusing
the SSH command emulator) while executing and fetching NOTHING.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..base import BaseService
from .ssh_shell import respond

_IAC = 0xFF


def _int_or(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def strip_iac(data: bytes) -> bytes:
    """Remove Telnet IAC (0xFF) option-negotiation sequences so credentials and
    commands are captured cleanly regardless of client negotiation."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b != _IAC:
            out.append(b)
            i += 1
            continue
        if i + 1 >= n:                         # dangling IAC at a buffer edge
            break
        c = data[i + 1]
        if c == _IAC:                          # escaped 0xFF -> literal 0xFF
            out.append(_IAC)
            i += 2
        elif c in (0xFB, 0xFC, 0xFD, 0xFE):    # WILL/WONT/DO/DONT <opt>
            i += 3
        elif c == 0xFA:                        # SB ... IAC SE
            j = i + 2
            while j + 1 < n and not (data[j] == _IAC and data[j + 1] == 0xF0):
                j += 1
            i = j + 2
        else:                                  # other 2-byte IAC command
            i += 2
    return bytes(out)


class TelnetService(BaseService):
    name = "telnet"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._server: asyncio.AbstractServer | None = None
        # Coerce operator config once here (a bad value must not break capture).
        self.port = _int_or(self.cfg.get("port"), 23)
        self.accept_after = _int_or(self.cfg.get("accept_after"), 3)
        self.bruteforce_threshold = _int_or(self.cfg.get("bruteforce_threshold"), 3)
        weak = self.cfg.get("weak_creds")
        self.weak_creds = ([c for c in weak if isinstance(c, dict)]
                           if isinstance(weak, list) else [])

    async def _readline(self, reader: asyncio.StreamReader) -> str:
        raw = await asyncio.wait_for(reader.readline(), timeout=60)
        if not raw:
            return ""
        return strip_iac(raw).decode("utf-8", "replace").strip("\r\n\x00 ")

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        client = f"{peer[0]}:{peer[1]}"
        attempts = 0
        accepted = False
        try:
            writer.write(str(self.cfg.get("banner", "")).encode())
            await writer.drain()
            while not accepted:
                writer.write(b"login: ")
                await writer.drain()
                user = await self._readline(reader)
                if not user and reader.at_eof():
                    break
                writer.write(b"Password: ")
                await writer.drain()
                password = await self._readline(reader)
                attempts += 1
                accept = (any(user == c.get("user") and password == c.get("password")
                              for c in self.weak_creds)
                          or attempts >= self.accept_after)
                self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                          dst_port=self.port, event_type="auth",
                          summary=f"telnet auth user='{user}' accepted={accept}",
                          request={"user": user, "password": password,
                                   "method": "telnet", "accepted": accept},
                          tags=["credentials"])
                if accept:
                    accepted = True
                else:
                    writer.write(b"\r\nLogin incorrect\r\n")
                    await writer.drain()
                    if reader.at_eof():
                        break
            # Fire the brute-force signal for ANY connection that crossed the
            # threshold — successful or not (a failed credential-list run that
            # hangs up is still the tell), matching the SSH honeypot's
            # per-connection model.
            if attempts >= self.bruteforce_threshold:
                self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                          dst_port=self.port, event_type="request",
                          summary=(f"telnet brute-force {attempts} attempts "
                                   f"client={client} accepted={accepted}"),
                          request={"attempts": attempts, "client": client,
                                   "accepted": accepted},
                          tags=["telnet-bruteforce"])
            if accepted:
                await self._shell(reader, writer, peer)
        except (asyncio.TimeoutError, ConnectionError):
            pass
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _shell(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter, peer) -> None:
        writer.write(b"\r\n# ")
        await writer.drain()
        while True:
            cmd = await self._readline(reader)
            if not cmd:
                if reader.at_eof():
                    break
                writer.write(b"# ")
                await writer.drain()
                continue
            if cmd in ("exit", "logout", "quit"):
                break
            output, pull = respond(cmd)
            writer.write((output + ("\r\n" if not output.endswith("\n") else "")).encode())
            if pull is not None:
                self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                          dst_port=self.port, event_type="request",
                          summary=f"telnet payload-pull {pull['tool']} {pull['url']}",
                          request={"command": cmd, "tool": pull["tool"],
                                   "url": pull["url"]},
                          tags=["telnet-payload-pull"])
            else:
                self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                          dst_port=self.port, event_type="request",
                          summary=f"telnet shell: {cmd}",
                          request={"command": cmd}, tags=[])
            writer.write(b"# ")
            await writer.drain()

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, host=self.bind_address, port=self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
