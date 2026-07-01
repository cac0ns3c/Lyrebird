# SPDX-License-Identifier: GPL-3.0-or-later
"""SSH honeypot.

Completes a real SSH key exchange (via asyncssh), captures every brute-force
credential attempt, and — after a threshold or a weak-credential match — grants
a fake shell that logs commands while executing and fetching NOTHING.
"""

from __future__ import annotations

import os
from typing import Any

import asyncssh

from ..base import BaseService
from .ssh_shell import respond


def _int_or(value: Any, default: int) -> int:
    """Coerce operator config to int, falling back on bad/missing values."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class _ConnHandler(asyncssh.SSHServer):
    """Per-connection auth handler. Logs each attempt; Task 2 adds acceptance."""

    def __init__(self, service: "SshService") -> None:
        self.service = service
        self.attempts = 0
        self.accepted = False
        self.client_version = ""
        self.peer = ("?", 0)
        self._conn: asyncssh.SSHServerConnection | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        self.peer = conn.get_extra_info("peername") or ("?", 0)

    def begin_auth(self, username: str) -> bool:
        # client_version is only populated after the banner exchange
        self.client_version = (self._conn.get_extra_info("client_version")
                               if self._conn else "") or ""
        return True  # always require auth

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        self.attempts += 1
        svc = self.service
        accept = (any(username == c.get("user") and password == c.get("password")
                      for c in svc.weak_creds)
                  or self.attempts >= svc.accept_after)
        if accept:
            self.accepted = True
        svc.emit(
            transport="tcp", src_ip=self.peer[0], src_port=self.peer[1],
            dst_port=svc.port, event_type="auth",
            summary=f"ssh auth user='{username}' accepted={accept}",
            request={"user": username, "password": password,
                     "method": "password", "accepted": accept},
            tags=["credentials"])
        return accept

    def connection_lost(self, exc: Exception | None) -> None:
        if self.attempts >= self.service.bruteforce_threshold:
            self.service.emit(
                transport="tcp", src_ip=self.peer[0], src_port=self.peer[1],
                dst_port=self.service.port, event_type="request",
                summary=(f"ssh brute-force {self.attempts} attempts "
                         f"client='{self.client_version}' accepted={self.accepted}"),
                request={"attempts": self.attempts,
                         "client_version": self.client_version,
                         "accepted": self.accepted},
                tags=["ssh-bruteforce"])


class SshService(BaseService):
    name = "ssh"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._server: asyncssh.SSHAcceptor | None = None
        # Coerce operator config ONCE here — not inside the asyncssh auth
        # callback, where a bad value (e.g. `accept_after: three`) would raise
        # and silently break credential logging for the whole run.
        self.port = _int_or(self.cfg.get("port"), 22)
        self.accept_after = _int_or(self.cfg.get("accept_after"), 3)
        self.bruteforce_threshold = _int_or(self.cfg.get("bruteforce_threshold"), 3)
        weak = self.cfg.get("weak_creds")
        self.weak_creds = [c for c in weak if isinstance(c, dict)] if isinstance(weak, list) else []

    def _host_key(self) -> asyncssh.SSHKey:
        key_dir = self.data_dir / "ssh"
        key_dir.mkdir(parents=True, exist_ok=True)
        key_path = key_dir / "host_key"
        if key_path.exists():
            return asyncssh.read_private_key(str(key_path))
        key = asyncssh.generate_private_key("ssh-ed25519")
        key.write_private_key(str(key_path))
        os.chmod(str(key_path), 0o600)
        return key

    async def start(self) -> None:
        banner = str(self.cfg.get("banner", "SSH-2.0-OpenSSH_8.9p1"))
        version = banner.split("SSH-2.0-", 1)[-1]  # asyncssh re-adds the prefix
        self._server = await asyncssh.create_server(
            lambda: _ConnHandler(self), host=self.bind_address, port=self.port,
            server_host_keys=[self._host_key()], server_version=version,
            process_factory=self._handle_shell, agent_forwarding=False)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass

    async def _handle_shell(self, process: asyncssh.SSHServerProcess) -> None:
        peer = process.get_extra_info("peername") or ("?", 0)
        if process.subsystem:
            # A subsystem request (sftp/netconf/…) is not an interactive shell;
            # log the attempt and close rather than feeding binary framing into
            # the text command loop.
            self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                      dst_port=self.port, event_type="request",
                      summary=f"ssh subsystem request: {process.subsystem}",
                      request={"subsystem": process.subsystem}, tags=[])
            try:
                process.exit(0)
            except Exception:
                pass
            return
        try:
            if process.command is not None:
                self._run_command(process.command, peer, process)
            else:
                process.stdout.write("$ ")
                while True:
                    try:
                        line = await process.stdin.readline()
                    except (asyncssh.TerminalSizeChanged, asyncssh.BreakReceived,
                            asyncssh.SignalReceived):
                        # asyncssh delivers channel control notifications (a
                        # terminal resize, ^C, etc.) as exceptions on the next
                        # read — they are not shell input; keep the session open.
                        continue
                    if not line:
                        break  # real EOF / channel closed
                    cmd = line.strip()
                    if not cmd:
                        process.stdout.write("$ ")
                        continue
                    if cmd in ("exit", "logout", "quit"):
                        break
                    self._run_command(cmd, peer, process)
                    process.stdout.write("$ ")
        except Exception:
            pass  # a dropped session must not escape the handler
        finally:
            try:
                process.exit(0)
            except Exception:
                pass

    def _run_command(self, cmd: str, peer, process: asyncssh.SSHServerProcess) -> None:
        output, pull = respond(cmd)
        process.stdout.write(output + ("\n" if not output.endswith("\n") else ""))
        if pull is not None:
            self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                      dst_port=self.port, event_type="request",
                      summary=f"ssh payload-pull {pull['tool']} {pull['url']}",
                      request={"command": cmd, "tool": pull["tool"], "url": pull["url"]},
                      tags=["ssh-payload-pull"])
        else:
            self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                      dst_port=self.port, event_type="request",
                      summary=f"ssh shell: {cmd}",
                      request={"command": cmd}, tags=[])
