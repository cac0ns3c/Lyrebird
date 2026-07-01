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
        cfg = self.service.cfg
        weak = cfg.get("weak_creds") or []
        accept_after = int(cfg.get("accept_after", 3))
        accept = (any(username == c.get("user") and password == c.get("password")
                      for c in weak)
                  or self.attempts >= accept_after)
        if accept:
            self.accepted = True
        self.service.emit(
            transport="tcp", src_ip=self.peer[0], src_port=self.peer[1],
            dst_port=self.service.port, event_type="auth",
            summary=f"ssh auth user='{username}' accepted={accept}",
            request={"user": username, "password": password,
                     "method": "password", "accepted": accept},
            tags=["credentials"])
        return accept

    def connection_lost(self, exc: Exception | None) -> None:
        threshold = int(self.service.cfg.get("bruteforce_threshold", 3))
        if self.attempts >= threshold:
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
        self.port = int(self.cfg.get("port", 22))

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
            server_host_keys=[self._host_key()], server_version=version)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
