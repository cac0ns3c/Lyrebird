# SPDX-License-Identifier: GPL-3.0-or-later
"""SMTP emulation service.

Accepts mail from anything that connects, captures the full message as an
artifact, and logs envelope details. Mass-mailer malware and exfil-over-email
reveal their recipient lists and payloads here.

Built on aiosmtpd's Controller.
"""

from __future__ import annotations

import asyncio
from typing import Any

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope, Session, SMTP

from ..base import BaseService
from ..events import Artifact


class _Handler:
    def __init__(self, service: "SmtpService") -> None:
        self.service = service

    async def handle_RCPT(self, server: SMTP, session: Session, envelope: Envelope,
                          address: str, rcpt_options: list) -> str:
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope) -> str:
        raw = envelope.content if isinstance(envelope.content, bytes) else \
            (envelope.content or "").encode("utf-8", "replace")
        artifact = Artifact.from_bytes("mail", raw, self.service.capture_dir,
                                       note=f"from={envelope.mail_from}")
        peer = session.peer or ("?", 0)
        tags = []
        if len(envelope.rcpt_tos) > 5:
            tags.append("bulk-recipients")

        self.service.emit(
            transport="tcp",
            src_ip=peer[0],
            src_port=peer[1],
            dst_port=int(self.service.cfg.get("port", 25)),
            event_type="capture",
            summary=f"mail from={envelope.mail_from} -> {len(envelope.rcpt_tos)} rcpt(s)",
            request={
                "mail_from": envelope.mail_from,
                "rcpt_tos": envelope.rcpt_tos,
                "size": len(raw),
            },
            response={"status": "250 accepted"},
            artifacts=[artifact],
            tags=tags,
        )
        return "250 Message accepted for delivery"


class SmtpService(BaseService):
    name = "smtp"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._controller: Controller | None = None

    async def start(self) -> None:
        port = int(self.cfg.get("port", 25))
        self._controller = Controller(
            _Handler(self), hostname=self.bind_address, port=port)
        # Controller.start spins up its own loop thread; run it off the event loop.
        await asyncio.get_running_loop().run_in_executor(None, self._controller.start)

    async def stop(self) -> None:
        if self._controller:
            await asyncio.get_running_loop().run_in_executor(None, self._controller.stop)