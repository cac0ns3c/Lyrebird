# SPDX-License-Identifier: GPL-3.0-or-later
"""TFTP emulation service.

TFTP shows up in IoT/embedded malware and some droppers. This emulator captures
WRQ (write/upload) transfers as artifacts and answers RRQ (read) with a small
placeholder. Per the protocol, each transfer is handled on its own ephemeral
port (TID); the well-known port 69 only receives the initial request.
"""

from __future__ import annotations

import asyncio
import struct
from typing import Any

from ..base import BaseService
from ..events import Artifact

OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR = 1, 2, 3, 4, 5
BLOCK = 512


def _parse_request(data: bytes) -> tuple[int, str, str]:
    opcode = struct.unpack("!H", data[:2])[0]
    parts = data[2:].split(b"\x00")
    filename = parts[0].decode("utf-8", "replace") if len(parts) > 0 else ""
    mode = parts[1].decode("utf-8", "replace") if len(parts) > 1 else ""
    return opcode, filename, mode


class _TransferProtocol(asyncio.DatagramProtocol):
    """Handles a single transfer on its own ephemeral port."""

    def __init__(self, service: "TftpService", opcode: int, filename: str,
                 client: tuple[str, int]) -> None:
        self.svc = service
        self.opcode = opcode
        self.filename = filename
        self.client = client
        self.transport: asyncio.DatagramTransport | None = None
        self.chunks: list[bytes] = []
        self.expected_block = 1 if opcode == OP_WRQ else 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        if self.opcode == OP_WRQ:
            # ACK block 0 to start receiving DATA
            self.transport.sendto(struct.pack("!HH", OP_ACK, 0), self.client)
        else:  # RRQ -> send one placeholder DATA block then finish
            self.transport.sendto(struct.pack("!HH", OP_DATA, 1) + b"lab\n", self.client)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) < 4:
            return
        opcode, block = struct.unpack("!HH", data[:4])
        if opcode == OP_DATA and self.opcode == OP_WRQ:
            payload = data[4:]
            self.chunks.append(payload)
            self.transport.sendto(struct.pack("!HH", OP_ACK, block), addr)  # type: ignore[union-attr]
            if len(payload) < BLOCK:          # final block
                self._finish_upload()
        elif opcode == OP_ACK and self.opcode == OP_RRQ:
            self._finish_download()

    def _finish_upload(self) -> None:
        blob = b"".join(self.chunks)
        art = Artifact.from_bytes("tftp-upload", blob, self.svc.capture_dir,
                                  note=f"WRQ {self.filename}")
        self.svc.emit(
            transport="udp", src_ip=self.client[0], src_port=self.client[1],
            dst_port=int(self.svc.cfg.get("port", 69)), event_type="capture",
            summary=f"tftp WRQ {self.filename} ({len(blob)} bytes)",
            request={"op": "WRQ", "filename": self.filename, "size": len(blob)},
            artifacts=[art], tags=["upload"])
        self._close()

    def _finish_download(self) -> None:
        self.svc.emit(
            transport="udp", src_ip=self.client[0], src_port=self.client[1],
            dst_port=int(self.svc.cfg.get("port", 69)), event_type="request",
            summary=f"tftp RRQ {self.filename}",
            request={"op": "RRQ", "filename": self.filename}, tags=["tftp"])
        self._close()

    def _close(self) -> None:
        if self.transport:
            self.transport.close()


class _MainProtocol(asyncio.DatagramProtocol):
    def __init__(self, service: "TftpService") -> None:
        self.svc = service
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) < 2:
            return
        opcode, filename, _mode = _parse_request(data)
        if opcode not in (OP_RRQ, OP_WRQ):
            return
        # Spin up a dedicated endpoint (new TID) for this transfer.
        asyncio.ensure_future(self._spawn(opcode, filename, addr))

    async def _spawn(self, opcode: int, filename: str, addr: tuple[str, int]) -> None:
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(
            lambda: _TransferProtocol(self.svc, opcode, filename, addr),
            local_addr=(self.svc.bind_address, 0))


class TftpService(BaseService):
    name = "tftp"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._transport: asyncio.BaseTransport | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _MainProtocol(self),
            local_addr=(self.bind_address, int(self.cfg.get("port", 69))))

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()