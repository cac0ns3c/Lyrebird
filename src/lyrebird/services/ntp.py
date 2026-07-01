# SPDX-License-Identifier: GPL-3.0-or-later
"""NTP emulation service.

Some malware checks the time before detonating (or to evade analysis). This
service answers NTP requests and supports a configurable ``faketime_delta`` so
the lab clock can be shifted forward/back to coax time-gated behaviour, mirroring
INetSim's faketime feature.
"""

from __future__ import annotations

import asyncio
import struct
import time
from typing import Any

from ..base import BaseService

# Seconds between 1900-01-01 (NTP epoch) and 1970-01-01 (Unix epoch).
NTP_DELTA = 2208988800

# A fixed, deliberately tiny reply to a control/private (mode 6/7) probe. Capped
# to the request length at send time so the emulator NEVER amplifies — it can be
# a reflection TARGET in a lab but must not become a reflector.
_CONTROL_REPLY = b"\x00\x00\x00\x00"


def parse_mode(data: bytes) -> "tuple[int | None, int | None]":
    """Return (mode, request_code) for an NTP request. mode = low 3 bits of the
    first byte; request_code is the mode-7 opcode (data[3], e.g. 42 = MONLIST) or
    the mode-6 control opcode (data[1] & 0x1F). Both None for a too-short/empty
    packet."""
    if not data:
        return None, None
    mode = data[0] & 0x07
    if mode == 7:
        return mode, (data[3] if len(data) > 3 else None)
    if mode == 6:
        return mode, (data[1] & 0x1F if len(data) > 1 else None)
    return mode, None


class _NtpProtocol(asyncio.DatagramProtocol):
    def __init__(self, service: "NtpService") -> None:
        self.service = service
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        reply = self.service.handle_datagram(data, addr)
        if self.transport and reply is not None:
            self.transport.sendto(reply, addr)


class NtpService(BaseService):
    name = "ntp"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._transport: asyncio.BaseTransport | None = None
        self.delta = int(self.cfg.get("faketime_delta", 0))

    def handle_datagram(self, data: bytes, addr: tuple[str, int]) -> "bytes | None":
        mode, req_code = parse_mode(data)
        if mode in (6, 7):
            note = f" (request_code={req_code})" if req_code is not None else ""
            self.emit(
                transport="udp", src_ip=addr[0], src_port=addr[1],
                dst_port=int(self.cfg.get("port", 123)), event_type="request",
                summary=f"ntp mode-{mode} control query{note}",
                request={"mode": mode, "request_code": req_code},
                tags=["ntp-control-query"])
            # never amplify: reply is fixed and capped at the request length
            return _CONTROL_REPLY[:len(data)]
        return self.build_reply(addr)

    def build_reply(self, addr: tuple[str, int]) -> bytes:
        now = time.time() + self.delta + NTP_DELTA
        secs = int(now)
        frac = int((now - secs) * (2 ** 32))

        # LI=0, VN=4, Mode=4 (server); stratum 2; poll 4; precision -20
        li_vn_mode = (0 << 6) | (4 << 3) | 4
        packet = struct.pack(
            "!B B B b 11I",
            li_vn_mode, 2, 4, -20,
            0, 0, 0,                      # root delay, root dispersion, ref id
            secs, frac,                   # reference timestamp
            0, 0,                         # originate timestamp
            secs, frac,                   # receive timestamp
            secs, frac,                   # transmit timestamp (last two ints)
        )

        self.emit(
            transport="udp",
            src_ip=addr[0],
            src_port=addr[1],
            dst_port=int(self.cfg.get("port", 123)),
            event_type="request",
            summary=f"ntp time query (delta={self.delta}s)",
            request={"proto": "ntp"},
            response={"unix_time": secs - NTP_DELTA, "faketime_delta": self.delta},
            tags=["faketime"] if self.delta else [],
        )
        return packet

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        port = int(self.cfg.get("port", 123))
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _NtpProtocol(self),
            local_addr=(self.bind_address, port),
        )

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()