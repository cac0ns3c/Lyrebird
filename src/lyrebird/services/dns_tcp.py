# SPDX-License-Identifier: GPL-3.0-or-later
"""DNS-over-TCP emulation service.

The TCP transport for DNS (2-byte length prefix + message), used for large
responses and sometimes for tunnelling. Sinkholes every query like the UDP DNS
service.
"""

from __future__ import annotations

import asyncio
import struct
from typing import Any

from dnslib import RR, QTYPE, A, AAAA, TXT, DNSRecord, DNSHeader

from ..base import BaseService


class DnsTcpService(BaseService):
    name = "dns_tcp"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._server: asyncio.AbstractServer | None = None
        self.default_a = self.cfg.get("default_a", "10.13.37.1")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        port = int(self.cfg.get("port", 53))
        try:
            hdr = await asyncio.wait_for(reader.readexactly(2), timeout=10)
            (mlen,) = struct.unpack("!H", hdr)
            msg = await asyncio.wait_for(reader.readexactly(mlen), timeout=10)
            req = DNSRecord.parse(msg)
            qname = str(req.q.qname); qtype = QTYPE[req.q.qtype]
            reply = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=1), q=req.q)
            if qtype == "AAAA":
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::1"), ttl=60))
            elif qtype == "TXT":
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT("ok"), ttl=60))
            else:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.default_a), ttl=60))
            packed = reply.pack()
            writer.write(struct.pack("!H", len(packed)) + packed)
            await writer.drain()
            tags = ["dns-tcp"]
            if len(qname.split(".")[0]) >= 20:
                tags.append("long-label")
            self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                      dst_port=port, event_type="request",
                      summary=f"{qtype} {qname.rstrip('.')} (tcp)",
                      request={"qname": qname, "qtype": qtype},
                      response={"answer": self.default_a}, tags=tags)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, ValueError):
            pass
        finally:
            try:
                writer.close(); await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, host=self.bind_address, port=int(self.cfg.get("port", 53)))

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
