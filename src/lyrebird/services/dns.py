# SPDX-License-Identifier: GPL-3.0-or-later
"""DNS emulation service.

Answers every query with a configured sinkhole address so that name resolution
inside the lab "succeeds" and the sample proceeds to its next stage. Each query
is logged — the domains a sample resolves are often the single most useful
indicator it produces.

Uses dnslib for record construction. Runs over UDP (the common case); TCP
fallback is a documented next addition.
"""

from __future__ import annotations

import asyncio
from typing import Any

from dnslib import RR, QTYPE, A, AAAA, TXT, RCODE
from dnslib import DNSRecord, DNSHeader

from ..base import BaseService
from ..profiles import Profiles


class _DnsProtocol(asyncio.DatagramProtocol):
    def __init__(self, service: "DnsService") -> None:
        self.service = service
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            reply = self.service.build_reply(data, addr)
        except Exception:
            return
        if reply and self.transport:
            self.transport.sendto(reply, addr)


class DnsService(BaseService):
    name = "dns"

    def __init__(self, *args: Any, profiles: Profiles | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._transport: asyncio.BaseTransport | None = None
        self.default_a = self.cfg.get("default_a", "10.13.37.1")
        self.default_aaaa = self.cfg.get("default_aaaa", "::1")
        self.profiles = profiles or Profiles(base_dir=self.data_dir)

    def build_reply(self, data: bytes, addr: tuple[str, int]) -> bytes:
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

        # Operator rule overrides the default answer if one matches.
        rule = self.profiles.match_dns(qname, qtype)
        answer = self.default_a
        source = "default"
        if rule is not None and rule.answer:
            answer = rule.answer
            source = "rule"

        if qtype == "A":
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(answer), ttl=60))
        elif qtype == "AAAA":
            aaaa = rule.answer if (rule and rule.answer) else self.default_aaaa
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(aaaa), ttl=60))
        elif qtype == "TXT":
            txt = rule.answer if (rule and rule.answer) else "ok"
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(txt), ttl=60))
        else:
            # Resolve generically rather than NXDOMAIN, so the sample keeps going.
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(answer), ttl=60))

        tags = []
        # Long random-looking labels are a classic DGA / tunneling tell.
        first_label = qname.split(".")[0]
        if len(first_label) >= 20:
            tags.append("long-label")
        if qtype == "TXT":
            tags.append("txt-query")

        self.emit(
            transport="udp",
            src_ip=addr[0],
            src_port=addr[1],
            dst_port=int(self.cfg.get("port", 53)),
            event_type="request",
            summary=f"{qtype} {qname.rstrip('.')} -> {source}",
            request={"qname": qname, "qtype": qtype},
            response={"rcode": RCODE.NOERROR, "answer": answer, "source": source},
            tags=tags,
        )
        return reply.pack()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        port = int(self.cfg.get("port", 53))
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _DnsProtocol(self),
            local_addr=(self.bind_address, port),
        )

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()