# SPDX-License-Identifier: GPL-3.0-or-later
"""DNS emulation service.

By default, answers every query with a configured sinkhole address so that name
resolution inside the lab "succeeds" and the sample proceeds to its next stage.
Each query is logged — the domains a sample resolves are often the single most
useful indicator it produces.

Optional realistic mode (``dns.upstream.enabled``, OFF by default): use a real
upstream resolver only to decide whether a domain *exists*, then still answer
with the lab sink for domains that do, and return ``NXDOMAIN`` for domains that
don't. This defeats the classic sinkhole "answer-everything" tell that
sandbox-aware malware probes for. It is off by default because it requires
network egress and therefore BREAKS lab isolation — the queried domain is sent
to the upstream resolver, which can reveal to adversary infrastructure that the
sample is under analysis. Obvious DGA/tunneling labels are never forwarded
upstream; they short-circuit straight to NXDOMAIN.

Uses dnslib for record construction. Runs over UDP (the common case).
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import Any

from dnslib import RR, QTYPE, A, AAAA, TXT, RCODE
from dnslib import DNSRecord, DNSHeader

from ..base import BaseService
from ..profiles import Profiles

#: leftmost-label length at or above which a query is treated as a DGA/tunneling
#: tell — tagged 'long-label' and (in realistic mode) never forwarded upstream.
DGA_LABEL_LEN = 20


class _DnsProtocol(asyncio.DatagramProtocol):
    def __init__(self, service: "DnsService") -> None:
        self.service = service
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        # Realistic mode needs an async upstream lookup, so hand off to a task.
        if self.service.upstream_enabled and self.transport is not None:
            asyncio.get_event_loop().create_task(
                self.service.handle(data, addr, self.transport)
            )
            return
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

        up = self.cfg.get("upstream", {}) or {}
        self.upstream_enabled = bool(up.get("enabled", False))
        self.upstream_resolver = str(up.get("resolver", "1.1.1.1"))
        self.upstream_timeout = float(up.get("timeout", 2.0))
        self.upstream_cache_ttl = float(up.get("cache_ttl", 300.0))
        self._cache: dict[str, tuple[bool, float]] = {}

    @staticmethod
    def _is_dga(qname: str) -> bool:
        return len(qname.split(".")[0]) >= DGA_LABEL_LEN

    async def resolve_exists(self, qname: str, qtype: str, rule: Any) -> bool:
        """Decide whether a name should resolve, in realistic (upstream) mode.

        Operator rules always win (no lookup). DGA/tunneling labels are never
        forwarded upstream — they resolve to NXDOMAIN locally. Everything else
        is checked against the configured upstream resolver.
        """
        if rule is not None and rule.answer:
            return True
        if self._is_dga(qname):
            return False
        return await self._exists_upstream(qname, qtype)

    async def _exists_upstream(self, qname: str, qtype: str) -> bool:
        key = qname.lower()
        now = time.monotonic()
        cached = self._cache.get(key)
        if cached and cached[1] > now:
            return cached[0]
        loop = asyncio.get_running_loop()
        try:
            exists = await asyncio.wait_for(
                loop.run_in_executor(None, self._lookup_blocking, qname, qtype),
                timeout=self.upstream_timeout,
            )
        except Exception:
            # Fail open to the sink: a flaky/blocked resolver must not blackhole
            # the whole lab. Only a definitive NXDOMAIN yields NXDOMAIN.
            exists = True
        self._cache[key] = (exists, now + self.upstream_cache_ttl)
        return exists

    def _lookup_blocking(self, qname: str, qtype: str) -> bool:
        rtype = qtype if qtype in ("A", "AAAA", "TXT") else "A"
        pkt = DNSRecord.question(qname, rtype).send(
            self.upstream_resolver, 53, timeout=self.upstream_timeout
        )
        return DNSRecord.parse(pkt).header.rcode != RCODE.NXDOMAIN

    def build_reply(self, data: bytes, addr: tuple[str, int],
                    upstream_exists: bool | None = None) -> bytes:
        """Build the DNS reply.

        ``upstream_exists`` is ``None`` in answer-everything mode (the default),
        ``True``/``False`` in realistic mode to mean the domain does / does not
        exist upstream. ``False`` (and no operator rule) yields NXDOMAIN.
        """
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

        rule = self.profiles.match_dns(qname, qtype)
        has_rule = rule is not None and bool(rule.answer)
        answer = rule.answer if has_rule else self.default_a
        source = "rule" if has_rule else "default"

        tags: list[str] = []
        if self._is_dga(qname):
            tags.append("long-label")
        if qtype == "TXT":
            tags.append("txt-query")

        nxdomain = (upstream_exists is False) and not has_rule
        if nxdomain:
            reply.header.rcode = RCODE.NXDOMAIN
            source = "nxdomain"
            tags.append("sandbox-probe")
            rcode: Any = RCODE.NXDOMAIN
            answer_val: Any = None
        else:
            if upstream_exists is True and not has_rule:
                source = "upstream"
                tags.append("upstream-resolved")
            if qtype == "AAAA":
                answer = rule.answer if has_rule else self.default_aaaa
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(answer), ttl=60))
            elif qtype == "TXT":
                answer = rule.answer if has_rule else "ok"
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(answer), ttl=60))
            else:
                # A and any other qtype resolve generically to the sink A record,
                # so the sample keeps going.
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(answer), ttl=60))
            rcode = RCODE.NOERROR
            answer_val = answer

        self.emit(
            transport="udp",
            src_ip=addr[0],
            src_port=addr[1],
            dst_port=int(self.cfg.get("port", 53)),
            event_type="request",
            summary=f"{qtype} {qname.rstrip('.')} -> {source}",
            request={"qname": qname, "qtype": qtype},
            response={"rcode": rcode, "answer": answer_val, "source": source},
            tags=tags,
        )
        return reply.pack()

    async def handle(self, data: bytes, addr: tuple[str, int],
                     transport: asyncio.DatagramTransport) -> None:
        """Async path for realistic mode: decide existence, then reply."""
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            qtype = QTYPE[request.q.qtype]
            rule = self.profiles.match_dns(qname, qtype)
            exists = await self.resolve_exists(qname, qtype, rule)
            reply = self.build_reply(data, addr, upstream_exists=exists)
        except Exception:
            return
        if reply:
            transport.sendto(reply, addr)

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        port = int(self.cfg.get("port", 53))
        if self.upstream_enabled:
            print(
                f"[lyrebird] WARNING: dns.upstream.enabled=true — unmatched queries "
                f"will be resolved against {self.upstream_resolver} on the real "
                f"internet. This breaks lab isolation and can reveal the analysis "
                f"to adversary infrastructure.",
                file=sys.stderr,
            )
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _DnsProtocol(self),
            local_addr=(self.bind_address, port),
        )

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()
