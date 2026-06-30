# SPDX-License-Identifier: GPL-3.0-or-later
"""Realistic-mode (upstream) DNS resolution.

The upstream resolver is always mocked here — these tests never touch the
network. They verify the decide-then-sink semantics, the NXDOMAIN-on-miss
behaviour, that operator rules and DGA labels short-circuit without any upstream
lookup, and that the default (answer-everything) mode is unchanged.
"""

import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dnslib import DNSRecord, RCODE  # noqa: E402

from lyrebird.events import EventSink  # noqa: E402
from lyrebird.services.dns import DnsService  # noqa: E402
from lyrebird.profiles import Profiles, DnsRule  # noqa: E402


def _svc(tmp_path, upstream=None, profiles=None):
    sink = EventSink(session="t", log_path=tmp_path / "e.jsonl", echo=False)
    cfg = {"port": 53}
    if upstream is not None:
        cfg["upstream"] = upstream
    svc = DnsService(cfg=cfg, sink=sink, bind_address="127.0.0.1",
                     data_dir=tmp_path, tls={}, profiles=profiles)
    return svc, sink


def _q(name, qtype="A"):
    return DNSRecord.question(name, qtype).pack()


def _last_event(tmp_path):
    lines = [l for l in (tmp_path / "e.jsonl").read_text().splitlines() if l]
    return json.loads(lines[-1])


def test_default_mode_resolves_everything(tmp_path):
    svc, sink = _svc(tmp_path)  # upstream disabled
    assert svc.upstream_enabled is False
    reply = DNSRecord.parse(svc.build_reply(_q("totally-bogus-zz.example."), ("10.0.0.5", 5300)))
    sink.close()
    assert reply.header.rcode == RCODE.NOERROR
    assert len(reply.rr) == 1
    assert "sandbox-probe" not in _last_event(tmp_path)["tags"]


def test_upstream_nonexistent_returns_nxdomain(tmp_path):
    svc, sink = _svc(tmp_path, upstream={"enabled": True})
    reply = DNSRecord.parse(
        svc.build_reply(_q("nope.invalid."), ("10.0.0.5", 5300), upstream_exists=False)
    )
    sink.close()
    assert reply.header.rcode == RCODE.NXDOMAIN
    assert len(reply.rr) == 0
    ev = _last_event(tmp_path)
    assert "sandbox-probe" in ev["tags"]
    assert ev["response"]["source"] == "nxdomain"


def test_upstream_existing_domain_still_sinks(tmp_path):
    svc, sink = _svc(tmp_path, upstream={"enabled": True})
    reply = DNSRecord.parse(
        svc.build_reply(_q("real.example."), ("10.0.0.5", 5300), upstream_exists=True)
    )
    sink.close()
    assert reply.header.rcode == RCODE.NOERROR
    assert str(reply.rr[0].rdata) == svc.default_a  # never forwarded to the real host
    assert "upstream-resolved" in _last_event(tmp_path)["tags"]


def test_operator_rule_wins_without_upstream_lookup(tmp_path):
    profiles = Profiles(dns=[DnsRule(qname="*.evil-c2.com", qtype="A", answer="10.13.37.66")])
    svc, sink = _svc(tmp_path, upstream={"enabled": True}, profiles=profiles)
    called = []

    async def must_not_call(*a):
        called.append(1)
        return False

    svc._exists_upstream = must_not_call
    rule = svc.profiles.match_dns("beacon.evil-c2.com.", "A")
    exists = asyncio.run(svc.resolve_exists("beacon.evil-c2.com.", "A", rule))
    sink.close()
    assert exists is True
    assert not called


def test_dga_label_short_circuits_to_nxdomain(tmp_path):
    svc, sink = _svc(tmp_path, upstream={"enabled": True})
    called = []

    async def must_not_call(*a):
        called.append(1)
        return True

    svc._exists_upstream = must_not_call
    dga = "a" * 30 + ".example."
    exists = asyncio.run(svc.resolve_exists(dga, "A", None))
    sink.close()
    assert exists is False       # NXDOMAIN
    assert not called            # the DGA domain is never leaked upstream


def test_normal_domain_consults_upstream(tmp_path):
    svc, sink = _svc(tmp_path, upstream={"enabled": True})

    async def fake_exists(qname, qtype):
        return False

    svc._exists_upstream = fake_exists
    exists = asyncio.run(svc.resolve_exists("plain.example.", "A", None))
    sink.close()
    assert exists is False
