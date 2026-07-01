# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests: DNS tunneling / exfil session analytic."""
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.dns_tunnel import (  # noqa: E402
    analyze_dns_tunnel, shannon_entropy, parent_domain, subdomain,
)


def _dns_event(src, qname, qtype="A"):
    return {"service": "dns", "event_type": "request", "src_ip": src,
            "request": {"qname": qname, "qtype": qtype}}


def _encoded(i):
    return base64.b32encode(bytes(range(i, i + 12))).decode().rstrip("=").lower()


def test_helpers():
    assert parent_domain("a.b.evil.com") == "evil.com"
    assert parent_domain("evil.com") == "evil.com"
    assert subdomain("chunk.tunnel.evil.com") == "chunk.tunnel"
    assert subdomain("evil.com") == ""
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("abcdefgh") > 2.5


def test_flags_exfil_tunnel():
    events = [_dns_event("10.0.0.5", f"{_encoded(i)}.t.evil.com") for i in range(12)]
    report = analyze_dns_tunnel(events)
    assert report["channels_flagged"] == 1
    f = report["findings"][0]
    assert f["src_ip"] == "10.0.0.5"
    assert f["parent_domain"] == "evil.com"
    assert f["unique_ratio"] >= 0.9
    assert f["mean_entropy"] >= 3.2
    assert f["queries"] == 12


def test_does_not_flag_benign():
    events = [_dns_event("10.0.0.6", q) for q in
              ["www.google.com", "mail.google.com", "www.google.com",
               "api.github.com", "www.github.com", "cdn.example.net"]]
    assert analyze_dns_tunnel(events)["channels_flagged"] == 0


def test_does_not_flag_single_dga_query():
    events = [_dns_event("10.0.0.7", f"{_encoded(0)}.t.evil.com")]
    assert analyze_dns_tunnel(events)["channels_flagged"] == 0


def test_does_not_flag_high_volume_low_entropy():
    events = [_dns_event("10.0.0.8", "www.example.com") for _ in range(12)]
    assert analyze_dns_tunnel(events)["channels_flagged"] == 0


def test_txt_ratio_recorded():
    events = [_dns_event("10.0.0.9", f"{_encoded(i)}.t.evil.com", "TXT")
              for i in range(12)]
    f = analyze_dns_tunnel(events)["findings"][0]
    assert f["txt_ratio"] == 1.0


def test_multilabel_public_suffix_is_approximate():
    # Documented limitation: last-2-labels attributes the parent to the public
    # suffix (co.uk), not the registrable domain. Detection still fires because
    # the encoded label carries the entropy.
    assert parent_domain("chunk.attacker.co.uk") == "co.uk"
    assert subdomain("chunk.attacker.co.uk") == "chunk.attacker"
    events = [_dns_event("10.0.0.10", f"{_encoded(i)}.attacker.co.uk")
              for i in range(12)]
    report = analyze_dns_tunnel(events)
    assert report["channels_flagged"] == 1
    assert report["findings"][0]["parent_domain"] == "co.uk"   # approximate


def test_isolates_sources_and_ignores_benign_in_same_session():
    exfil = [_dns_event("10.0.0.11", f"{_encoded(i)}.t.evil.com") for i in range(12)]
    benign = [_dns_event("10.0.0.12", q) for q in
              ["www.google.com", "mail.google.com", "api.github.com"]]
    report = analyze_dns_tunnel(exfil + benign)
    assert report["channels_flagged"] == 1
    assert report["findings"][0]["src_ip"] == "10.0.0.11"      # only the exfil source


def test_tolerates_malformed_events():
    events = [
        {"service": "dns", "event_type": "request"},           # no request/src_ip
        {"service": "dns", "event_type": "request", "request": {"qname": ""}},
        {"service": "dns", "event_type": "request", "request": {"qname": "evil.com."}},
        {"service": "http", "event_type": "request", "request": {"qname": "x.y.z"}},
    ]
    report = analyze_dns_tunnel(events)                          # no crash
    assert report["channels_flagged"] == 0
