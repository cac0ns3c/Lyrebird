# SPDX-License-Identifier: GPL-3.0-or-later
"""DNS tunneling / exfil detection.

Data-exfil-over-DNS is a *channel*: one source streams data as many high-entropy
encoded subdomains under a single parent domain. The single-query long-label DGA
rule can't see the channel; this session analytic does — grouping a captured
session's DNS queries by (source, parent domain) and flagging channels by volume,
per-label entropy, and subdomain uniqueness.

    python -m lyrebird.dns_tunnel --session labdata/events/<id>.jsonl

Limitations (heuristic, analyst-triaged — not an automated blocker):
  * Parent domain is the last two labels (dependency-free eTLD+1 approximation),
    so a channel under a multi-label public suffix (co.uk, com.au) is attributed
    to the suffix, and unrelated traffic under it can share a bucket. Detection
    still fires (the encoded label carries the entropy); the reported
    ``parent_domain`` is approximate for those TLDs.
  * Any high-entropy, near-all-unique subdomain stream is flagged. If a lab
    redirects ALL DNS to the emulator, benign automated traffic (telemetry GUIDs,
    CDN cache-busting hashes, OCSP hash-prefix lookups) can also match — triage
    findings by parent domain.
  * No time window: queries accumulate across the whole session. The coarse Sigma
    companion (dns_tunnel_correlation.yml) adds the SIEM-side windowed view.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

# Tunables (documented so analysts can adapt). Verified against encoded-vs-benign
# samples: base32/64/hex data lands ~3.1-3.5 bits/char; benign labels are <~2.
MIN_QUERIES = 8            # sustained volume before a channel is assessable
ENTROPY_MIN = 3.2          # mean bits/char over subdomains -> encoded data
UNIQUE_RATIO_MIN = 0.8     # exfil chunks are near-all-unique (not cached lookups)
PARENT_LABELS = 2          # last-2-labels parent (dependency-free eTLD+1 approx)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parent_domain(qname: str, labels: int = PARENT_LABELS) -> str:
    parts = qname.rstrip(".").split(".")
    return ".".join(parts[-labels:]) if len(parts) >= labels else qname.rstrip(".")


def subdomain(qname: str, labels: int = PARENT_LABELS) -> str:
    parts = qname.rstrip(".").split(".")
    return ".".join(parts[:-labels]) if len(parts) > labels else ""


def analyze_dns_tunnel(events: list[dict[str, Any]]) -> dict[str, Any]:
    # Group DNS request events by (source, parent domain).
    channels: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for e in events:
        if e.get("service") != "dns" or e.get("event_type") != "request":
            continue
        req = e.get("request", {}) or {}
        qname = (req.get("qname") or "").rstrip(".")
        if not qname or not subdomain(qname):
            continue
        key = (e.get("src_ip", "?"), parent_domain(qname))
        channels.setdefault(key, []).append(e)

    findings = []
    for (src, parent), evs in channels.items():
        subs = [subdomain((ev.get("request", {}) or {}).get("qname", ""))
                for ev in evs]
        queries = len(evs)
        distinct = len(set(subs))
        unique_ratio = distinct / queries if queries else 0.0
        mean_entropy = (sum(shannon_entropy(s.replace(".", "")) for s in subs)
                        / len(subs)) if subs else 0.0
        max_label_len = max((len(s.split(".")[0]) for s in subs), default=0)
        txt = sum(1 for ev in evs
                  if (ev.get("request", {}) or {}).get("qtype") in ("TXT", "NULL"))
        txt_ratio = txt / queries if queries else 0.0

        if (queries >= MIN_QUERIES and mean_entropy >= ENTROPY_MIN
                and unique_ratio >= UNIQUE_RATIO_MIN):
            findings.append({
                "src_ip": src,
                "parent_domain": parent,
                "queries": queries,
                "distinct_subdomains": distinct,
                "unique_ratio": round(unique_ratio, 3),
                "mean_entropy": round(mean_entropy, 3),
                "max_label_len": max_label_len,
                "txt_ratio": round(txt_ratio, 3),
                "sample": [(ev.get("request", {}) or {}).get("qname", "")
                           for ev in evs[:5]],
            })

    return {
        "session_events": len(events),
        "channels_flagged": len(findings),
        "findings": sorted(findings, key=lambda f: -f["queries"]),
    }


def load_events(path: Path) -> list[dict[str, Any]]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def main() -> None:
    p = argparse.ArgumentParser(
        prog="lyrebird.dns_tunnel",
        description="Detect DNS tunneling / data-exfil channels in a session.")
    p.add_argument("--session", required=True, help="path to a session .jsonl")
    p.add_argument("--out", default=None, help="write JSON report here")
    args = p.parse_args()
    report = analyze_dns_tunnel(load_events(Path(args.session)))
    text = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
