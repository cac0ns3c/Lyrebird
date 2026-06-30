# SPDX-License-Identifier: GPL-3.0-or-later
"""Traffic-mimicry and encryption-tell detection (Phase 3, defensive pair).

Phase 3's offensive techniques — making C2 traffic look like ordinary web/CDN
traffic and encrypting payloads — are evasions against protocol and content
inspection. This module is their detection counterpart. It reads a captured
session and flags the fingerprints those techniques leave in the telemetry the
emulator already records:

  * protocol-on-unexpected-port — raw bytes captured by the TCP sink that match a
    known protocol (TLS, SSH, HTTP, SMTP, IRC) on a port that isn't that
    protocol's home. A classic tunnelling / port-hopping tell.
  * possible-domain-fronting   — an HTTP Host header pointing at a frontable CDN
    edge while the request otherwise looks like a beacon (no User-Agent, small
    bodies). Real fronting needs SNI-vs-Host comparison from packet capture; this
    is the app-layer heuristic.
  * browser-ua-but-bot         — a request advertising a browser User-Agent whose
    behaviour isn't browser-like (one endpoint, hammered, no asset fetches).
  * encrypted-body             — a captured upload/body with near-maximal Shannon
    entropy, i.e. encrypted or packed, especially when declared as plaintext.

Detection only. Nothing here generates evasive traffic.

    python -m lyrebird.mimicry --session labdata/events/<id>.jsonl
"""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

# Edge/CDN domains historically abused for domain fronting. Non-exhaustive and
# meant to be extended per environment.
FRONTABLE = (
    "cloudfront.net", "azureedge.net", "fastly.net", "akamaihd.net",
    "googleapis.com", "appspot.com", "cloudflare.net", "s3.amazonaws.com",
    "windows.net", "azurefd.net", "trafficmanager.net",
)

_BROWSER_UA = re.compile(r"Mozilla/5\.0.*(Chrome|Firefox|Safari|Edg)/", re.IGNORECASE)

# Standard home port(s) for protocols we can fingerprint from initial bytes.
_PROTO_HOME = {
    "tls": {443}, "ssh": {22}, "http": {80}, "smtp": {25},
    "irc": {6667, 6697}, "ftp": {21},
}


def shannon_entropy(data: bytes) -> float:
    """Bits per byte (0–8). Encrypted/compressed data sits near 8.0."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def protocol_fingerprint(first_bytes: bytes) -> Optional[str]:
    """Best-effort protocol guess from the first bytes of a stream."""
    if len(first_bytes) >= 3 and first_bytes[0] == 0x16 and first_bytes[1] == 0x03:
        return "tls"            # TLS handshake record, version 3.x
    head = first_bytes[:16].upper()
    if head.startswith(b"SSH-"):
        return "ssh"
    if head[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ") or head.startswith(b"OPTIONS"):
        return "http"
    if head.startswith(b"EHLO") or head.startswith(b"HELO") or head.startswith(b"MAIL"):
        return "smtp"
    if head.startswith(b"NICK") or head.startswith(b"USER") or head.startswith(b"PASS"):
        return "irc"
    if head.startswith(b"USER ") or head.startswith(b"220 "):
        return "ftp"
    return None


def _hex_to_bytes(preview_hex: str) -> bytes:
    try:
        return bytes.fromhex(preview_hex)
    except ValueError:
        return b""


def _read_artifact(art: dict[str, Any], data_dir: Optional[Path]) -> bytes:
    path = art.get("path", "")
    p = Path(path)
    if not p.is_absolute() and data_dir:
        p = data_dir / path
    try:
        return p.read_bytes() if p.is_file() else b""
    except Exception:
        return b""


def analyze_mimicry(events: list[dict[str, Any]],
                    data_dir: Optional[Path] = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    # Track per-source HTTP endpoint diversity for the browser-ua-but-bot check.
    src_paths: dict[str, set] = defaultdict(set)
    src_http_events: dict[str, list] = defaultdict(list)
    src_sni: dict[str, set] = defaultdict(set)     # from TLS fingerprint events
    src_hosts: dict[str, set] = defaultdict(set)   # from HTTP Host headers

    for e in events:
        svc = e.get("service")
        req = e.get("request", {}) or {}
        src = e.get("src_ip", "?")

        # collect SNI from TLS capture events
        if svc in ("tls_capture", "tls") and req.get("sni"):
            src_sni[src].add(req["sni"].lower())

        # 1. protocol-on-unexpected-port (from sink captures)
        if svc == "tcp_sink":
            raw = _hex_to_bytes(req.get("preview", ""))
            proto = protocol_fingerprint(raw)
            port = e.get("dst_port")
            if proto and port not in _PROTO_HOME.get(proto, set()):
                findings.append({
                    "type": "protocol-on-unexpected-port", "src_ip": src,
                    "detail": f"{proto} bytes on port {port}",
                    "severity": "high",
                })

        # collect for http heuristics
        if svc == "http":
            src_paths[src].add(req.get("path", ""))
            src_http_events[src].append(e)

            # 2. possible-domain-fronting
            host = (req.get("host") or "").lower()
            if host:
                src_hosts[src].add(host.split(":")[0])
            beaconish = ("missing-user-agent" in e.get("tags", [])
                         or (req.get("method") in ("POST", "PUT")
                             and req.get("body_len", 0) and req["body_len"] < 2048))
            if host and any(host.endswith(cdn) for cdn in FRONTABLE) and beaconish:
                findings.append({
                    "type": "possible-domain-fronting", "src_ip": src,
                    "detail": f"frontable host '{host}' with beacon-like request",
                    "severity": "medium",
                })

            # 4. encrypted-body on a plaintext-declared endpoint
            headers = req.get("headers", {}) or {}
            ctype = (headers.get("content-type") or "").lower()
            for art in e.get("artifacts", []):
                data = _read_artifact(art, data_dir)
                if len(data) >= 64:
                    ent = shannon_entropy(data)
                    plaintextish = any(t in ctype for t in
                                       ("text/", "json", "form-urlencoded", "xml"))
                    if ent >= 7.2 and (plaintextish or not ctype):
                        findings.append({
                            "type": "encrypted-body", "src_ip": src,
                            "detail": f"entropy={ent:.2f} bits/byte on "
                                      f"content-type='{ctype or 'unset'}'",
                            "severity": "medium",
                        })

        # encrypted upload over ftp/tftp
        if svc in ("ftp", "tftp"):
            for art in e.get("artifacts", []):
                data = _read_artifact(art, data_dir)
                if len(data) >= 64 and shannon_entropy(data) >= 7.2:
                    findings.append({
                        "type": "encrypted-upload", "src_ip": src,
                        "detail": f"{svc} upload entropy "
                                  f"{shannon_entropy(data):.2f} bits/byte",
                        "severity": "medium",
                    })

    # 3. browser-ua-but-bot — browser UA but single endpoint hammered
    for src, evs in src_http_events.items():
        if len(evs) < 4:
            continue
        uas = {(e.get("request", {}).get("headers", {}) or {}).get("user-agent", "")
               for e in evs}
        browser = any(_BROWSER_UA.search(ua or "") for ua in uas)
        if browser and len(src_paths[src]) == 1:
            findings.append({
                "type": "browser-ua-but-bot", "src_ip": src,
                "detail": f"browser UA but {len(evs)} requests to a single endpoint",
                "severity": "medium",
            })

    # 5. sni-host-mismatch — TLS SNI differs from the HTTP Host. With both
    # observed for one source, this is the strong domain-fronting signal
    # (front domain in SNI, real C2 host in the encrypted Host header).
    for src in set(src_sni) & set(src_hosts):
        snis, hosts = src_sni[src], src_hosts[src]
        if snis and hosts and snis.isdisjoint(hosts):
            findings.append({
                "type": "sni-host-mismatch", "src_ip": src,
                "detail": f"SNI {sorted(snis)} vs Host {sorted(hosts)}",
                "severity": "high",
            })

    by_type: dict[str, int] = defaultdict(int)
    for f in findings:
        by_type[f["type"]] += 1
    return {
        "session_events": len(events),
        "findings_count": len(findings),
        "by_type": dict(by_type),
        "findings": findings,
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
        prog="lyrebird.mimicry",
        description="Detect traffic-mimicry and encryption tells in a session.")
    p.add_argument("--session", required=True, help="path to a session .jsonl")
    p.add_argument("--data-dir", default=None,
                   help="base dir for resolving captured artifact paths")
    p.add_argument("--out", default=None, help="write JSON report here")
    args = p.parse_args()

    data_dir = Path(args.data_dir) if args.data_dir else None
    report = analyze_mimicry(load_events(Path(args.session)), data_dir)
    text = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
