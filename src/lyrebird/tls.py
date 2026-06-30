# SPDX-License-Identifier: GPL-3.0-or-later
"""TLS ClientHello parsing and JA3 / JA4 fingerprinting.

Defensive TLS-client fingerprinting: parse a raw ClientHello and compute JA3 and
JA4, the fingerprints threat-intel feeds (VirusTotal, GreyNoise, Cloudflare) use
to identify a client by *how* it speaks TLS, independent of SNI or IP. Useful for
spotting malware whose TLS stack differs from the browser its User-Agent claims.

This implements detection only — it does not craft or mimic handshakes.

JA3 is by Salesforce. JA4 (TLS client) is by FoxIO, published under BSD-3-Clause;
the algorithm is credited here. JA4+ suite methods (JA4S/JA4H/...) carry FoxIO's
own license and are not implemented.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

# GREASE values (RFC 8701) are excluded from fingerprints.
GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
          0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

_JA4_VER = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}

# Extension type constants we care about.
EXT_SNI = 0x0000
EXT_SUPPORTED_GROUPS = 0x000a
EXT_EC_POINT_FORMATS = 0x000b
EXT_SIG_ALGS = 0x000d
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002b


@dataclass
class ClientHello:
    legacy_version: int = 0
    ciphers: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)   # in original order
    groups: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)
    sig_algs: list[int] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    sni: Optional[str] = None
    alpn: list[str] = field(default_factory=list)


def _u16(b: bytes, i: int) -> int:
    return (b[i] << 8) | b[i + 1]


def parse_client_hello(data: bytes) -> Optional[ClientHello]:
    """Parse a ClientHello. Accepts bytes starting at either the TLS record
    header (0x16 ...) or the handshake message (0x01 ...). Returns None if the
    bytes are not a parseable ClientHello."""
    try:
        i = 0
        if data[0] == 0x16:           # TLS record: skip type(1)+version(2)+len(2)
            i = 5
        if data[i] != 0x01:           # handshake type must be client_hello
            return None
        i += 1
        i += 3                        # handshake length (3 bytes)
        ch = ClientHello()
        ch.legacy_version = _u16(data, i); i += 2
        i += 32                       # random
        sid_len = data[i]; i += 1 + sid_len
        cs_len = _u16(data, i); i += 2
        for j in range(i, i + cs_len, 2):
            ch.ciphers.append(_u16(data, j))
        i += cs_len
        comp_len = data[i]; i += 1 + comp_len
        if i + 2 > len(data):
            return ch                 # no extensions
        ext_total = _u16(data, i); i += 2
        end = i + ext_total
        while i + 4 <= end:
            etype = _u16(data, i)
            elen = _u16(data, i + 2)
            i += 4
            edata = data[i:i + elen]
            i += elen
            ch.extensions.append(etype)
            try:
                _parse_extension(ch, etype, edata)
            except (IndexError, ValueError):
                pass            # a malformed extension shouldn't void the whole CH
        return ch
    except (IndexError, ValueError):
        return None


def _parse_extension(ch: ClientHello, etype: int, edata: bytes) -> None:
    if etype == EXT_SNI and len(edata) >= 5:
        # server_name_list: list_len(2), name_type(1), name_len(2), name
        name_len = _u16(edata, 3)
        ch.sni = edata[5:5 + name_len].decode("utf-8", "replace")
    elif etype == EXT_SUPPORTED_GROUPS and len(edata) >= 2:
        ln = _u16(edata, 0)
        for j in range(2, 2 + ln, 2):
            ch.groups.append(_u16(edata, j))
    elif etype == EXT_EC_POINT_FORMATS and len(edata) >= 1:
        ln = edata[0]
        ch.point_formats.extend(edata[1:1 + ln])
    elif etype == EXT_SIG_ALGS and len(edata) >= 2:
        ln = _u16(edata, 0)
        for j in range(2, 2 + ln, 2):
            ch.sig_algs.append(_u16(edata, j))
    elif etype == EXT_SUPPORTED_VERSIONS and len(edata) >= 1:
        ln = edata[0]
        for j in range(1, 1 + ln, 2):
            ch.supported_versions.append(_u16(edata, j))
    elif etype == EXT_ALPN and len(edata) >= 2:
        i = 2
        while i < len(edata):
            plen = edata[i]; i += 1
            ch.alpn.append(edata[i:i + plen].decode("utf-8", "replace"))
            i += plen


def _no_grease(values: list[int]) -> list[int]:
    return [v for v in values if v not in GREASE]


def grease_present(ch: ClientHello) -> bool:
    """True if the ClientHello carried any GREASE value (RFC 8701)."""
    return any(v in GREASE for v in
               (*ch.ciphers, *ch.extensions, *ch.groups,
                *ch.sig_algs, *ch.supported_versions))


def offers_tls13(ch: ClientHello) -> bool:
    """True if the client advertised TLS 1.3 via supported_versions."""
    return 0x0304 in ch.supported_versions


def ja3(ch: ClientHello) -> tuple[str, str]:
    """Return (ja3_string, ja3_hash). JA3 keeps original extension order."""
    parts = [
        str(ch.legacy_version),
        "-".join(str(c) for c in _no_grease(ch.ciphers)),
        "-".join(str(e) for e in _no_grease(ch.extensions)),
        "-".join(str(g) for g in _no_grease(ch.groups)),
        "-".join(str(p) for p in ch.point_formats),
    ]
    s = ",".join(parts)
    return s, hashlib.md5(s.encode()).hexdigest()


def _sha12(s: str) -> str:
    if not s:
        return "000000000000"
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _ja4_parts(ch: ClientHello, protocol: str = "t") -> tuple[str, str, str]:
    """Compute the three JA4 components before b/c are hashed: (ja4_a, b_raw, c_raw)."""
    ciphers = _no_grease(ch.ciphers)
    exts = _no_grease(ch.extensions)

    sv = _no_grease(ch.supported_versions)
    ver_num = max(sv) if sv else ch.legacy_version
    ver = _JA4_VER.get(ver_num, "00")

    sni = "d" if EXT_SNI in ch.extensions else "i"
    cc = min(len(ciphers), 99)
    ec = min(len(exts), 99)
    if ch.alpn:
        a = ch.alpn[0]
        alpn = (a[0] + a[-1]) if a else "00"
    else:
        alpn = "00"
    ja4_a = f"{protocol}{ver}{sni}{cc:02d}{ec:02d}{alpn}"

    b_raw = ",".join(f"{c:04x}" for c in sorted(ciphers))

    ext_for_c = sorted(e for e in exts if e not in (EXT_SNI, EXT_ALPN))
    c_raw = ",".join(f"{e:04x}" for e in ext_for_c)
    if ch.sig_algs:
        c_raw += "_" + ",".join(f"{a:04x}" for a in ch.sig_algs)
    return ja4_a, b_raw, c_raw


def ja4(ch: ClientHello, protocol: str = "t") -> str:
    """Return the JA4 fingerprint (FoxIO, BSD-3-Clause algorithm)."""
    a, b_raw, c_raw = _ja4_parts(ch, protocol)
    return f"{a}_{_sha12(b_raw)}_{_sha12(c_raw)}"


def ja4_raw(ch: ClientHello, protocol: str = "t") -> str:
    """Return the raw JA4 (ja4_r): same prefix, b/c lists left unhashed."""
    a, b_raw, c_raw = _ja4_parts(ch, protocol)
    return f"{a}_{b_raw}_{c_raw}"


def fingerprint(data: bytes) -> Optional[dict]:
    """Convenience: parse + both fingerprints + key fields, or None."""
    ch = parse_client_hello(data)
    if ch is None:
        return None
    j3_str, j3 = ja3(ch)
    return {
        "ja3": j3, "ja3_string": j3_str, "ja4": ja4(ch),
        "sni": ch.sni, "alpn": ch.alpn,
        "cipher_count": len(_no_grease(ch.ciphers)),
        "ext_count": len(_no_grease(ch.extensions)),
    }
