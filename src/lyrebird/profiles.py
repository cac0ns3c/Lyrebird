# SPDX-License-Identifier: GPL-3.0-or-later
"""Operator-defined response profiles.

Lets a lab tailor what each service hands back, without touching code — the
modern equivalent of INetSim's fakefiles and static responses. Rules are matched
top-to-bottom; the first match wins; if nothing matches, the service falls back
to its built-in default (and, only if explicitly enabled, to a model-generated
response).

HTTP rules match on method + path glob (+ optional host glob) and define the
status, headers, and body (inline or from a file).
DNS rules match on a qname glob + qtype and define the answer.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class HttpRule:
    path: str = "*"
    method: str = "*"
    host: str = "*"
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    body_file: Optional[str] = None
    content_type: str = "text/html"

    def matches(self, method: str, path: str, host: str) -> bool:
        return (fnmatch.fnmatch(method.upper(), self.method.upper())
                and fnmatch.fnmatch(path, self.path)
                and fnmatch.fnmatch(host, self.host))

    def resolve_body(self, base_dir: Path) -> bytes:
        if self.body_file:
            fp = Path(self.body_file)
            if not fp.is_absolute():
                fp = base_dir / fp
            if fp.exists():
                return fp.read_bytes()
            return b""
        if self.body is not None:
            return self.body.encode("utf-8")
        return b""


@dataclass
class DnsRule:
    qname: str = "*"
    qtype: str = "*"
    answer: str = ""        # the A/AAAA address or TXT string to return

    def matches(self, qname: str, qtype: str) -> bool:
        return (fnmatch.fnmatch(qname.rstrip(".").lower(), self.qname.rstrip(".").lower())
                and fnmatch.fnmatch(qtype.upper(), self.qtype.upper()))


@dataclass
class Profiles:
    http: list[HttpRule] = field(default_factory=list)
    dns: list[DnsRule] = field(default_factory=list)
    fakefiles_dir: Optional[str] = None     # serve real files by URL path
    base_dir: Path = field(default_factory=lambda: Path("."))

    @classmethod
    def from_config(cls, service_cfg: dict[str, Any], *, base_dir: Path) -> "Profiles":
        responses = (service_cfg or {}).get("responses", {}) or {}
        http_rules = [HttpRule(**r) for r in responses.get("http", [])]
        dns_rules = [DnsRule(**r) for r in responses.get("dns", [])]
        return cls(http=http_rules, dns=dns_rules,
                   fakefiles_dir=responses.get("fakefiles_dir"),
                   base_dir=base_dir)

    def match_http(self, method: str, path: str, host: str) -> Optional[HttpRule]:
        for rule in self.http:
            if rule.matches(method, path, host):
                return rule
        return None

    def match_dns(self, qname: str, qtype: str) -> Optional[DnsRule]:
        for rule in self.dns:
            if rule.matches(qname, qtype):
                return rule
        return None

    def fakefile_for(self, path: str) -> Optional[bytes]:
        """If a fakefiles dir is set and the URL path maps to a real file, return it."""
        if not self.fakefiles_dir:
            return None
        root = Path(self.fakefiles_dir)
        if not root.is_absolute():
            root = self.base_dir / root
        candidate = (root / path.lstrip("/")).resolve()
        try:
            candidate.relative_to(root.resolve())   # prevent path traversal
        except ValueError:
            return None
        if candidate.is_file():
            return candidate.read_bytes()
        return None