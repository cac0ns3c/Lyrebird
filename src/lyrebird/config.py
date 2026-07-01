# SPDX-License-Identifier: GPL-3.0-or-later
"""Configuration loading.

A single YAML file describes which services run, what ports they bind, and
per-service behaviour. Sensible defaults mean an empty config still produces a
working lab.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


DEFAULTS: dict[str, Any] = {
    "bind_address": "0.0.0.0",
    "data_dir": "./labdata",
    "session": None,            # auto-generated if null
    "echo": True,               # mirror events to stdout
    "tls": {
        "enabled": True,
        "ca_dir": "./labdata/ca",
    },
    "services": {
        "http":     {"enabled": True,  "port": 80,   "tls_port": 443},
        "dns":      {"enabled": True,  "port": 53,   "default_a": "10.13.37.1",
                     "default_aaaa": "::1"},
        "dns_tcp":  {"enabled": True,  "port": 53,   "default_a": "10.13.37.1"},
        "smtp":     {"enabled": True,  "port": 25},
        "pop3":     {"enabled": True,  "port": 110},
        "ssh":      {"enabled": True,  "port": 22,
                     "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
                     "accept_after": 3, "weak_creds": [], "bruteforce_threshold": 3},
        "imap":     {"enabled": True,  "port": 143, "idle_push_delay": 2.0, "idle_max": 60},
        "ftp":      {"enabled": True,  "port": 21},
        "tftp":     {"enabled": True,  "port": 69},
        "irc":      {"enabled": True,  "port": 6667},
        "ntp":      {"enabled": True,  "port": 123,  "faketime_delta": 0},
        "telnet":   {"enabled": True,  "port": 23,
                     "banner": "\r\nAM335x/Linux login service\r\n",
                     "accept_after": 3, "weak_creds": [], "bruteforce_threshold": 3},
        "quic":     {"enabled": True,  "port": 443,  "body": "OK"},
        # Fingerprinting HTTPS emulator: peeks ClientHello (JA3/JA4 + SNI), then
        # terminates with the lab cert and serves content. Off by default to
        # avoid clashing with the HTTP service's TLS terminator on 443; enable it
        # instead of that when you want fingerprints on content-serving sessions.
        "tls":      {"enabled": False, "port": 443},
        # TLS fingerprinting tap. Off by default — enabling it on 443 means using
        # it instead of the HTTP TLS terminator. Captures JA3/JA4 then closes.
        "tls_capture": {"enabled": False, "port": 8443},
        "tcp_sink": {"enabled": True,  "ports": [8080, 1080]},
    },
    # Model layer. Used for (a) `python -m lyrebird.analyze` session triage and
    # (b) optional response generation. Egress to frontier APIs happens only if
    # you select one of those providers; 'local' keeps everything on-host.
    "models": {
        "provider": "local",        # anthropic | openai | gemini | local | mock
        "model": None,              # provider default if null
        "base_url": None,           # local provider endpoint override
        "respond": {
            "enabled": False,       # OFF by default — static templates are preferred
        },
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


@dataclass
class Config:
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path | None) -> "Config":
        user_cfg: dict[str, Any] = {}
        if path:
            p = Path(path)
            if p.exists():
                user_cfg = yaml.safe_load(p.read_text()) or {}
        merged = _deep_merge(DEFAULTS, user_cfg)
        return cls(raw=merged)

    # convenience accessors
    @property
    def bind_address(self) -> str:
        return self.raw["bind_address"]

    @property
    def data_dir(self) -> Path:
        return Path(self.raw["data_dir"])

    @property
    def echo(self) -> bool:
        return bool(self.raw["echo"])

    @property
    def tls(self) -> dict[str, Any]:
        return self.raw["tls"]

    @property
    def services(self) -> dict[str, Any]:
        return self.raw["services"]

    def service(self, name: str) -> dict[str, Any]:
        return self.raw["services"].get(name, {})

    def enabled_services(self) -> list[str]:
        return [n for n, c in self.services.items() if c.get("enabled")]