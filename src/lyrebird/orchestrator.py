# SPDX-License-Identifier: GPL-3.0-or-later
"""Orchestrator.

Loads config, wires up the event sink and lab CA, instantiates every enabled
service, and runs them concurrently until interrupted. Adding a new service is
a one-line registry entry plus its module.
"""

from __future__ import annotations

import asyncio
import signal
from typing import Type

from .base import BaseService
from .certs import LabCA
from .config import Config
from .events import EventSink, new_session_id
from .profiles import Profiles
from .services.dns import DnsService
from .services.dns_tcp import DnsTcpService
from .services.ftp import FtpService
from .services.http import HttpService
from .services.imap import ImapService
from .services.irc import IrcService
from .services.ntp import NtpService
from .services.pop3 import Pop3Service
from .services.smtp import SmtpService
from .services.tcp_sink import TcpSinkService
from .services.tftp import TftpService
from .services.telnet import TelnetService
from .services.tls import TlsService
from .services.tls_capture import TlsCaptureService

try:
    from .models.registry import build_provider
    from .models.responder import Responder
    _MODELS_AVAILABLE = True
except Exception:  # requests not installed, etc. — emulator still runs
    _MODELS_AVAILABLE = False

# The registry. New services land here.
REGISTRY: dict[str, Type[BaseService]] = {
    "http": HttpService,
    "dns": DnsService,
    "dns_tcp": DnsTcpService,
    "smtp": SmtpService,
    "pop3": Pop3Service,
    "imap": ImapService,
    "ftp": FtpService,
    "tftp": TftpService,
    "irc": IrcService,
    "ntp": NtpService,
    "telnet": TelnetService,
    "tls": TlsService,
    "tls_capture": TlsCaptureService,
    "tcp_sink": TcpSinkService,
}

# SSH depends on the compiled `asyncssh` package; register it only if importable
# so a missing crypto dependency doesn't take down the rest of the emulator.
try:
    from .services.ssh import SshService
    REGISTRY["ssh"] = SshService
except Exception:  # asyncssh not installed
    pass


class Orchestrator:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.session = cfg.raw.get("session") or new_session_id()
        self.data_dir = cfg.data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.sink = EventSink(
            session=self.session,
            log_path=self.data_dir / "events" / f"{self.session}.jsonl",
            echo=cfg.echo,
        )
        self.ca: LabCA | None = None
        if cfg.tls.get("enabled"):
            self.ca = LabCA(cfg.tls.get("ca_dir", self.data_dir / "ca"))
            self.ca.ensure()

        # Optional model-backed responder (off unless explicitly enabled).
        self.responder = None
        models_cfg = cfg.raw.get("models", {}) or {}
        respond_cfg = models_cfg.get("respond", {}) or {}
        if _MODELS_AVAILABLE and respond_cfg.get("enabled"):
            try:
                provider = build_provider(models_cfg)
                self.responder = Responder(provider, enabled=True)
                print(f"[orch ] model responder ON via '{models_cfg.get('provider','local')}' "
                      f"(generates benign placeholder responses only)")
            except Exception as e:
                print(f"[orch ] responder disabled: {e}")

        self.services: list[BaseService] = []

    def _profiles_for(self, name: str) -> Profiles:
        return Profiles.from_config(self.cfg.service(name), base_dir=self.data_dir)

    def _build(self) -> None:
        for name in self.cfg.enabled_services():
            cls = REGISTRY.get(name)
            if cls is None:
                print(f"[orch ] no implementation for '{name}', skipping")
                continue
            scfg = self.cfg.service(name)
            kwargs = dict(
                cfg=scfg, sink=self.sink,
                bind_address=self.cfg.bind_address,
                data_dir=self.data_dir, tls=self.cfg.tls,
            )
            if name == "http":
                svc = cls(tls_enabled=bool(self.cfg.tls.get("enabled")),
                          ca=self.ca, profiles=self._profiles_for("http"),
                          responder=self.responder, **kwargs)  # type: ignore[call-arg]
            elif name == "dns":
                svc = cls(profiles=self._profiles_for("dns"), **kwargs)  # type: ignore[call-arg]
            elif name == "tls":
                svc = cls(ca=self.ca, **kwargs)  # type: ignore[call-arg]
            else:
                svc = cls(**kwargs)
            self.services.append(svc)

    async def run(self) -> None:
        self._build()
        print(f"[orch ] session {self.session}")
        print(f"[orch ] events -> {self.sink.log_path}")
        started = []
        for svc in self.services:
            try:
                await svc.start()
                port = svc.cfg.get("port") or svc.cfg.get("ports")
                print(f"[orch ] started {svc.name} on {port}")
                started.append(svc)
            except PermissionError:
                print(f"[orch ] {svc.name}: permission denied (privileged port?) — skipping")
            except OSError as e:
                print(f"[orch ] {svc.name}: {e} — skipping")
            except Exception as e:
                print(f"[orch ] {svc.name}: failed to start ({e}) — skipping")

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:
                pass  # Windows
        print("[orch ] running — Ctrl-C to stop")
        await stop.wait()

        print("[orch ] shutting down")
        for svc in started:
            try:
                await svc.stop()
            except Exception:
                pass
        self.sink.close()