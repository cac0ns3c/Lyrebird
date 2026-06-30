# SPDX-License-Identifier: GPL-3.0-or-later
"""Structured event model.

Every emulated service emits normalized events through this module. The JSON
shape here is the contract that the rest of the system keys off: log files,
SIEM ingestion, the optional analysis layer, and the Sigma detections all
assume this schema. Change it deliberately.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class Artifact:
    """A file or blob captured from a client (uploaded payload, mail body, etc.)."""

    kind: str            # "upload", "mail", "dns_query", "binary", ...
    path: str            # where it was stored on disk
    sha256: str
    size: int
    note: str = ""

    @classmethod
    def from_bytes(cls, kind: str, data: bytes, store_dir: Path, note: str = "") -> "Artifact":
        digest = hashlib.sha256(data).hexdigest()
        store_dir.mkdir(parents=True, exist_ok=True)
        dest = store_dir / f"{digest[:16]}.bin"
        if not dest.exists():
            dest.write_bytes(data)
        return cls(kind=kind, path=str(dest), sha256=digest, size=len(data), note=note)


@dataclass
class Event:
    """A single observed interaction with an emulated service."""

    service: str                 # "http", "dns", "smtp", ...
    transport: str               # "tcp" | "udp"
    src_ip: str
    src_port: int
    dst_port: int
    event_type: str              # "connection" | "request" | "auth" | "capture"
    summary: str = ""
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    artifacts: list[Artifact] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    # populated automatically
    schema: str = SCHEMA_VERSION
    ts: str = field(default_factory=_utcnow)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    session: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)


class EventSink:
    """Thread-safe writer that fans events out to newline-delimited JSON.

    Services call ``sink.emit(event)`` from any thread or event loop. Output is
    one JSON object per line (JSONL), which is trivially tailable into a SIEM.
    """

    def __init__(self, session: str, log_path: Path, echo: bool = True) -> None:
        self.session = session
        self.log_path = Path(log_path)
        self.echo = echo
        self._lock = threading.Lock()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.log_path.open("a", encoding="utf-8")

    def emit(self, event: Event) -> None:
        event.session = self.session
        line = event.to_json()
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            if self.echo:
                print(f"[{event.service:>5}] {event.src_ip}:{event.src_port} "
                      f"{event.event_type} :: {event.summary}", flush=True)

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.close()
            except Exception:
                pass


def new_session_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:6]