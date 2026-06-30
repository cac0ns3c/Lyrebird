# SPDX-License-Identifier: GPL-3.0-or-later
"""Base service contract.

Every emulated service subclasses ``BaseService`` and implements ``start`` /
``stop``. The orchestrator discovers and runs them. Keeping this contract small
is what makes adding FTP, TFTP, POP3, IRC, etc. a drop-in exercise rather than
a rewrite.
"""

from __future__ import annotations

import abc
from pathlib import Path
from typing import Any

from .events import Event, EventSink


class BaseService(abc.ABC):
    #: short identifier, used in config keys and event records
    name: str = "base"

    def __init__(self, cfg: dict[str, Any], sink: EventSink, *,
                 bind_address: str, data_dir: Path, tls: dict[str, Any] | None = None) -> None:
        self.cfg = cfg
        self.sink = sink
        self.bind_address = bind_address
        self.data_dir = Path(data_dir)
        self.tls = tls or {}
        self.capture_dir = self.data_dir / "artifacts" / self.name

    @abc.abstractmethod
    async def start(self) -> None:
        """Bind sockets and begin serving. Must return once listening."""

    @abc.abstractmethod
    async def stop(self) -> None:
        """Tear down cleanly."""

    # helper so subclasses don't repeat boilerplate
    def event(self, **kwargs: Any) -> Event:
        kwargs.setdefault("service", self.name)
        return Event(**kwargs)

    def emit(self, **kwargs: Any) -> None:
        self.sink.emit(self.event(**kwargs))