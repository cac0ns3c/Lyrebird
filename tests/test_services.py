# SPDX-License-Identifier: GPL-3.0-or-later
"""Registry coverage and instantiation for all services."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.orchestrator import REGISTRY  # noqa: E402
from lyrebird.events import EventSink  # noqa: E402


def test_all_expected_services_registered():
    for name in ("http", "dns", "smtp", "pop3", "ftp", "tftp", "irc", "ntp", "tcp_sink"):
        assert name in REGISTRY, f"{name} missing from REGISTRY"


def test_services_instantiate(tmp_path):
    sink = EventSink(session="t", log_path=tmp_path / "e.jsonl", echo=False)
    for name, cls in REGISTRY.items():
        svc = cls(cfg={"ports": [9999]}, sink=sink,
                  bind_address="127.0.0.1", data_dir=tmp_path, tls={})
        assert svc.name
    sink.close()