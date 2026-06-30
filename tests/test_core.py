# SPDX-License-Identifier: GPL-3.0-or-later
"""Smoke tests for the core: event schema round-trips and config defaults."""

import json
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.events import Event, EventSink, Artifact, new_session_id  # noqa: E402
from lyrebird.config import Config  # noqa: E402


def test_event_serializes_to_valid_json():
    ev = Event(
        service="dns", transport="udp", src_ip="10.0.0.5", src_port=5000,
        dst_port=53, event_type="request", summary="A evil.example",
        request={"qname": "evil.example.", "qtype": "A"},
    )
    parsed = json.loads(ev.to_json())
    assert parsed["service"] == "dns"
    assert parsed["schema"] == "1.0"
    assert parsed["request"]["qtype"] == "A"
    assert "event_id" in parsed and "ts" in parsed


def test_sink_writes_jsonl(tmp_path):
    log = tmp_path / "events.jsonl"
    sink = EventSink(session="s1", log_path=log, echo=False)
    sink.emit(Event(service="http", transport="tcp", src_ip="1.2.3.4",
                    src_port=4444, dst_port=80, event_type="request", summary="GET /"))
    sink.close()
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 1
    obj = json.loads(lines[0])
    assert obj["session"] == "s1"
    assert obj["service"] == "http"


def test_artifact_hashes_and_stores(tmp_path):
    art = Artifact.from_bytes("upload", b"hello world", tmp_path)
    assert art.size == 11
    assert len(art.sha256) == 64
    assert Path(art.path).exists()


def test_config_defaults_apply_with_no_file():
    cfg = Config.load(None)
    assert cfg.bind_address == "0.0.0.0"
    assert "http" in cfg.enabled_services()
    assert cfg.service("dns")["port"] == 53


def test_config_user_override_merges(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("services:\n  http:\n    port: 8888\n  dns:\n    enabled: false\n")
    cfg = Config.load(p)
    assert cfg.service("http")["port"] == 8888
    assert "dns" not in cfg.enabled_services()
    # untouched defaults still present
    assert cfg.service("smtp")["port"] == 25


def test_session_id_unique():
    assert new_session_id() != new_session_id()


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call(["pytest", "-q", __file__]))