# SPDX-License-Identifier: GPL-3.0-or-later
"""Integration tests: SSH honeypot captures credentials, brute-force, and shell."""
import asyncio
import json
import time
from pathlib import Path
import sys

import asyncssh

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.events import EventSink  # noqa: E402
from lyrebird.services.ssh import SshService  # noqa: E402


def _wait_for_events(log: Path, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log.exists():
            lines = [l for l in log.read_text().splitlines() if l.strip()]
            if lines:
                return [json.loads(l) for l in lines]
        time.sleep(0.05)
    return []


def _client(passwords):
    class _C(asyncssh.SSHClient):
        def __init__(self):
            self._pw = list(passwords)
        def password_auth_requested(self):
            return self._pw.pop(0) if self._pw else None
    return _C


def test_ssh_denies_and_logs_credentials(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = SshService(cfg={"port": 0, "accept_after": 99}, sink=sink,
                     bind_address="127.0.0.1", data_dir=tmp_path, tls={})

    async def scenario():
        await svc.start()
        port = svc._server.get_port()
        try:
            await asyncssh.connect("127.0.0.1", port, username="root",
                                   known_hosts=None, client_factory=_client(["hunter2"]))
        except asyncssh.PermissionDenied:
            pass
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    creds = [e for e in events if "credentials" in e.get("tags", [])]
    assert creds, "no credentials event emitted"
    assert creds[0]["request"]["user"] == "root"
    assert creds[0]["request"]["password"] == "hunter2"
    assert creds[0]["request"]["accepted"] is False
    assert creds[0]["service"] == "ssh"


def test_ssh_host_key_persists(tmp_path):
    sink = EventSink(session="t", log_path=tmp_path / "e.jsonl", echo=False)

    async def start_stop():
        svc = SshService(cfg={"port": 0}, sink=sink, bind_address="127.0.0.1",
                         data_dir=tmp_path, tls={})
        await svc.start()
        await svc.stop()

    asyncio.run(start_stop())
    key_path = tmp_path / "ssh" / "host_key"
    assert key_path.exists()
    first = key_path.read_bytes()
    asyncio.run(start_stop())
    assert key_path.read_bytes() == first  # reused, not regenerated
    sink.close()
