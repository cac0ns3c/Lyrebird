# SPDX-License-Identifier: GPL-3.0-or-later
"""Integration tests: IMAP IDLE pushes new-mail and emits the imap-idle signal."""
import asyncio
import json
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.events import EventSink  # noqa: E402
from lyrebird.services.imap import ImapService  # noqa: E402


def _wait_for_events(log: Path, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log.exists():
            lines = [l for l in log.read_text().splitlines() if l.strip()]
            if lines:
                return [json.loads(l) for l in lines]
        time.sleep(0.05)
    return []


def test_imap_idle_push_done_emits_signal(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = ImapService(cfg={"port": 0, "idle_push_delay": 0.2, "idle_max": 2},
                      sink=sink, bind_address="127.0.0.1", data_dir=tmp_path, tls={})

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()                       # * OK greeting
        writer.write(b"a1 LOGIN user pass\r\n"); await writer.drain()
        await reader.readline()                       # a1 OK LOGIN
        writer.write(b"a2 SELECT INBOX\r\n"); await writer.drain()
        await reader.readline(); await reader.readline()   # * 0 EXISTS, a2 OK
        writer.write(b"a3 IDLE\r\n"); await writer.drain()
        await reader.readline()                       # + idling
        pushed = await asyncio.wait_for(reader.readline(), timeout=3)  # * 1 EXISTS
        writer.write(b"DONE\r\n"); await writer.drain()
        await reader.readline()                       # a3 OK IDLE terminated
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await svc.stop()
        return pushed

    pushed = asyncio.run(scenario())
    sink.close()
    assert b"EXISTS" in pushed
    events = _wait_for_events(log)
    idle = [e for e in events if "imap-idle" in e.get("tags", [])]
    assert idle, "no imap-idle event emitted"
    assert idle[0]["service"] == "imap"
    assert idle[0]["request"]["pushed"] is True
    assert idle[0]["request"]["ended"] == "done"
    assert idle[0]["request"]["idle_seconds"] >= 0


def test_imap_idle_timeout(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = ImapService(cfg={"port": 0, "idle_push_delay": 5, "idle_max": 0.5},
                      sink=sink, bind_address="127.0.0.1", data_dir=tmp_path, tls={})

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()                       # greeting
        writer.write(b"a1 IDLE\r\n"); await writer.drain()
        await reader.readline()                       # + idling
        await asyncio.wait_for(reader.readline(), timeout=3)  # a1 OK IDLE timeout
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    idle = [e for e in events if "imap-idle" in e.get("tags", [])]
    assert idle, "no imap-idle event emitted"
    assert idle[0]["service"] == "imap"
    assert idle[0]["request"]["ended"] == "timeout"
    assert idle[0]["request"]["pushed"] is False


def test_imap_idle_non_done_line_marks_other(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = ImapService(cfg={"port": 0, "idle_push_delay": 5, "idle_max": 5},
                      sink=sink, bind_address="127.0.0.1", data_dir=tmp_path, tls={})

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()                       # greeting
        writer.write(b"a1 IDLE\r\n"); await writer.drain()
        await reader.readline()                       # + idling
        writer.write(b"NOOP\r\n"); await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    idle = [e for e in events if "imap-idle" in e.get("tags", [])]
    assert idle, "no imap-idle event emitted"
    assert idle[0]["request"]["ended"] == "other"
    assert idle[0]["request"]["pushed"] is False
    assert idle[0]["service"] == "imap"


def test_imap_fetch_returns_stub(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = ImapService(cfg={"port": 0}, sink=sink, bind_address="127.0.0.1",
                      data_dir=tmp_path, tls={})

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()                       # greeting
        writer.write(b"a1 FETCH 1 RFC822\r\n"); await writer.drain()
        data = b""
        for _ in range(12):
            line = await asyncio.wait_for(reader.readline(), timeout=3)
            data += line
            if line.startswith(b"a1 OK"):
                break
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await svc.stop()
        return data

    data = asyncio.run(scenario())
    sink.close()
    assert b"* 1 FETCH (RFC822" in data
    assert b"postmaster@lab.local" in data
    assert b"a1 OK FETCH completed" in data
