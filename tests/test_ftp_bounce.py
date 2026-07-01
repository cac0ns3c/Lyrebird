# SPDX-License-Identifier: GPL-3.0-or-later
"""Integration tests: FTP active mode is confined to the client's own IP; a
cross-host PORT/EPRT (FTP bounce) is refused and tagged ftp-bounce."""
import asyncio
import json
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.events import EventSink  # noqa: E402
from lyrebird.services.ftp import FtpService  # noqa: E402


def _wait_for_events(log: Path, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log.exists():
            lines = [l for l in log.read_text().splitlines() if l.strip()]
            if lines:
                return [json.loads(l) for l in lines]
        time.sleep(0.05)
    return []


def _mksvc(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = FtpService(cfg={"port": 0}, sink=sink, bind_address="127.0.0.1",
                     data_dir=tmp_path, tls={})
    return svc, sink, log


def test_ftp_port_bounce_refused_and_detected(tmp_path):
    svc, sink, log = _mksvc(tmp_path)

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()                               # 220
        writer.write(b"PORT 192,0,2,1,17,112\r\n"); await writer.drain()   # foreign host
        await reader.readline()                               # 200
        writer.write(b"STOR evil.bin\r\n"); await writer.drain()
        await reader.readline()                               # 150
        # PROMPT refusal — if the emulator dialed 192.0.2.1 it would hang ~15s;
        # a quick 426 is the proof that no outbound dial happened.
        resp = await asyncio.wait_for(reader.readline(), timeout=5)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await svc.stop()
        return resp

    resp = asyncio.run(scenario())
    sink.close()
    assert b"426" in resp
    events = _wait_for_events(log)
    bounce = [e for e in events if "ftp-bounce" in e.get("tags", [])]
    assert bounce, "no ftp-bounce event"
    assert bounce[0]["request"]["requested_host"] == "192.0.2.1"
    assert bounce[0]["request"]["requested_port"] == 4464
    assert bounce[0]["request"]["command"] == "PORT"
    assert bounce[0]["service"] == "ftp"


def test_ftp_eprt_bounce_refused_and_detected(tmp_path):
    svc, sink, log = _mksvc(tmp_path)

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()                               # 220
        writer.write(b"EPRT |1|203.0.113.9|4444|\r\n"); await writer.drain()
        await reader.readline()                               # 200
        writer.write(b"STOR x\r\n"); await writer.drain()
        await reader.readline()                               # 150
        resp = await asyncio.wait_for(reader.readline(), timeout=5)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await svc.stop()
        return resp

    resp = asyncio.run(scenario())
    sink.close()
    assert b"426" in resp
    events = _wait_for_events(log)
    bounce = [e for e in events if "ftp-bounce" in e.get("tags", [])]
    assert bounce, "no ftp-bounce event"
    assert bounce[0]["request"]["requested_host"] == "203.0.113.9"
    assert bounce[0]["request"]["command"] == "EPRT"


def test_ftp_active_own_ip_preserved(tmp_path):
    # legit active mode: PORT names the client's own IP; the server dials back
    # and captures the upload (no regression, no ftp-bounce).
    svc, sink, log = _mksvc(tmp_path)

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]

        async def data_handler(dr, dw):
            dw.write(b"UPLOAD-PAYLOAD")
            await dw.drain()
            dw.close()

        data_srv = await asyncio.start_server(data_handler, "127.0.0.1", 0)
        dport = data_srv.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()                               # 220
        p1, p2 = dport >> 8, dport & 0xFF
        writer.write(f"PORT 127,0,0,1,{p1},{p2}\r\n".encode()); await writer.drain()
        await reader.readline()                               # 200
        writer.write(b"STOR up.bin\r\n"); await writer.drain()
        await reader.readline()                               # 150
        resp = await asyncio.wait_for(reader.readline(), timeout=5)   # 226
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        data_srv.close()
        await data_srv.wait_closed()
        await svc.stop()
        return resp

    resp = asyncio.run(scenario())
    sink.close()
    assert b"226" in resp
    events = _wait_for_events(log)
    up = [e for e in events if "upload" in e.get("tags", [])]
    assert up, "upload not captured in active mode"
    assert up[0]["request"]["filename"] == "up.bin"
    assert up[0]["request"]["size"] == len(b"UPLOAD-PAYLOAD")
    assert [e for e in events if "ftp-bounce" in e.get("tags", [])] == []


def test_ftp_bounce_then_passive_transfer_works(tmp_path):
    # A cross-host PORT must NOT poison a subsequent legitimate PASV transfer.
    svc, sink, log = _mksvc(tmp_path)

    async def scenario():
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()                               # 220
        writer.write(b"PORT 192,0,2,1,17,112\r\n"); await writer.drain()   # cross-host
        await reader.readline()                               # 200
        writer.write(b"PASV\r\n"); await writer.drain()
        pasv = await reader.readline()                        # 227 (h,h,h,h,p1,p2)
        import re as _re
        m = _re.search(rb"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", pasv)
        nums = [int(x) for x in m.groups()]
        dport = (nums[4] << 8) + nums[5]
        dr, dw = await asyncio.open_connection("127.0.0.1", dport)
        writer.write(b"STOR up.bin\r\n"); await writer.drain()
        await reader.readline()                               # 150
        dw.write(b"PASSIVE-PAYLOAD"); await dw.drain(); dw.close()
        resp = await asyncio.wait_for(reader.readline(), timeout=5)   # must be 226, not 426
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await svc.stop()
        return resp

    resp = asyncio.run(scenario())
    sink.close()
    assert b"226" in resp, f"passive transfer wrongly refused after a bounce PORT: {resp!r}"
    events = _wait_for_events(log)
    up = [e for e in events if "upload" in e.get("tags", [])]
    assert up, "passive upload not captured"
    assert up[0]["request"]["size"] == len(b"PASSIVE-PAYLOAD")
