# SPDX-License-Identifier: GPL-3.0-or-later
"""Integration tests: NTP flags mode-6/7 (control/MONLIST) without amplifying."""
import asyncio
import json
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.events import EventSink  # noqa: E402
from lyrebird.services.ntp import NtpService, parse_mode  # noqa: E402


def _wait_for_events(log: Path, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log.exists():
            lines = [l for l in log.read_text().splitlines() if l.strip()]
            if lines:
                return [json.loads(l) for l in lines]
        time.sleep(0.05)
    return []


def test_parse_mode_unit():
    assert parse_mode(bytes([0x23]) + b"\x00" * 47) == (3, None)   # client mode 3
    assert parse_mode(bytes([0x16, 0x02])) == (6, 2)               # control mode 6, opcode 2
    assert parse_mode(bytes([0x17, 0x00, 0x03, 0x2a])) == (7, 42)  # private mode 7, monlist
    assert parse_mode(b"") == (None, None)
    assert parse_mode(b"\x17") == (7, None)                        # short mode-7, no crash


class _Client(asyncio.DatagramProtocol):
    def __init__(self):
        self.replies = []
        self.done = asyncio.get_running_loop().create_future()

    def datagram_received(self, data, addr):
        self.replies.append(data)
        if not self.done.done():
            self.done.set_result(True)


async def _send(port, payload):
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(
        _Client, remote_addr=("127.0.0.1", port))
    transport.sendto(payload)
    try:
        await asyncio.wait_for(proto.done, timeout=2)
    except asyncio.TimeoutError:
        pass
    transport.close()
    return proto.replies


def _mksvc(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = NtpService(cfg={"port": 0}, sink=sink, bind_address="127.0.0.1",
                     data_dir=tmp_path, tls={})
    return svc, sink, log


def _run(svc, payload):
    async def scenario():
        await svc.start()
        port = svc._transport.get_extra_info("sockname")[1]
        replies = await _send(port, payload)
        await svc.stop()
        return replies
    return asyncio.run(scenario())


def test_ntp_mode3_time_query_no_signal(tmp_path):
    svc, sink, log = _mksvc(tmp_path)
    replies = _run(svc, bytes([0x23]) + b"\x00" * 47)
    sink.close()
    assert replies and len(replies[0]) >= 48        # a time packet came back
    events = _wait_for_events(log)
    assert [e for e in events if "ntp-control-query" in e.get("tags", [])] == []


def test_ntp_mode6_control_flagged(tmp_path):
    svc, sink, log = _mksvc(tmp_path)
    request = bytes([0x16, 0x02]) + b"\x00" * 10
    replies = _run(svc, request)
    sink.close()
    events = _wait_for_events(log)
    cq = [e for e in events if "ntp-control-query" in e.get("tags", [])]
    assert cq, "no ntp-control-query for mode 6"
    assert cq[0]["request"]["mode"] == 6
    assert cq[0]["service"] == "ntp"
    for r in replies:                       # mode 6 must also never amplify
        assert len(r) <= len(request), f"amplified: {len(r)} > {len(request)}"


def test_ntp_mode7_monlist_flagged_and_not_amplified(tmp_path):
    svc, sink, log = _mksvc(tmp_path)
    request = bytes([0x17, 0x00, 0x03, 0x2a]) + b"\x00" * 44   # 48-byte monlist request
    replies = _run(svc, request)
    sink.close()
    events = _wait_for_events(log)
    cq = [e for e in events if "ntp-control-query" in e.get("tags", [])]
    assert cq, "no ntp-control-query for mode 7 monlist"
    assert cq[0]["request"]["mode"] == 7
    assert cq[0]["request"]["request_code"] == 42
    # ANTI-AMPLIFICATION: any reply must be <= the request size
    for r in replies:
        assert len(r) <= len(request), f"amplified: {len(r)} > {len(request)}"
