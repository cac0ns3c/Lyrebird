<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# NTP mode-6/7 (control/MONLIST) Detection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse the NTP request mode and flag mode 6 (ntpq control) / mode 7 (private — MONLIST) with a paired `ntp-control-query` signal, replying minimally (never amplifying); mode-3 time-sync and `faketime` unchanged.

**Architecture:** All in `services/ntp.py`: a pure `parse_mode(data)` helper + a `handle_datagram(data, addr)` router; mode 6/7 → emit `ntp-control-query` + a fixed reply capped at the request size (anti-amplification); else → the existing `build_reply` time path. One paired Sigma rule + one test file.

**Tech Stack:** Python 3.10–3.12, stdlib `asyncio`/`struct`, pytest. **No new dependency.**

## Global Constraints

- Run tests with `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest`.
- SPDX header on every new file. Commit with plain `git commit -s` + a second `-m` co-author trailer (`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`); no inline `-c` override.
- **No dependency change** (stdlib). Do NOT touch requirements.txt / pyproject.toml.
- `ntp-control-query` is a **signal** — paired in Task 2, NOT added to `CONTEXT_OR_ANALYTIC_TAGS`. `faketime` unchanged.
- **TASK-ORDERING:** Task 1 emits `ntp-control-query` whose rule comes in Task 2, so `tests/test_detection_pairing.py` is RED by design; Task 1 runs the targeted file only (`tests/test_ntp_control.py`). Task 2 makes it green; Task 3 runs the full suite.
- Verified (spiked): `parse_mode` returns mode3→(3,None), mode6(0x16,op)→(6,op), mode7 monlist(0x17,_,_,0x2a)→(7,42); empty→(None,None); short-mode7→(7,None). NTP request first byte low 3 bits = mode.

---

### Task 1: Parse mode + emit `ntp-control-query` (never amplify)

**Files:**
- Modify: `src/lyrebird/services/ntp.py`
- Test: `tests/test_ntp_control.py` (create)

**Interfaces:**
- Produces: module `parse_mode(data: bytes) -> tuple[int|None, int|None]`; `NtpService.handle_datagram(data, addr) -> bytes|None`. Emits an `ntp-control-query` event `tags=["ntp-control-query"]`, `request={"mode": int, "request_code": int|None}` for mode 6/7, replying a fixed payload ≤ request length; mode-3 unchanged.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_ntp_control.py`:

```python
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
        self.done = asyncio.get_event_loop().create_future()
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
    _run(svc, bytes([0x16, 0x02]) + b"\x00" * 10)
    sink.close()
    events = _wait_for_events(log)
    cq = [e for e in events if "ntp-control-query" in e.get("tags", [])]
    assert cq, "no ntp-control-query for mode 6"
    assert cq[0]["request"]["mode"] == 6
    assert cq[0]["service"] == "ntp"


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
```

- [ ] **Step 2: Run to verify failure**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_ntp_control.py -v`
Expected: FAIL — `ImportError: cannot import name 'parse_mode'` (and the mode-6/7 tests fail: the current service emits no `ntp-control-query` and replies with a full time packet to every datagram, so the mode-7 anti-amplification assert would also fail).

- [ ] **Step 3: Add `parse_mode`, the control reply, and route in `handle_datagram`**

In `src/lyrebird/services/ntp.py`, after the `NTP_DELTA = ...` line add:

```python

# A fixed, deliberately tiny reply to a control/private (mode 6/7) probe. Capped
# to the request length at send time so the emulator NEVER amplifies — it can be
# a reflection TARGET in a lab but must not become a reflector.
_CONTROL_REPLY = b"\x00\x00\x00\x00"


def parse_mode(data: bytes) -> "tuple[int | None, int | None]":
    """Return (mode, request_code) for an NTP request. mode = low 3 bits of the
    first byte; request_code is the mode-7 opcode (data[3], e.g. 42 = MONLIST) or
    the mode-6 control opcode (data[1] & 0x1F). Both None for a too-short/empty
    packet."""
    if not data:
        return None, None
    mode = data[0] & 0x07
    if mode == 7:
        return mode, (data[3] if len(data) > 3 else None)
    if mode == 6:
        return mode, (data[1] & 0x1F if len(data) > 1 else None)
    return mode, None
```

Then in `_NtpProtocol.datagram_received`, pass `data` to the service:

```python
    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        reply = self.service.handle_datagram(data, addr)
        if self.transport and reply is not None:
            self.transport.sendto(reply, addr)
```

Then add this method to `NtpService` (e.g. just above `build_reply`):

```python
    def handle_datagram(self, data: bytes, addr: tuple[str, int]) -> bytes | None:
        mode, req_code = parse_mode(data)
        if mode in (6, 7):
            note = f" (request_code={req_code})" if req_code is not None else ""
            self.emit(
                transport="udp", src_ip=addr[0], src_port=addr[1],
                dst_port=int(self.cfg.get("port", 123)), event_type="request",
                summary=f"ntp mode-{mode} control query{note}",
                request={"mode": mode, "request_code": req_code},
                tags=["ntp-control-query"])
            # never amplify: reply is fixed and capped at the request length
            return _CONTROL_REPLY[:len(data)]
        return self.build_reply(addr)
```

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_ntp_control.py -v`
Expected: PASS (4 passed). Do NOT run the full suite — pairing guard RED until Task 2.

- [ ] **Step 5: Commit**

```bash
git add src/lyrebird/services/ntp.py tests/test_ntp_control.py
git commit -s -m "NTP: flag mode-6/7 control/MONLIST queries (ntp-control-query); never amplify" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Paired Sigma rule

**Files:**
- Create: `detections/sigma/ntp_control_query.yml`

- [ ] **Step 1: Confirm the guard is RED**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_detection_pairing.py -v`
Expected: FAIL — `ntp.py -> ['ntp-control-query']` emitted/unpaired.

- [ ] **Step 2: Create the rule**

Create `detections/sigma/ntp_control_query.yml`:

```yaml
# SPDX-License-Identifier: GPL-3.0-or-later
title: NTP Control/Private Query By Sample (mode 6/7 — MONLIST Amplification Recon)
id: 4d9c1f83-72a6-4e05-b1d8-6f3a0e2c7b95
status: experimental
description: >
  The Lyrebird NTP emulator flags a request in mode 6 (ntpq control) or mode 7
  (private — including MONLIST, opcode 42, the classic NTP DDoS-reflection
  vector) as 'ntp-control-query'. In a single-sample lab there is no monitoring
  infrastructure, so a sample sending a control/private NTP query — rather than a
  time sync — is a reflection/amplification-recon tell. The emulator logs the
  probe but never sends an amplified response.
  Pair: services/ntp.py tags such datagrams 'ntp-control-query' (mode,
  request_code recorded).
author: Lyrebird
date: 2026/07/01
logsource:
  product: lyrebird
  service: ntp
detection:
  selection:
    service: 'ntp'
    tags|contains: 'ntp-control-query'
  condition: selection
fields:
  - src_ip
  - request.mode
  - request.request_code
falsepositives:
  - Legitimate NTP monitoring (ntpq, mode 6) outside a single-sample analysis lab
level: high
```

- [ ] **Step 3: Run the guard + lint**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_detection_pairing.py -v && PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/lint_sigma.py`
Expected: PASS (do NOT touch `CONTEXT_OR_ANALYTIC_TAGS`); `Sigma lint OK`.

- [ ] **Step 4: Commit**

```bash
git add detections/sigma/ntp_control_query.yml
git commit -s -m "Pair ntp-control-query signal with a Sigma rule" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Regenerate REFERENCE.md + full suite

**Files:**
- Modify: `REFERENCE.md` (generated)

- [ ] **Step 1: Regenerate**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/gen_reference.py`
Expected: `wrote REFERENCE.md`; `git status --short` shows only `REFERENCE.md` (a new `ntp-control-query` row). If anything else changed, STOP and report.

- [ ] **Step 2: Full suite + lint**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/ -q && PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/lint_sigma.py`
Expected: all PASS (incl. `test_reference.py`, `test_detection_pairing.py`, new NTP tests); `Sigma lint OK`.

- [ ] **Step 3: Commit**

```bash
git add REFERENCE.md
git commit -s -m "Regenerate REFERENCE.md for the ntp-control-query rule" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-review

**Spec coverage:** parse_mode + mode-6/7 flag + never-amplify (Task 1); paired rule (Task 2); REFERENCE + full suite (Task 3). ✓
**Placeholder scan:** complete code every step; concrete UUID. ✓
**Type consistency:** `request` keys `mode`/`request_code` identical across emit (Task 1), tests, and rule `fields` (Task 2); `parse_mode` signature matches its call + unit test. ✓
**Task-ordering:** Task 1 emits the unpaired signal (guard RED), targeted tests only; Task 2 pairs it green; Task 3 full suite. ✓
