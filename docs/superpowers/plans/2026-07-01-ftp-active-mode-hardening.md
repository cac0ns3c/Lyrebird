<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# FTP Active-Mode Hardening + `ftp-bounce` Detection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Confine the FTP active-mode data connection to the client's own control-channel source IP so a `PORT`/`EPRT` naming a different host (FTP bounce / egress) is refused and tagged `ftp-bounce`, paired with a Sigma rule.

**Architecture:** All behaviour lives in `src/lyrebird/services/ftp.py`. A `_set_active(ip, port, command, dst_port)` helper does the own-IP confinement + `ftp-bounce` emit for both `PORT` and `EPRT`; `get_data_streams()` raises a `_BounceRefused(ConnectionError)` sentinel when a cross-host target was flagged — caught by the existing `except Exception` in the STOR/RETR/LIST handlers, which reply `426` promptly (no dial, no new handler code). One paired Sigma rule and one test file are added; the stale docstring is corrected.

**Tech Stack:** Python 3.10–3.12, stdlib `asyncio`, pytest, PyYAML (lint/guard). **No new dependency.**

## Global Constraints

- Run tests with `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest` (plain `python`/`python3` lack pytest).
- Every new source/YAML file starts with `# SPDX-License-Identifier: GPL-3.0-or-later`.
- Commit with **plain** `git commit -s` PLUS the co-author trailer as a second `-m` (do NOT use the inline `git -c user.name=… -c user.email=…` override — it trips the harness classifier). Template:
  `git commit -s -m "<subject>" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"`
- **No dependency change** — this is stdlib only. Do NOT touch `requirements.txt` or `pyproject.toml`.
- `ftp-bounce` is a **signal** tag — paired by the Sigma rule in Task 2 and must **NOT** be added to `CONTEXT_OR_ANALYTIC_TAGS` in `tests/test_detection_pairing.py`. `credentials`/`upload` are unchanged.
- **TASK-ORDERING:** Task 1 begins emitting `ftp-bounce`, whose paired rule does not exist until Task 2 — so `tests/test_detection_pairing.py` is **RED by design** between them. Task 1 runs the TARGETED test file only (`tests/test_ftp_bounce.py`), NOT the full suite. Task 2 makes the guard green; Task 3 runs the full suite.
- `ftp` is an `asyncio.start_server` service: integration tests MUST drive client and server in **one** event loop (`asyncio.open_connection` inside a single `asyncio.run`) and poll the JSONL log for events (never a fixed sleep).

---

### Task 1: Confine active mode + emit `ftp-bounce` (+ docstring fix)

**Files:**
- Modify: `src/lyrebird/services/ftp.py` (docstring; add `_BounceRefused`; `_FtpSession.__init__` `active_bounce`; add `_set_active`; rework `get_data_streams`, `PORT`, `EPRT`)
- Test: `tests/test_ftp_bounce.py` (create)

**Interfaces:**
- Produces: an `ftp-bounce` event with `tags=["ftp-bounce"]` and `request={"command": "PORT"|"EPRT", "requested_host": str, "requested_port": int, "control_src": str}` when a `PORT`/`EPRT` names a host `!= self.peer[0]`. A cross-host active transfer is refused (`426`); legit active mode (own IP) and passive mode are unchanged.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_ftp_bounce.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_ftp_bounce.py -v`
Expected: FAIL — the bounce tests time out or hang (the current code dials `192.0.2.1`, so `STOR` waits ~15s then errors; no `ftp-bounce` event exists), and `test_ftp_active_own_ip_preserved` may pass already (legit path unchanged). At minimum the two bounce tests fail.

- [ ] **Step 3: Fix the docstring**

In `src/lyrebird/services/ftp.py`, replace the module docstring (lines 2-11) with:

```python
"""FTP emulation service.

Emulates an FTP server's control channel and a data channel so that a sample
logging in and uploading (STOR) — e.g. exfiltrating collected data or dropping a
secondary file — has its upload captured as an artifact. RETR/LIST return
placeholders. Credentials and commands are logged.

Both passive and active (PORT/EPRT) modes are supported. The active-mode data
connection is confined to the client's own control-channel source IP: a PORT/
EPRT naming a different host (FTP bounce / data-redirect) is refused, never
dialed, and tagged 'ftp-bounce' — the emulator never opens a data socket to a
third party.
"""
```

- [ ] **Step 4: Add the `_BounceRefused` sentinel**

In `src/lyrebird/services/ftp.py`, immediately after the `_FAKE_LISTING = ...` line (~line 21), add:

```python


class _BounceRefused(ConnectionError):
    """Raised when a PORT/EPRT names a host other than the client itself, so the
    data connection is refused instead of dialed (FTP-bounce guard). Being a
    ConnectionError, it is caught by the existing `except Exception` in the
    STOR/RETR/LIST handlers, which reply 426."""
```

- [ ] **Step 5: Add the `active_bounce` flag**

In `_FtpSession.__init__`, add a line right after the `self.active_addr` line:

```python
        self.active_addr: Optional[tuple[str, int]] = None   # set by PORT (active mode)
        self.active_bounce = False   # PORT/EPRT named a non-client host → refuse
```

- [ ] **Step 6: Add `_set_active` and rework `get_data_streams`**

In `src/lyrebird/services/ftp.py`, replace the whole `get_data_streams` method with the version below **and** add the new `_set_active` method right before it:

```python
    def _set_active(self, ip: str, dport: int, command: str, dst_port: int) -> None:
        """Store the active-mode data target, confined to the client's own IP.
        A cross-host target (FTP bounce / redirect) is NOT stored for dialing —
        it is flagged and reported so the transfer is refused, never dialed."""
        if ip == self.peer[0]:
            self.active_addr = (ip, dport)
            self.active_bounce = False
        else:
            self.active_addr = None
            self.active_bounce = True
            self.svc.emit(
                transport="tcp", src_ip=self.peer[0], src_port=self.peer[1],
                dst_port=dst_port, event_type="request",
                summary=f"ftp {command} bounce -> {ip}:{dport} (control src {self.peer[0]})",
                request={"command": command, "requested_host": ip,
                         "requested_port": dport, "control_src": self.peer[0]},
                tags=["ftp-bounce"])

    async def get_data_streams(self) -> tuple:
        """Return (reader, writer) for the data channel. Active mode dials back
        ONLY to the client's own IP; a flagged bounce target is refused, never
        dialed (raises _BounceRefused, which the data handlers turn into 426)."""
        if self.active_bounce:
            self.active_bounce = False
            self.active_addr = None
            raise _BounceRefused("active-mode target is not the client host")
        if self.active_addr is not None:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(*self.active_addr), timeout=15)
            self.active_addr = None
            return r, w
        return await asyncio.wait_for(self._data_conn, timeout=15)
```

- [ ] **Step 7: Rework the `PORT` and `EPRT` handlers to confine via `_set_active`**

In `_FtpSession.run()`, replace the `PORT` branch:

```python
                elif cmd == "PORT":
                    # active mode: client gives h1,h2,h3,h4,p1,p2 to dial back to
                    try:
                        nums = [int(x) for x in arg.split(",")]
                        ip = ".".join(str(n) for n in nums[:4])
                        dport = (nums[4] << 8) + nums[5]
                        self._set_active(ip, dport, "PORT", port)
                        self.reply("200 PORT command successful")
                    except (ValueError, IndexError):
                        self.reply("501 bad PORT")
```

and the `EPRT` branch:

```python
                elif cmd == "EPRT":
                    # extended active: |proto|addr|port|
                    try:
                        fields = arg.split("|")
                        self._set_active(fields[2], int(fields[3]), "EPRT", port)
                        self.reply("200 EPRT command successful")
                    except (ValueError, IndexError):
                        self.reply("501 bad EPRT")
```

(The `STOR`/`RETR`/`LIST` handlers are unchanged — their existing `except Exception: self.reply("426 …")` already catches `_BounceRefused`. `port` in these branches is the control-port local computed at the top of `run()`.)

- [ ] **Step 8: Run the targeted tests to verify they pass**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_ftp_bounce.py -v`
Expected: PASS (3 passed). Do NOT run the full suite — `test_detection_pairing.py` is RED by design until Task 2.

- [ ] **Step 9: Commit**

```bash
git add src/lyrebird/services/ftp.py tests/test_ftp_bounce.py
git commit -s -m "FTP: confine active-mode data connection to the client IP; emit ftp-bounce" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Paired Sigma rule

**Files:**
- Create: `detections/sigma/ftp_bounce.yml`

**Interfaces:**
- Consumes: the `ftp-bounce` tag (Task 1). Makes the pairing guard green.

- [ ] **Step 1: Confirm the guard is currently RED**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_detection_pairing.py -v`
Expected: FAIL — reports `ftp.py -> ['ftp-bounce']` as emitted/unpaired. (Expected interim state from Task 1.)

- [ ] **Step 2: Create the paired rule**

Create `detections/sigma/ftp_bounce.yml`:

```yaml
# SPDX-License-Identifier: GPL-3.0-or-later
title: FTP Bounce / Active-Mode Data Redirect By Sample
id: 6b1f0a3c-2d84-4e91-b7a5-9c0f13e6d472
status: experimental
description: >
  The Lyrebird FTP emulator confines active-mode (PORT/EPRT) data connections to
  the client's own control-channel IP. A PORT/EPRT naming a different host is an
  FTP-bounce / data-redirect attempt (isolation break / egress) — the emulator
  refuses to dial it and tags the connection 'ftp-bounce'. In a single-sample
  lab a legitimate client only ever names its own address, so this is a strong
  tell.
  Pair: services/ftp.py tags such connections 'ftp-bounce' (command,
  requested_host, requested_port, control_src recorded).
author: Lyrebird
date: 2026/07/01
logsource:
  product: lyrebird
  service: ftp
detection:
  selection:
    service: 'ftp'
    tags|contains: 'ftp-bounce'
  condition: selection
fields:
  - src_ip
  - request.requested_host
  - request.requested_port
  - request.command
falsepositives:
  - A legitimate FTP client behind an unusual proxy/relay naming a non-self
    address in PORT/EPRT (rare outside a single-sample analysis lab)
level: high
```

- [ ] **Step 3: Run the guard + lint to verify pass**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_detection_pairing.py -v && PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/lint_sigma.py`
Expected: PASS — pairing guard green (do NOT touch `CONTEXT_OR_ANALYTIC_TAGS`); `Sigma lint OK`.

- [ ] **Step 4: Commit**

```bash
git add detections/sigma/ftp_bounce.yml
git commit -s -m "Pair ftp-bounce signal with a Sigma rule" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Regenerate `REFERENCE.md` and verify the full suite

**Files:**
- Modify: `REFERENCE.md` (generated)

- [ ] **Step 1: Regenerate the reference**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/gen_reference.py`
Expected: `wrote REFERENCE.md`. Then `git status --short` — only `REFERENCE.md` should be modified (a new `ftp-bounce` rule row). If anything else changed, STOP and report.

- [ ] **Step 2: Run the FULL suite + lint (the drift guards)**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/ -q && PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/lint_sigma.py`
Expected: all tests PASS (including `test_reference.py`, `test_detection_pairing.py`, and the 3 new FTP tests); `Sigma lint OK`.

- [ ] **Step 3: Commit**

```bash
git add REFERENCE.md
git commit -s -m "Regenerate REFERENCE.md for the ftp-bounce rule" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-review

**Spec coverage:**
- Confine active-mode dial-back to the client's own IP; refuse cross-host → Task 1 (`_set_active` + `get_data_streams` `_BounceRefused`). ✓
- Preserve legit active-mode upload capture → Task 1 (`test_ftp_active_own_ip_preserved`). ✓
- Emit `ftp-bounce` with `{command, requested_host, requested_port, control_src}` → Task 1 (`_set_active`). ✓
- Paired rule, `service: ftp` + `tags|contains: 'ftp-bounce'`, level high, not in `CONTEXT_OR_ANALYTIC_TAGS` → Task 2. ✓
- Docstring corrected → Task 1 Step 3. ✓
- No dependency change → Global Constraints (stdlib only). ✓
- Regenerate REFERENCE.md + full suite → Task 3. ✓
- One-event-loop + poll-for-artifact tests; PORT bounce, EPRT bounce, legit-active → Task 1. ✓
- SPDX headers on new test + YAML → included in their code. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code; the Sigma `id` is a concrete UUID. ✓

**Type consistency:** `request` keys `command`/`requested_host`/`requested_port`/`control_src` are identical across the emit (Task 1), the test assertions (Task 1), and the rule `fields` (Task 2). `_set_active(ip, dport, command, dst_port)` signature matches its two call sites. `_BounceRefused` is raised in `get_data_streams` and caught by the unchanged `except Exception`. ✓

**Task-ordering guard:** Task 1 emits `ftp-bounce` (guard RED by design) and runs targeted tests only; Task 2 pairs it green; Task 3 runs the full suite. Explicit in Global Constraints and each task's run step. ✓
