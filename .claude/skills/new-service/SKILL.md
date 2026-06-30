---
name: new-service
description: >
  Scaffold a new Lyrebird service emulator with its paired detection in one
  pass — the service module, REGISTRY + import wiring, config defaults, a paired
  Sigma rule, and a poll-for-artifact integration test. Enforces the project's
  core principle (every emulated behaviour ships a detection) by construction.
  Invoke as /new-service <name> [port] [tcp|udp].
argument-hint: <name> [port] [tcp|udp]
disable-model-invocation: true
---

# /new-service — scaffold a service + its paired detection

You are scaffolding a new emulated service for Lyrebird. The whole point of this
skill is that the emulator and its detection land **together** — never scaffold a
service that emits a behavioural tag without also creating the Sigma rule (or
explicitly declaring the tag as context). Read `CLAUDE.md` "Core principle:
detection pairing" before you start.

## Inputs (from the invocation arguments)

Parse from the arguments, asking only for what's missing:
- **name** (required): short lowercase identifier, e.g. `redis`, `rdp`, `mysql`.
  Used as the `name` attribute, REGISTRY key, config key, and event `service`.
- **port** (optional): default listening port. Ask if not given.
- **protocol** (optional): `tcp` (default) or `udp`.
- **What suspicious behaviour does it detect?** (required — this is the paired
  signal). Ask the operator: what does a malware sample *do* against this service
  that is worth flagging? That answer becomes the emitted tag + the Sigma rule.
  Examples: an unusual auth pattern, a known-bad command, an oversized payload, a
  specific banner probe. Pick a kebab-case tag slug for it (e.g. `auth-spray`).

## Pre-flight

1. Refuse names already in `orchestrator.REGISTRY`.
2. Re-read a close existing service as the live template: `services/irc.py` for a
   line-oriented TCP server, `services/dns.py` for UDP. Match its structure,
   error handling, and docstring tone rather than the snippets below verbatim if
   the existing code has drifted.

## Files to create / edit

Create the service, wire it in four places, add the rule, add the test. Every
new file's **first line** must be `# SPDX-License-Identifier: GPL-3.0-or-later`
(a PostToolUse hook will flag it otherwise).

### 1. `src/lyrebird/services/<name>.py` (TCP template)

```python
# SPDX-License-Identifier: GPL-3.0-or-later
"""<Name> emulation service.

<One or two sentences: what real service this imitates, what an analyst learns
by watching a sample talk to it, and that it only mirrors+records — never issues
commands of its own.>
"""
from __future__ import annotations

import asyncio
from typing import Any

from ..base import BaseService


class <Name>Service(BaseService):
    name = "<name>"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        port = int(self.cfg.get("port", <PORT>))
        try:
            while True:
                raw = await asyncio.wait_for(reader.readline(), timeout=120)
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if not line:
                    continue

                # --- emulate just enough protocol to keep the sample talking ---
                # writer.write(b"...response...\r\n")

                # --- detection: tag the suspicious behaviour you defined ---
                tags = ["<name>"]  # service-context tag
                if <suspicious condition>:
                    tags.append("<signal-tag>")  # <- paired with the Sigma rule

                self.emit(
                    transport="tcp", src_ip=peer[0], src_port=peer[1],
                    dst_port=port, event_type="request",
                    summary=f"<name> {line[:80]}",
                    request={"line": line},
                    tags=tags,
                )
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, host=self.bind_address,
            port=int(self.cfg.get("port", <PORT>)))

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
```

For **UDP**, follow `services/dns.py`: a `asyncio.DatagramProtocol` subclass +
`loop.create_datagram_endpoint(...)` in `start()`, closing the transport in
`stop()`.

### 2. `src/lyrebird/orchestrator.py` — register in two spots

- Add the import alongside the others (keep alphabetical):
  `from .services.<name> import <Name>Service`
- Add the REGISTRY entry: `"<name>": <Name>Service,`
- The generic `else: svc = cls(**kwargs)` branch in `_build()` already covers a
  plain service. Only add an `elif name == "<name>":` branch if the service needs
  extra constructor kwargs (like http/dns/tls do).

### 3. `src/lyrebird/config.py` — add to `DEFAULTS["services"]`

```python
"<name>": {"enabled": True, "port": <PORT>},
```

(Optionally add a documented block to `config/lyrebird.yaml` too.)

### 4. `detections/sigma/<name>_<signal>.yml` — the paired rule

```yaml
# SPDX-License-Identifier: GPL-3.0-or-later
title: <Human-readable: what the signal means> (Observed By Emulator)
id: <generate a fresh uuid4>
status: experimental
description: >
  <What the Lyrebird <name> service observes and why it is suspicious. End with
  the explicit pairing note:> Pair: services/<name>.py tags such connections
  '<signal-tag>'.
author: Lyrebird
date: <YYYY/MM/DD today>
logsource:
  product: lyrebird
  service: <name>
detection:
  selection:
    service: '<name>'
    tags|contains: '<signal-tag>'
  condition: selection
fields:
  - src_ip
  - request.line
falsepositives:
  - <at least one honest real-world false-positive scenario>
level: <low|medium|high>
```

The linter requires `title` + `logsource` + `detection`. The pairing guard
(`tests/test_detection_pairing.py`) requires that `<signal-tag>` is selected by
this rule. The service-context tag (`<name>`) is *not* a signal — add it to
`CONTEXT_OR_ANALYTIC_TAGS` in that test file with a short reason, e.g.
`"<name>",  # service-name context`.

### 5. `tests/test_<name>_service.py` — integration test

Use the **poll-for-artifact** pattern (never a fixed sleep — see
`tests/test_tls_service.py::_wait_for_events`). The service runs on a background
loop, so poll the JSONL log until the event appears.

```python
# SPDX-License-Identifier: GPL-3.0-or-later
"""Integration test: the <name> service serves a session and emits the
'<signal-tag>' detection tag on the suspicious behaviour."""
import asyncio
import json
import socket
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.events import EventSink  # noqa: E402
from lyrebird.orchestrator import REGISTRY  # noqa: E402
from lyrebird.services.<name> import <Name>Service  # noqa: E402


def _wait_for_events(log: Path, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log.exists():
            lines = [l for l in log.read_text().splitlines() if l.strip()]
            if lines:
                return [json.loads(l) for l in lines]
        time.sleep(0.05)
    return []


def test_<name>_registered():
    assert "<name>" in REGISTRY


def test_<name>_emits_signal_tag(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = <Name>Service(cfg={"port": 0}, sink=sink, bind_address="127.0.0.1",
                        data_dir=tmp_path, tls={})
    asyncio.run(svc.start())
    port = svc._server.sockets[0].getsockname()[1]
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=5)
        c.sendall(b"<bytes that trigger the suspicious behaviour>\r\n")
        c.close()
        events = _wait_for_events(log)
    finally:
        asyncio.run(svc.stop())
        sink.close()
    assert events, "no event was flushed"
    assert any("<signal-tag>" in e.get("tags", []) for e in events)
```

## Verify before reporting done

Run all three and make them green:

```bash
PYTHONPATH=src python -m pytest tests/test_<name>_service.py tests/test_detection_pairing.py tests/test_services.py -q
PYTHONPATH=src python scripts/lint_sigma.py
PYTHONPATH=src python -m lyrebird --help   # import smoke
```

If the pairing guard fails, it names the exact tag — either it needs the Sigma
rule (signal) or a `CONTEXT_OR_ANALYTIC_TAGS` entry with a reason (context).
Then summarize: the files created, the tag→rule pair, and the green checks. Do
not commit unless the operator asks.

## Scope guardrail

Lyrebird only *responds to and records* malware — it never *becomes* it. If the
requested service's purpose is to attack or evade production defenses rather than
to be observed in a lab, stop and flag it against `SCOPE.md`.
