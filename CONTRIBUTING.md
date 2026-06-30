# Contributing to Lyrebird

Thanks for helping build a modern, open replacement for the aging malware-lab
service emulators. This guide covers setup, the bar for changes, and the most
common contribution — adding a new emulated service.

## Scope and intent

Lyrebird is a **defensive** tool: it emulates benign internet services to observe
malware in an isolated lab, and pairs every emulated technique with detection
content. Contributions must stay on that side of the line:

- ✅ new service emulators, response profiles, detection analytics, Sigma rules,
  docs, tests, packaging.
- ❌ implants, real command-and-control, or evasion tooling whose purpose is to
  defeat production defenses. The emulator *responds to* malware; it never *is*
  the malware.

If a change would make Lyrebird useful for attacking rather than observing,
it's out of scope.

## Setup

```bash
git clone <your-fork>
cd lyrebird
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest
PYTHONPATH=src python -m pytest tests/ -q       # should be all green
PYTHONPATH=src python scripts/lint_sigma.py     # detection content lint
```

## The bar for a PR

- Tests pass on Python 3.10–3.12 (`pytest`), and you've added tests for new code.
- `scripts/lint_sigma.py` passes if you touched detections.
- New services are registered, configurable, and emit structured events.
- New emulated behaviour ships with a paired detection (Sigma rule or analytic).
- Every source file carries `# SPDX-License-Identifier: GPL-3.0-or-later`.
- Sign your commits off (`git commit -s`) — we use the Developer Certificate of
  Origin. By contributing you agree your work is licensed GPL-3.0-or-later.

## Adding a service (walkthrough)

Say you want to add an IMAP emulator. The plugin contract is small.

**1. Implement it** in `src/lyrebird/services/imap.py`, subclassing `BaseService`:

```python
# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
from typing import Any
from ..base import BaseService

class ImapService(BaseService):
    name = "imap"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._server = None

    async def _handle(self, reader, writer):
        peer = writer.get_extra_info("peername") or ("?", 0)
        writer.write(b"* OK Lab IMAP ready\r\n")
        await writer.drain()
        # ... read commands, emit events, respond ...
        self.emit(transport="tcp", src_ip=peer[0], src_port=peer[1],
                  dst_port=int(self.cfg.get("port", 143)),
                  event_type="auth", summary="imap login",
                  request={"user": "..."}, tags=["credentials"])

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, host=self.bind_address, port=int(self.cfg.get("port", 143)))

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
```

Use `self.emit(...)` for every observed interaction, and store any captured bytes
as an `Artifact` (see `services/ftp.py` for upload capture, `services/dns.py` for
a compact UDP example).

**2. Register it** in `src/lyrebird/orchestrator.py`:

```python
from .services.imap import ImapService
REGISTRY = { ..., "imap": ImapService }
```

**3. Add a config default** in `src/lyrebird/config.py` under `services`:

```python
"imap": {"enabled": True, "port": 143},
```

and document it in `config/lyrebird.yaml`.

**4. Pair a detection.** Add a Sigma rule in `detections/sigma/` keyed off the
events you emit (`logsource.product: lyrebird`), or extend an analytic.

**5. Add a test** in `tests/` — at minimum that the service is in `REGISTRY` and
instantiates (see `tests/test_services.py`); ideally a runtime check.

That's the whole loop. The event schema in `events.py` is the stable contract
everything keys off — don't break its shape without a discussion.

## Adding detection content only

Drop a `.yml` in `detections/sigma/` (single rule or a correlation rule), run the
linter, and reference the event fields it keys off in the description so analysts
can trace the pairing back to the emitting service.

## Reporting issues

Use the issue tracker. For anything that looks like a security concern in
Lyrebird itself, note it privately rather than in a public issue.
