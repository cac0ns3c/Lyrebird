# CLAUDE.md — project context for Claude Code

Standing context for any Claude Code session in this repo. Read this first.

## What Lyrebird is

A modern internet-services emulation suite for **malware analysis labs** — a
spiritual successor to INetSim. It stands up fake-but-believable network
services (HTTP/DNS/SMTP/IRC/…) so a malware sample detonating in an isolated
sandbox keeps talking, while every interaction is captured as structured JSONL.
Detection telemetry is a first-class output.

## Scope guardrails (do not cross)

Lyrebird is a **defensive** tool. The emulator *responds to* malware; it never
*becomes* the malware.

- ✅ In scope: new service emulators, response profiles, detection analytics,
  Sigma rules, docs, tests, packaging.
- ❌ Out of scope: implants, agents, beacon payloads, real command-and-control,
  or evasion tooling whose purpose is to defeat production defenses.

If a change would make Lyrebird useful for **attacking** rather than
**observing**, it's out of scope. See `SCOPE.md` and `CONTRIBUTING.md`.

## Core principle: detection pairing

Every emulated technique ships with its paired detection in the same change. A
service emits a tag on notable behaviour; a Sigma rule selects on that tag, or a
session analytic covers the statistical case. The emulator and its detections
are versioned together so the signal and the rule never drift apart.

## Layout

```
src/lyrebird/
  events.py        # structured event model + JSONL sink (the schema contract)
  config.py        # YAML loading + defaults
  base.py          # BaseService plugin contract
  certs.py / tls.py# lab CA; ClientHello parsing + JA3/JA4
  orchestrator.py  # loads config, runs enabled services (REGISTRY)
  cli.py           # `python -m lyrebird`
  analyze.py       # optional model-assisted session triage
  beacons.py       # beacon / jitter / channel-rotation analytic
  mimicry.py       # traffic-mimicry / encryption-tell analytic
  services/        # http, dns, dns_tcp, smtp, pop3, imap, ftp, tftp,
                   #   irc, ntp, tls, tls_capture, tcp_sink
  models/          # anthropic, openai, gemini, local, mock + sanitize
detections/sigma/  # Sigma rules, paired per service
scripts/lint_sigma.py
docker/  tests/  config/lyrebird.yaml
docs/              # GitHub Pages documentation site
```

## Commands

```bash
# tests (must be green on 3.10–3.12)
PYTHONPATH=src python -m pytest tests/ -q

# detection-content lint (run if you touched detections/)
PYTHONPATH=src python scripts/lint_sigma.py

# run a lab
python -m lyrebird --config config/lyrebird.yaml
```

## The bar for a change

- Tests pass on Python 3.10–3.12; new code has tests.
- `scripts/lint_sigma.py` passes if detections changed.
- New services are registered in `orchestrator.REGISTRY`, configurable, and emit
  structured events via `self.emit(...)`.
- New emulated behaviour ships with a paired detection (Sigma rule or analytic).
- Every source file carries `# SPDX-License-Identifier: GPL-3.0-or-later`.
- Commits signed off (`git commit -s`, DCO). License: GPL-3.0-or-later.

## Plugin contract (adding a service)

Subclass `BaseService`, implement `start()` / `stop()`, emit events with
`self.emit(...)`, register the class in `orchestrator.REGISTRY`. See
`services/dns.py` for a compact example and `CONTRIBUTING.md` for the full
walkthrough.

## Test conventions

Integration tests that exercise a service's background thread pool must **wait
for the emitted artifact** (poll the JSONL log), never a fixed `sleep`. A fixed
sleep races the handler and goes flaky on loaded CI runners. See
`tests/test_tls_service.py::_wait_for_events` for the pattern.
