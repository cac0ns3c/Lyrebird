<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Design: FTP active-mode hardening + `ftp-bounce` detection

**Date:** 2026-07-01
**Status:** Approved (pre-implementation)
**Backlog item:** "active-mode edge cases" (additive)

## Summary

The FTP service handles active-mode `PORT`/`EPRT` by dialing an outbound data
connection to whatever host:port the client named — with no restriction. In a
malware-analysis lab a sample can therefore send `PORT <external-host>` and make
the emulator connect out to an arbitrary third party: an FTP-bounce / data-
redirect that both breaks lab isolation (egress) and is itself a detectable
tell. This change **confines the active-mode data connection to the client's own
control-channel source IP**: legitimate active mode (client asks the server to
connect back to itself) keeps working and keeps capturing uploads, while a
`PORT`/`EPRT` naming a *different* host is refused — no outbound socket — and
emits a paired `ftp-bounce` signal. The stale "passive only" docstring is
corrected.

This is the same egress line SCOPE.md draws for realistic DNS mode: capture the
intent, perform nothing.

## Goals

- Never open an FTP data socket to a host other than the client's control-channel
  source IP (close the active-mode egress / FTP-bounce hole).
- Preserve legitimate active-mode upload capture (dial-back to the client's own
  IP is unchanged).
- Emit `ftp-bounce` telemetry for a cross-host `PORT`/`EPRT` and pair it with a
  Sigma rule.
- Fix the FTP module docstring to reflect that active mode is implemented and
  confined.

## Non-goals (YAGNI)

- No FTPS/TLS data channel.
- No config toggle — the confinement is a security fix, always on.
- No capturing of the *bounced* payload (that would require the egress we are
  closing).
- No change to passive mode, LOGIN, STOR-capture, RETR/LIST placeholders.

## Current state

`src/lyrebird/services/ftp.py` (`_FtpSession`): `PORT`/`EPRT` parse a host:port
into `self.active_addr`; `get_data_streams()` does
`asyncio.open_connection(*self.active_addr)` to that address with **no check**
against `self.peer` (the control-channel source). The module docstring claims
"Passive mode only … active-mode PORT is a documented next addition", which is
stale — active mode is implemented. FTP already emits `credentials` (context)
and `upload` (paired by `ftp_tftp_upload_exfil.yml`).

## Architecture

Single service file, `src/lyrebird/services/ftp.py`.

### The confinement check

`_FtpSession` already holds `self.peer` (control-channel source) and derives
`active_addr` from `PORT`/`EPRT`. Add one comparison of the requested host to
`self.peer[0]`:

- On `PORT`/`EPRT`, parse the requested `(ip, port)`. Reply `200` either way
  (keep the sample engaged — the detection already captured the intent).
  - **`ip == self.peer[0]`** (legit active mode): set `self.active_addr =
    (ip, port)` as today. `self.active_bounce = False`.
  - **`ip != self.peer[0]`** (bounce / redirect): do NOT store a dialable
    `active_addr`; set `self.active_bounce = True` and record the requested
    `(ip, port)`; emit the `ftp-bounce` signal (below).
- `get_data_streams()`:
  - if `self.active_bounce`: raise a sentinel (e.g. `_BounceRefused`) — never
    dials; the data command (`STOR`/`RETR`/`LIST`) catches it and replies
    `426 transfer failed` (the existing generic data-failure reply — no new handler code). Reset the flag afterwards.
  - elif `self.active_addr` (own IP): dial back as today.
  - else: passive (unchanged).

The single outbound `asyncio.open_connection(...)` is thus only ever reached
with a host equal to `self.peer[0]` — the sample itself, inside the sandbox.

### Scope guardrail (non-negotiable — per SCOPE.md)

The emulator never opens a data socket to a host `!= self.peer[0]`. A `PORT`/
`EPRT` to any other host is logged and refused, never dialed. Asserted by a test
(a bounce target on TEST-NET must produce a prompt `426`, not a dial-out hang).

### Telemetry

Add one signal tag; `credentials`/`upload` unchanged.

- **`ftp-bounce`** (SIGNAL) — emitted once when a cross-host `PORT`/`EPRT` is
  parsed. `event_type="request"`, `transport="tcp"`, src/dst as elsewhere in the
  session, `request={"command": "PORT"|"EPRT", "requested_host": str,
  "requested_port": int, "control_src": str}`, summary e.g.
  `ftp PORT bounce → 203.0.113.5:4444 (control src 10.13.37.9)`.

### Detection (paired)

`detections/sigma/ftp_bounce.yml`:

- `logsource: product: lyrebird, service: ftp`
- `detection.selection: { service: 'ftp', tags|contains: 'ftp-bounce' }`,
  `condition: selection`
- `fields: src_ip, request.requested_host, request.requested_port, request.command`
- `level: high`
- `falsepositives`: a legitimate FTP client only ever names its own address in
  `PORT`/`EPRT`; a cross-host target outside a proxying setup is the bounce tell.

`ftp-bounce` is a **signal** (paired by this rule) and must **NOT** be added to
`CONTEXT_OR_ANALYTIC_TAGS`.

## Config

None. The confinement is always on.

## Error handling / edge cases

- A malformed `PORT`/`EPRT` still replies `501` as today (unchanged).
- The bounce refusal resets `self.active_bounce`/`active_addr` after each data
  command so a later passive transfer in the same session works normally.
- If the sample sends `PORT` (own IP) then never transfers, no `426` occurs and
  no bounce event fires (only cross-host PORT/EPRT emits).
- Legit active dial-back keeps its existing 15s timeout; a bounce never reaches
  the dial, so it returns immediately.

## Testing

Extend the FTP tests (new `tests/test_ftp_bounce.py`, poll-for-artifact + one
event loop via `asyncio.open_connection` against the control channel):

- **Legit active mode preserved:** client sends `PORT` with its own IP and a
  listening data port, then `STOR`; assert the upload is still captured as an
  `upload` artifact (no regression).
- **Bounce refused + detected:** client sends `PORT` naming `192.0.2.1` (TEST-
  NET, non-routable) then `STOR`; assert (a) an `ftp-bounce` event with
  `requested_host == "192.0.2.1"` and `command == "PORT"`, and (b) the `STOR`
  gets a prompt `426` — the transfer returns quickly rather than hanging on a
  ~15s outbound dial (this is the proof no egress occurred).
- **EPRT variant:** same bounce assertion for an `EPRT` naming a foreign host.
- Regenerate `REFERENCE.md` and run the full suite + `scripts/lint_sigma.py`.

## Acceptance criteria

- Active-mode data connection is only ever dialed to the client's own source IP;
  a cross-host `PORT`/`EPRT` is refused (`426`) and never dialed.
- Legit active-mode uploads still captured; passive mode unchanged.
- `ftp-bounce` emitted for cross-host `PORT`/`EPRT`; `ftp_bounce.yml` exists,
  lints clean, pairs the tag; pairing guard green without touching
  `CONTEXT_OR_ANALYTIC_TAGS`.
- Docstring corrected. `REFERENCE.md` regenerated; full suite green; SPDX header
  on all new files; commits DCO-signed + `Co-Authored-By` trailer.

## Files touched

- `src/lyrebird/services/ftp.py` (confinement check, `ftp-bounce` emit, docstring)
- `detections/sigma/ftp_bounce.yml` (new, paired)
- `tests/test_ftp_bounce.py` (new)
- `REFERENCE.md` (regenerated)
- `requirements.txt` / `pyproject.toml` — **no dep change** (stdlib only here)
