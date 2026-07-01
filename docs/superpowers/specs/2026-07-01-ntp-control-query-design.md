<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Design: NTP mode-6/7 (control / MONLIST) detection

**Date:** 2026-07-01
**Status:** Approved (pre-implementation)
**Backlog item:** more detections on existing services — NTP amplification

## Summary

The NTP service replies to any datagram with a time packet and never inspects
the request mode, so it can't distinguish normal time-sync (mode 3) from
**mode 6 (ntpq control)** or **mode 7 (private — including `MONLIST`, opcode 42,
the classic NTP DDoS-amplification / reflection vector)**. This change parses the
NTP mode, flags mode 6/7 with a paired `ntp-control-query` signal, and — as a
hard scope guardrail — replies to such probes **minimally, never amplifying**
(response ≤ request size; it never builds a monlist list). Normal time-sync and
the `faketime` feature are unchanged. No new dependency (stdlib).

## Goals

- Parse the NTP request mode; emit `ntp-control-query` for mode 6 or 7 with the
  mode + request code (mode-7 opcode `42` = monlist), paired with a Sigma rule.
- Never amplify: the emulator's response to a mode-6/7 probe is ≤ the request
  size — capture the reflection/recon intent without becoming a reflector.

## Non-goals (YAGNI)

- No real MONLIST responder, no ntpq control-protocol emulation, no amplification.
- No new config, no dependency, no change to the mode-3 time path or `faketime`.

## Current state

`src/lyrebird/services/ntp.py`: `_NtpProtocol.datagram_received(data, addr)`
calls `build_reply(addr)` (which does NOT receive `data`) and sends a mode-4
time packet, emitting `faketime` (context) only when a delta is configured. No
mode inspection, no behavioural signal. `faketime` is declared context in
`tests/test_detection_pairing.py`.

## Architecture

Single service file `src/lyrebird/services/ntp.py`.

- `datagram_received(data, addr)` passes `data` to the service. A module-level
  pure helper `parse_mode(data) -> tuple[int|None, int|None]` returns
  `(mode, request_code)`:
  - `mode = data[0] & 0x07` (None for empty data).
  - mode 7 → `request_code = data[3]` if present (e.g. 42 = monlist).
  - mode 6 → `request_code = data[1] & 0x1F` if present (control opcode).
  - else → `request_code = None`.
- The service routes on mode:
  - **mode 6 or 7:** emit the `ntp-control-query` signal (below) and send a
    minimal non-amplifying reply — a short fixed byte string no larger than the
    request (realistic for a monlist-disabled server). No time packet, no list.
  - **anything else (mode 3, malformed, etc.):** the existing `build_reply`
    time path + existing `faketime` emit, unchanged.

### Scope guardrail (non-negotiable — per SCOPE.md)

The emulator NEVER sends an amplified response: the mode-6/7 reply is a fixed
small payload whose length is ≤ the request length, so the amplification factor
is ≤ 1. It never constructs a MONLIST list. Asserted by a test.

### Telemetry

- **`ntp-control-query`** (SIGNAL) — emitted once per mode-6/7 datagram:
  `event_type="request"`, `transport="udp"`, `src`/`dst` as elsewhere,
  `request={"mode": int, "request_code": int|None}`, summary e.g.
  `ntp mode-7 control query (request_code=42 monlist)`.
- `faketime` (context) and the mode-3 time reply are unchanged.

### Detection (paired)

`detections/sigma/ntp_control_query.yml`:

- `logsource: product: lyrebird, service: ntp`
- `detection.selection: { service: 'ntp', tags|contains: 'ntp-control-query' }`,
  `condition: selection`
- `fields: src_ip, request.mode, request.request_code`
- `level: high`
- `falsepositives`: legitimate monitoring uses ntpq (mode 6); a mode-6/7 query in
  a single-sample analysis lab (no monitoring infra) is the reflection/recon tell.

`ntp-control-query` is a **signal** (paired) and must NOT be added to
`CONTEXT_OR_ANALYTIC_TAGS`.

## Config

None. Always on.

## Error handling / edge cases

- Empty or short (<1 byte) datagram: `parse_mode` returns `(None, None)` → routed
  to the default (time) path or ignored; no crash / no index error.
- A mode-7/6 packet too short for the request-code offset: `request_code` is
  `None`, still emits `ntp-control-query` with the mode.

## Testing

New `tests/test_ntp_control.py` (UDP; drive via a datagram socket / endpoint;
poll-for-artifact on the JSONL log):

- **mode 3 time query:** send a mode-3 client packet → a time reply is returned,
  and NO `ntp-control-query` event (normal path unchanged).
- **mode 6 (ntpq):** send `\x16\x02…` → `ntp-control-query` with `mode==6`.
- **mode 7 MONLIST:** send `\x17\x00\x03\x2a…` (opcode 42) → `ntp-control-query`
  with `mode==7`, `request_code==42`, AND the returned reply length ≤ the request
  length (the anti-amplification proof).
- **short/empty datagram:** does not crash; no spurious signal.
- `parse_mode` covered by a direct unit test.
- Regenerate `REFERENCE.md`; run the full suite + `scripts/lint_sigma.py`.

## Acceptance criteria

- NTP parses the mode; mode 6/7 emits `ntp-control-query` (mode + request_code)
  and replies minimally (≤ request size — never amplifies); mode-3/faketime
  unchanged.
- `ntp_control_query.yml` exists, lints clean, pairs the tag; pairing guard green
  without touching `CONTEXT_OR_ANALYTIC_TAGS`.
- `REFERENCE.md` regenerated; full suite green; SPDX headers on new files;
  commits DCO-signed + `Co-Authored-By`; NO dependency change (stdlib).

## Files touched

- `src/lyrebird/services/ntp.py` (parse_mode, mode routing, ntp-control-query emit)
- `detections/sigma/ntp_control_query.yml` (new, paired)
- `tests/test_ntp_control.py` (new)
- `REFERENCE.md` (regenerated)
