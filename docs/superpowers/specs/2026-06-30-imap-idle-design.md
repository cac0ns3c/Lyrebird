<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Design: IMAP IDLE emulation + `imap-idle` detection

**Date:** 2026-06-30
**Status:** Approved (pre-implementation)
**Backlog item:** "IMAP IDLE" (additive)

## Summary

Turn the IMAP service's existing-but-silent IDLE handling into a believable
mailbox-as-C2 channel and pair it with a detection. On IDLE, the emulator pushes
an unsolicited `* 1 EXISTS` after a short delay (simulating the server delivering
"new mail"/tasking) so a long-polling implant DONEs and FETCHes; a benign stub
message answers the FETCH; and every IDLE entry emits an `imap-idle` event keyed
off by a paired Sigma rule. In a malware-analysis lab (no real users), a sample
parking on IMAP IDLE to receive pushed tasking is the mailbox-C2 tell.

## Goals

- Make IDLE a convincing push channel: proactive `* EXISTS`, a FETCH stub, and
  support for the client re-entering IDLE in a loop.
- Emit `imap-idle` telemetry (idle duration, whether a push was sent, how the
  IDLE ended) and pair it with a Sigma rule — closing the detection-pairing gap.

## Non-goals (YAGNI)

- No operator-configurable mailbox contents / per-rule message bodies (static
  benign stub only).
- No real message store, flags, UID handling, or multi-message mailboxes.
- No model-backed FETCH responses.
- No changes to LOGIN/SELECT/CAPABILITY/LOGOUT handling.

## Current state

`src/lyrebird/services/imap.py` already answers `IDLE` with `+ idling`, waits for
`DONE` (60s timeout), and replies — but emits **no event**, so there is no
telemetry and no detection. The only IMAP tag today is `credentials` (from
LOGIN), already declared context in `tests/test_detection_pairing.py`.

## Architecture

Single service file, `src/lyrebird/services/imap.py`. The IDLE branch is reworked
to coordinate a background push with the wait-for-DONE; a new FETCH branch
returns the stub; one `self.emit(...)` per IDLE entry produces the signal. Config
defaults grow two keys; one paired Sigma rule and one test file are added.

### IDLE branch (background-push approach)

Chosen mechanism: a fire-and-forget push task while the main path awaits `DONE`.

1. Reply `+ idling`, record `idle_start = time.monotonic()`.
2. Schedule a background task: `await asyncio.sleep(idle_push_delay)`, then write
   `* 1 EXISTS\r\n`, set a shared `pushed = True`. Wrapped so a write on a closed
   connection cannot crash the handler.
3. `await asyncio.wait_for(reader.readline(), timeout=idle_max)`:
   - line is `DONE` → write `<tag> OK IDLE terminated`, `ended="done"`.
   - empty line (client closed) → `ended="closed"`.
   - non-empty line that is not `DONE` → `ended="other"` (no extra protocol
     response; "other" = a non-empty non-DONE line received during IDLE; added
     in review to fix a telemetry mislabel).
   - `asyncio.TimeoutError` → write `<tag> OK IDLE timeout`, `ended="timeout"`.
4. `finally`: cancel the push task and await its cancellation.
5. Emit one event (below). The enclosing `while` loop continues, so a client may
   FETCH and/or re-enter IDLE; each IDLE entry emits its own event.

Writes do not truly overlap: the main path only writes after `readline()`
returns, and the push writes during that read-wait.

### FETCH branch

```
* 1 FETCH (RFC822 {<N>}\r\n<benign stub bytes>)\r\n
<tag> OK FETCH completed\r\n
```

The stub is a small, inert RFC822 message (headers + a one-line empty-mailbox
body). It is static.

### Telemetry

One event per IDLE entry:

- `event_type="request"`, `transport="tcp"`, src/dst as elsewhere in the handler.
- `tags=["imap-idle"]`
- `request={"idle_seconds": <float, 2 dp>, "pushed": <bool>, "ended": "done"|"timeout"|"closed"|"other"}`
  (`"other"` = a non-empty non-DONE line received during IDLE; added in review
  to fix a telemetry mislabel)
- `summary` e.g. `imap IDLE done after 2.10s pushed=true`

### Detection (paired)

`detections/sigma/imap_idle_c2_wait.yml`

- `logsource: product: lyrebird, service: imap`
- `detection.selection: { service: 'imap', tags|contains: 'imap-idle' }`, `condition: selection`
- `fields: src_ip, request.idle_seconds, request.pushed, request.ended`
- `level: medium`
- `falsepositives`: legitimate mail clients (Thunderbird, Outlook, mobile) all
  use IDLE for push — common outside a single-sample lab.

`imap-idle` is a **signal**: it is paired by this rule and must **NOT** be added
to `CONTEXT_OR_ANALYTIC_TAGS`.

### Config

`DEFAULTS["services"]["imap"]` in `src/lyrebird/config.py`:

```python
"imap": {"enabled": True, "port": 143, "idle_push_delay": 2.0, "idle_max": 60},
```

- `idle_push_delay` (float, seconds): delay before pushing `* 1 EXISTS`. Default 2.0.
- `idle_max` (float, seconds): how long to wait for `DONE` before the IDLE times
  out. Default 60 (preserves current behaviour).

## Error handling / edge cases

- The push task is exception-guarded; a connection dropped mid-push yields
  `ended="closed"` on the main path and a swallowed write error in the task.
- The existing `(asyncio.TimeoutError, ConnectionError)` guard and the `finally`
  close remain.
- A client that never enters IDLE is unaffected (no event, no push).

## Testing

New `tests/test_imap_idle.py`, using the poll-for-artifact + one-event-loop
pattern (IMAP is an `asyncio.start_server` service, so client and server share a
single `asyncio.run`; do NOT use `asyncio.run(start())` + a blocking socket).

- **Push → DONE → FETCH loop:** instantiate with `cfg={"port":0,"idle_push_delay":0.2,"idle_max":2}`;
  drive `LOGIN`, `SELECT`, `IDLE`; read `+ idling`; read the pushed `* 1 EXISTS`;
  send `DONE`; read `OK IDLE terminated`; send `FETCH 1 RFC822`; read the stub;
  poll the JSONL for an `imap-idle` event with `pushed is True`, `ended == "done"`.
- **Timeout path:** with a tiny `idle_max` (e.g. 0.5s) and a larger
  `idle_push_delay`, enter IDLE and never send DONE; assert the emitted event has
  `ended == "timeout"`.
- Registry/instantiation already covered by `tests/test_phase3_services.py`.
- Regenerate `REFERENCE.md` (`scripts/gen_reference.py`) and run the **full**
  suite so the pairing guard and `test_reference.py` both pass.

## Acceptance criteria

- IDLE pushes `* 1 EXISTS` after `idle_push_delay`; FETCH returns the stub; the
  client can loop IDLE.
- Each IDLE entry emits one `imap-idle` event with `idle_seconds`, `pushed`,
  `ended`.
- `imap_idle_c2_wait.yml` exists, lints clean, pairs the tag; pairing guard
  passes without touching `CONTEXT_OR_ANALYTIC_TAGS`.
- `REFERENCE.md` regenerated; full suite green on Python 3.10–3.12.
- Every changed/new file carries the SPDX header.

## Files touched

- `src/lyrebird/services/imap.py` (IDLE rework, FETCH stub, emit `imap-idle`)
- `src/lyrebird/config.py` (imap `idle_push_delay`, `idle_max`)
- `detections/sigma/imap_idle_c2_wait.yml` (new, paired)
- `tests/test_imap_idle.py` (new)
- `REFERENCE.md` (regenerated)
