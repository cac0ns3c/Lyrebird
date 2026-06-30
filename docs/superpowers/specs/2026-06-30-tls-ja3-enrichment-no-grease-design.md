<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Design: Packet-layer JA3/JA4 enrichment + `no-grease` signal

**Date:** 2026-06-30
**Status:** Approved (pre-implementation)
**Backlog item:** "packet-layer JA3 enrichment" (additive)

## Summary

Enrich Lyrebird's TLS ClientHello fingerprinting with fields the parser already
extracts but never surfaces, add the raw JA4 (`ja4_r`) variant, and derive one
new behavioural signal — `no-grease` — that fires when a TLS-1.3-capable client
sends a ClientHello with **no** GREASE values. Modern browsers inject GREASE
(RFC 8701); a 1.3-capable client that omits it is a high-signal "not a real
browser" tell of a library/malware TLS stack. The signal ships with a paired
Sigma rule, satisfying the core detection-pairing principle.

## Goals

- Surface richer, already-parsed ClientHello detail for triage and threat-intel
  matching: `groups`, `sig_algs`, `supported_versions`, `alpn`, `ja4_r`,
  `grease_present`.
- Add the `no-grease` behavioural signal, gated to TLS-1.3-capable clients to
  keep false positives low.
- Pair the signal with a Sigma rule, versioned in the same change.

## Non-goals (YAGNI)

- No fingerprint-vs-User-Agent mismatch detection (needs a browser-JA4 baseline).
- No JA4+ suite methods (JA4S/JA4H/...) — FoxIO-licensed.
- No changes to the existing `tls_known_bad_ja3_ja4.yml` blocklist rule.
- No new service; this enriches the two existing TLS paths.

## Architecture

All logic anchors on the shared chokepoint `src/lyrebird/tls.py::fingerprint()`,
already called by both `services/tls_capture.py` (passive tap) and
`services/tls.py` (terminating HTTPS emulator). Three units change:

1. **`src/lyrebird/tls.py`** — parser-derived helpers + enriched `fingerprint()`
   output. This is the testable core; the gating decision lives here once.
2. **`services/tls_capture.py` and `services/tls.py`** — emit the new fields and
   append the `no-grease` tag when signalled. No re-derivation in the services.
3. **detections + docs** — one paired Sigma rule; regenerated `REFERENCE.md`.

## Detailed design

### `tls.py` core

The `ClientHello` dataclass already stores raw `ciphers` / `extensions` /
`groups` / `supported_versions` **including** GREASE (GREASE is only stripped
later, inside the JA3/JA4 computations via `_no_grease`). Add three pure
functions:

- `grease_present(ch) -> bool` — any GREASE value across
  `ciphers + extensions + groups + supported_versions`.
- `offers_tls13(ch) -> bool` — `0x0304 in ch.supported_versions`.
- `ja4_raw(ch) -> str` — the FoxIO `ja4_r` variant: the same `ja4_a` prefix as
  `ja4()`, but with the cipher and extension/sig-alg lists left **raw**
  (comma-joined hex) instead of SHA-256-truncated. Implemented by refactoring
  `ja4()` to compute its two pre-hash strings once and reuse them for both the
  hashed (`ja4`) and raw (`ja4_r`) forms.

`fingerprint()` gains these output keys (existing keys unchanged):

| key | value |
|-----|-------|
| `grease_present` | bool — did the hello carry any GREASE |
| `no_grease_signal` | `(not grease_present) and offers_tls13` |
| `ja4_r` | raw JA4 string |
| `groups` | GREASE-stripped supported groups (full list) |
| `sig_algs` | GREASE-stripped signature algorithms (full list) |
| `supported_versions` | GREASE-stripped supported versions (full list) |

`alpn` is already returned. The surfaced lists are GREASE-stripped for
cleanliness; `grease_present` reflects the raw presence before stripping.

### Services

Both services, after `fp = fingerprint(hello)` (when `fp` is not `None`):

- `if fp["no_grease_signal"]: tags.append("no-grease")`
- add `grease_present`, `ja4_r`, `groups`, `sig_algs`, `supported_versions`
  (full lists) into the event `request` dict alongside the existing
  `ja3`/`ja4`/`sni`.

The signal is identical on both paths because the decision is computed in
`tls.py`.

### Detection pairing

`no-grease` is a **signal**, so it gets a paired rule and must **not** be added
to `CONTEXT_OR_ANALYTIC_TAGS` in `tests/test_detection_pairing.py`. New rule:

`detections/sigma/tls_no_grease_modern_client.yml`

- Selects on `tags|contains: 'no-grease'` (the tag is emitted by **both** TLS
  services, so the rule keys on the tag, not a single `service`).
- `logsource: product: lyrebird`.
- `fields`: `src_ip`, `request.ja3`, `request.ja4`, `request.ja4_r`,
  `request.sni`, `request.grease_present`.
- `level: medium`.
- `falsepositives`: old/embedded TLS stacks, non-browser libraries that don't
  GREASE, pinned enterprise clients.

The enrichment fields are plain context (not tags) and need no pairing.

### Error handling / edge cases

- `fingerprint()` still returns `None` on unparseable bytes; services already
  handle `None`.
- The `no-grease` gate requires `0x0304` in `supported_versions`, which a real
  TLS-1.3 client must send via the supported_versions extension. So a
  TLS-1.2-only, legacy, or unparseable hello cannot fire the signal —
  conservative by construction.

## Testing

- **Unit (pure, deterministic)** — new `tests/test_tls_grease.py` constructs
  `ClientHello` objects and asserts:
  - GREASE + TLS-1.3 → `no_grease_signal` is `False`.
  - no-GREASE + TLS-1.3 offered → `no_grease_signal` is `True`.
  - no-GREASE + TLS-1.2 only → `no_grease_signal` is `False` (gated out).
  - `ja4_r` keeps the `ja4_a` prefix and is not the hashed form.
  - enrichment fields (`groups`, `sig_algs`, `supported_versions`, `alpn`) are
    populated.
- **Integration (poll-for-artifact)** — craft a raw no-GREASE TLS-1.3
  ClientHello byte vector, send it to `tls_capture`, and poll the JSONL for the
  `no-grease` tag, following `tests/test_tls_service.py::_wait_for_events`
  (never a fixed sleep).
- **Guards** — regenerate `REFERENCE.md` via `scripts/gen_reference.py` and run
  the **full** suite so the pairing guard and `test_reference.py` both pass.

## Acceptance criteria

- `fingerprint()` returns the six new keys; `no_grease_signal` follows the gated
  rule.
- Both TLS services emit the enrichment fields and the `no-grease` tag when
  signalled.
- `tls_no_grease_modern_client.yml` exists, lints clean, and the pairing guard
  passes without adding `no-grease` to `CONTEXT_OR_ANALYTIC_TAGS`.
- `REFERENCE.md` regenerated; full test suite green on the supported Python
  versions.
- Every changed/new file carries the SPDX header.

## Files touched

- `src/lyrebird/tls.py` (parser helpers, enriched `fingerprint()`, `ja4_raw`)
- `src/lyrebird/services/tls_capture.py`, `src/lyrebird/services/tls.py` (emit)
- `detections/sigma/tls_no_grease_modern_client.yml` (new, paired)
- `tests/test_tls_grease.py` (new), plus a `tls_capture` integration assertion
- `REFERENCE.md` (regenerated)
