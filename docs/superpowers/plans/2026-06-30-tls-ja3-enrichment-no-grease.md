<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# TLS JA3/JA4 Enrichment + `no-grease` Signal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface richer parsed ClientHello fields (`groups`, `sig_algs`, `supported_versions`, `ja4_r`, `grease_present`) from the TLS fingerprinter and add a `no-grease` behavioural signal — gated to TLS-1.3-capable clients — with a paired Sigma rule.

**Architecture:** All derived logic lives once in the shared chokepoint `src/lyrebird/tls.py::fingerprint()`, which both `services/tls_capture.py` and `services/tls.py` already call. The services only read `fp["no_grease_signal"]` and merge enrichment fields into their event. One paired Sigma rule keys on the `no-grease` tag.

**Tech Stack:** Python 3.10–3.12, stdlib only (`hashlib`, `asyncio`), pytest, PyYAML (lint/guard).

## Global Constraints

- Tests must pass on Python 3.10–3.12. Run tests with `PYTHONPATH=src python -m pytest`.
- Every new/modified source file starts with `# SPDX-License-Identifier: GPL-3.0-or-later` (YAML/Sigma files too).
- Commit with DCO sign-off using the project identity:
  `git -c user.name='cac0ns3c' -c user.email='11958671+cac0ns3c@users.noreply.github.com' commit -s -m "..."`.
- `no-grease` is a **signal** tag — it gets the paired Sigma rule below and must **NOT** be added to `CONTEXT_OR_ANALYTIC_TAGS` in `tests/test_detection_pairing.py`.
- After detection/schema changes, regenerate `REFERENCE.md` (`PYTHONPATH=src python scripts/gen_reference.py`) and run the **FULL** suite (it includes the pairing guard and `test_reference.py`), not just targeted files.
- `tls_capture` is an `asyncio.start_server` service: its integration test MUST drive client and server in **one** event loop (`asyncio.open_connection` inside a single `asyncio.run(...)`). Do NOT use `asyncio.run(svc.start())` + a blocking socket — the loop closes and the server stops serving.
- Sigma content lint must pass: `PYTHONPATH=src python scripts/lint_sigma.py`.

---

## Test helper used by several tasks

Add this ClientHello byte-builder to `tests/test_tls_grease.py` (Task 3 creates the file). It assembles a minimal, valid ClientHello that `parse_client_hello` accepts.

```python
def build_client_hello(ciphers: list[int], extensions: list[tuple[int, bytes]]) -> bytes:
    """Minimal raw ClientHello handshake message (starts with 0x01)."""
    body = b"\x03\x03"                                   # legacy_version TLS1.2
    body += b"\x00" * 32                                 # random
    body += b"\x00"                                      # session_id length 0
    cs = b"".join(c.to_bytes(2, "big") for c in ciphers)
    body += len(cs).to_bytes(2, "big") + cs             # cipher_suites
    body += b"\x01\x00"                                  # compression: len 1, null
    ext = b"".join(et.to_bytes(2, "big") + len(ed).to_bytes(2, "big") + ed
                   for et, ed in extensions)
    body += len(ext).to_bytes(2, "big") + ext           # extensions block
    return b"\x01" + len(body).to_bytes(3, "big") + body


def supported_versions_ext(versions: list[int]) -> tuple[int, bytes]:
    """Build a supported_versions extension (0x002b)."""
    payload = b"".join(v.to_bytes(2, "big") for v in versions)
    return (0x002b, bytes([len(payload)]) + payload)
```

Reference vectors (no GREASE in any field):
- TLS-1.3 hello: `build_client_hello([0x1301, 0x1302], [supported_versions_ext([0x0304])])`
- TLS-1.2-only hello: `build_client_hello([0x1301], [supported_versions_ext([0x0303])])`
- With-GREASE TLS-1.3 hello: `build_client_hello([0x0a0a, 0x1301], [(0x1a1a, b""), supported_versions_ext([0x0304])])`

---

### Task 1: GREASE + TLS-1.3 helpers in `tls.py`

**Files:**
- Modify: `src/lyrebird/tls.py` (add two pure functions after `_no_grease`, ~line 124)
- Test: `tests/test_tls_grease.py` (create)

**Interfaces:**
- Produces: `grease_present(ch: ClientHello) -> bool`, `offers_tls13(ch: ClientHello) -> bool`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_tls_grease.py`:

```python
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for GREASE / TLS-1.3 detection and JA4 raw enrichment."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.tls import ClientHello, grease_present, offers_tls13  # noqa: E402


def test_grease_present_true_when_grease_in_ciphers():
    ch = ClientHello(ciphers=[0x0a0a, 0x1301])
    assert grease_present(ch) is True


def test_grease_present_false_without_grease():
    ch = ClientHello(ciphers=[0x1301], extensions=[0x002b], supported_versions=[0x0304])
    assert grease_present(ch) is False


def test_offers_tls13_true():
    ch = ClientHello(supported_versions=[0x0303, 0x0304])
    assert offers_tls13(ch) is True


def test_offers_tls13_false_when_only_12():
    ch = ClientHello(supported_versions=[0x0303])
    assert offers_tls13(ch) is False
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `PYTHONPATH=src python -m pytest tests/test_tls_grease.py -v`
Expected: FAIL — `ImportError: cannot import name 'grease_present'`.

- [ ] **Step 3: Implement the helpers**

In `src/lyrebird/tls.py`, immediately after `_no_grease` (line ~124), add:

```python
def grease_present(ch: ClientHello) -> bool:
    """True if the ClientHello carried any GREASE value (RFC 8701)."""
    return any(v in GREASE for v in
               (*ch.ciphers, *ch.extensions, *ch.groups,
                *ch.sig_algs, *ch.supported_versions))


def offers_tls13(ch: ClientHello) -> bool:
    """True if the client advertised TLS 1.3 via supported_versions."""
    return 0x0304 in ch.supported_versions
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `PYTHONPATH=src python -m pytest tests/test_tls_grease.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add src/lyrebird/tls.py tests/test_tls_grease.py
git -c user.name='cac0ns3c' -c user.email='11958671+cac0ns3c@users.noreply.github.com' commit -s -m "Add GREASE/TLS-1.3 ClientHello helpers"
```

---

### Task 2: `ja4_raw` (raw JA4) via shared `_ja4_parts`

**Files:**
- Modify: `src/lyrebird/tls.py` (refactor `ja4`, add `_ja4_parts` and `ja4_raw`, lines ~146-175)
- Test: `tests/test_tls_grease.py` (append)

**Interfaces:**
- Consumes: existing `ja4(ch, protocol="t") -> str` output must stay identical.
- Produces: `ja4_raw(ch: ClientHello, protocol: str = "t") -> str`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_tls_grease.py`:

```python
from lyrebird.tls import ja4, ja4_raw  # noqa: E402


def _sample_ch():
    return ClientHello(legacy_version=0x0303, ciphers=[0x1302, 0x1301],
                       extensions=[0x0000, 0x002b, 0x000d],
                       sig_algs=[0x0403], supported_versions=[0x0304])


def test_ja4_unchanged_shape():
    # JA4 is three underscore-separated parts; b and c are 12-hex-char hashes.
    parts = ja4(_sample_ch()).split("_")
    assert len(parts) == 3
    assert len(parts[1]) == 12 and len(parts[2]) == 12


def test_ja4_raw_shares_prefix_and_is_unhashed():
    ch = _sample_ch()
    raw = ja4_raw(ch)
    assert raw.split("_")[0] == ja4(ch).split("_")[0]          # same ja4_a prefix
    # raw cipher list is the literal sorted hex, not a 12-char hash
    assert raw.split("_")[1] == "1301,1302"
```

- [ ] **Step 2: Run to verify failure**

Run: `PYTHONPATH=src python -m pytest tests/test_tls_grease.py -k ja4 -v`
Expected: FAIL — `cannot import name 'ja4_raw'`.

- [ ] **Step 3: Refactor `ja4` and add `_ja4_parts` + `ja4_raw`**

Replace the existing `ja4` function (lines ~146-175) with:

```python
def _ja4_parts(ch: ClientHello, protocol: str = "t") -> tuple[str, str, str]:
    """Compute the three JA4 components before b/c are hashed: (ja4_a, b_raw, c_raw)."""
    ciphers = _no_grease(ch.ciphers)
    exts = _no_grease(ch.extensions)

    sv = _no_grease(ch.supported_versions)
    ver_num = max(sv) if sv else ch.legacy_version
    ver = _JA4_VER.get(ver_num, "00")

    sni = "d" if EXT_SNI in ch.extensions else "i"
    cc = min(len(ciphers), 99)
    ec = min(len(exts), 99)
    if ch.alpn:
        a = ch.alpn[0]
        alpn = (a[0] + a[-1]) if a else "00"
    else:
        alpn = "00"
    ja4_a = f"{protocol}{ver}{sni}{cc:02d}{ec:02d}{alpn}"

    b_raw = ",".join(f"{c:04x}" for c in sorted(ciphers))

    ext_for_c = sorted(e for e in exts if e not in (EXT_SNI, EXT_ALPN))
    c_raw = ",".join(f"{e:04x}" for e in ext_for_c)
    if ch.sig_algs:
        c_raw += "_" + ",".join(f"{a:04x}" for a in ch.sig_algs)
    return ja4_a, b_raw, c_raw


def ja4(ch: ClientHello, protocol: str = "t") -> str:
    """Return the JA4 fingerprint (FoxIO, BSD-3-Clause algorithm)."""
    a, b_raw, c_raw = _ja4_parts(ch, protocol)
    return f"{a}_{_sha12(b_raw)}_{_sha12(c_raw)}"


def ja4_raw(ch: ClientHello, protocol: str = "t") -> str:
    """Return the raw JA4 (ja4_r): same prefix, b/c lists left unhashed."""
    a, b_raw, c_raw = _ja4_parts(ch, protocol)
    return f"{a}_{b_raw}_{c_raw}"
```

- [ ] **Step 4: Run to verify pass (and JA4 output unchanged)**

Run: `PYTHONPATH=src python -m pytest tests/test_tls_grease.py tests/test_tls_service.py -v`
Expected: PASS — the existing TLS service test confirms `ja4()` output is unchanged.

- [ ] **Step 5: Commit**

```bash
git add src/lyrebird/tls.py tests/test_tls_grease.py
git -c user.name='cac0ns3c' -c user.email='11958671+cac0ns3c@users.noreply.github.com' commit -s -m "Add raw JA4 (ja4_r) via shared _ja4_parts"
```

---

### Task 3: Enrich `fingerprint()` output

**Files:**
- Modify: `src/lyrebird/tls.py` (`fingerprint`, lines ~178-189; add `fp_event_fields` after it)
- Test: `tests/test_tls_grease.py` (append; add the builder helpers from "Test helper" above)

**Interfaces:**
- Consumes: `grease_present`, `offers_tls13`, `ja4_raw` (Tasks 1-2).
- Produces: enriched `fingerprint(data) -> dict | None` with keys `ja4_r`, `groups`, `sig_algs`, `supported_versions`, `grease_present`, `no_grease_signal`; and `fp_event_fields(fp: dict) -> dict`.

- [ ] **Step 1: Write the failing tests**

First add the `build_client_hello` and `supported_versions_ext` helpers (from the "Test helper" section above) to the top of `tests/test_tls_grease.py` (after the imports). Then append:

```python
from lyrebird.tls import fingerprint, fp_event_fields  # noqa: E402


def test_no_grease_signal_fires_for_tls13_without_grease():
    data = build_client_hello([0x1301, 0x1302], [supported_versions_ext([0x0304])])
    fp = fingerprint(data)
    assert fp is not None
    assert fp["grease_present"] is False
    assert fp["no_grease_signal"] is True
    assert fp["ja4_r"].split("_")[0] == fp["ja4"].split("_")[0]
    assert fp["supported_versions"] == [0x0304]


def test_no_grease_signal_gated_off_for_tls12_only():
    data = build_client_hello([0x1301], [supported_versions_ext([0x0303])])
    fp = fingerprint(data)
    assert fp["grease_present"] is False
    assert fp["no_grease_signal"] is False   # gated: no TLS 1.3 offered


def test_no_grease_signal_false_when_grease_sent():
    data = build_client_hello([0x0a0a, 0x1301], [(0x1a1a, b""), supported_versions_ext([0x0304])])
    fp = fingerprint(data)
    assert fp["grease_present"] is True
    assert fp["no_grease_signal"] is False


def test_fp_event_fields_subset():
    data = build_client_hello([0x1301], [supported_versions_ext([0x0304])])
    fields = fp_event_fields(fingerprint(data))
    assert set(fields) == {"ja4_r", "groups", "sig_algs", "supported_versions", "grease_present"}
```

- [ ] **Step 2: Run to verify failure**

Run: `PYTHONPATH=src python -m pytest tests/test_tls_grease.py -k "signal or event_fields" -v`
Expected: FAIL — `KeyError: 'grease_present'` / `cannot import name 'fp_event_fields'`.

- [ ] **Step 3: Implement**

Replace `fingerprint` (lines ~178-189) and add `fp_event_fields` after it:

```python
def fingerprint(data: bytes) -> Optional[dict]:
    """Convenience: parse + both fingerprints + enriched fields, or None."""
    ch = parse_client_hello(data)
    if ch is None:
        return None
    j3_str, j3 = ja3(ch)
    gp = grease_present(ch)
    return {
        "ja3": j3, "ja3_string": j3_str, "ja4": ja4(ch), "ja4_r": ja4_raw(ch),
        "sni": ch.sni, "alpn": ch.alpn,
        "cipher_count": len(_no_grease(ch.ciphers)),
        "ext_count": len(_no_grease(ch.extensions)),
        "groups": _no_grease(ch.groups),
        "sig_algs": _no_grease(ch.sig_algs),
        "supported_versions": _no_grease(ch.supported_versions),
        "grease_present": gp,
        "no_grease_signal": (not gp) and offers_tls13(ch),
    }


def fp_event_fields(fp: dict) -> dict:
    """Enrichment fields both TLS services attach to their event request dict."""
    return {
        "ja4_r": fp.get("ja4_r"),
        "groups": fp.get("groups"),
        "sig_algs": fp.get("sig_algs"),
        "supported_versions": fp.get("supported_versions"),
        "grease_present": fp.get("grease_present"),
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `PYTHONPATH=src python -m pytest tests/test_tls_grease.py -v`
Expected: PASS (all tests).

- [ ] **Step 5: Commit**

```bash
git add src/lyrebird/tls.py tests/test_tls_grease.py
git -c user.name='cac0ns3c' -c user.email='11958671+cac0ns3c@users.noreply.github.com' commit -s -m "Enrich fingerprint() with ja4_r, parsed lists, grease signal"
```

---

### Task 4: Emit enrichment + `no-grease` tag from both TLS services

**Files:**
- Modify: `src/lyrebird/services/tls_capture.py` (import + the `if fp:` emit block, lines ~21, 40-48)
- Modify: `src/lyrebird/services/tls.py` (import + tags/request in the emit block, lines ~30, 103-116)
- Test: `tests/test_tls_grease.py` (append integration test)

**Interfaces:**
- Consumes: `fingerprint`, `fp_event_fields` (Task 3); emits the `no-grease` tag.

- [ ] **Step 1: Write the failing integration test**

Append to `tests/test_tls_grease.py`:

```python
import asyncio  # noqa: E402
import json     # noqa: E402
import time     # noqa: E402

from lyrebird.events import EventSink  # noqa: E402
from lyrebird.services.tls_capture import TlsCaptureService  # noqa: E402


def _wait_for_events(log: Path, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log.exists():
            lines = [l for l in log.read_text().splitlines() if l.strip()]
            if lines:
                return [json.loads(l) for l in lines]
        time.sleep(0.05)
    return []


def test_tls_capture_emits_no_grease_tag(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = TlsCaptureService(cfg={"port": 0}, sink=sink, bind_address="127.0.0.1",
                            data_dir=tmp_path, tls={})
    hello = build_client_hello([0x1301, 0x1302], [supported_versions_ext([0x0304])])

    async def scenario():
        # tls_capture is asyncio.start_server: client+server share ONE loop.
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(hello)
        await writer.drain()
        await reader.read(64)   # service sends a TLS alert, then closes
        writer.close()
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    assert events, "no event flushed"
    ev = events[0]
    assert "no-grease" in ev.get("tags", [])
    assert ev["request"]["grease_present"] is False
    assert ev["request"]["ja4_r"]
```

- [ ] **Step 2: Run to verify failure**

Run: `PYTHONPATH=src python -m pytest tests/test_tls_grease.py::test_tls_capture_emits_no_grease_tag -v`
Expected: FAIL — `'no-grease'` not in tags (services don't emit it yet).

- [ ] **Step 3a: Update `tls_capture.py`**

Change the import (line ~21) from `from ..tls import fingerprint` to:

```python
from ..tls import fingerprint, fp_event_fields
```

Replace the `if fp:` block (lines ~40-48) with:

```python
        if fp:
            tags = ["tls", "fingerprint"]
            if fp.get("no_grease_signal"):
                tags.append("no-grease")
            self.emit(
                transport="tcp", src_ip=peer[0], src_port=peer[1], dst_port=port,
                event_type="request",
                summary=f"tls hello ja4={fp['ja4']} sni={fp.get('sni')}",
                request={"sni": fp.get("sni"), "alpn": fp.get("alpn"),
                         "ja3": fp["ja3"], "ja4": fp["ja4"],
                         "cipher_count": fp["cipher_count"],
                         **fp_event_fields(fp)},
                tags=tags)
```

- [ ] **Step 3b: Update `tls.py` service**

Change the import (line ~30) from `from ..tls import fingerprint` to:

```python
from ..tls import fingerprint, fp_event_fields
```

In the emit block (lines ~103-116), after the `if mismatch:` block, add the no-grease tag and merge the fields into `request`:

```python
            tags = ["tls", "fingerprint"]
            mismatch = bool(sni and host
                            and sni.split(":")[0].lower() != host.split(":")[0].lower())
            if mismatch:
                tags.append("sni-host-mismatch")
            if fp and fp.get("no_grease_signal"):
                tags.append("no-grease")
            self.emit(
                transport="tcp", src_ip=addr[0], src_port=addr[1], dst_port=port,
                event_type="request",
                summary=(f"https ja4={fp['ja4'] if fp else '?'} sni={sni} host={host}"
                         + (" MISMATCH" if mismatch else "")),
                request={"sni": sni, "host": host, "http": method_path,
                         "ja3": fp.get("ja3") if fp else None,
                         "ja4": fp.get("ja4") if fp else None,
                         **(fp_event_fields(fp) if fp else {})},
                tags=tags)
```

- [ ] **Step 4: Run to verify pass**

Run: `PYTHONPATH=src python -m pytest tests/test_tls_grease.py tests/test_tls_service.py -v`
Expected: PASS — new integration test green; existing TLS service test still green.

- [ ] **Step 5: Commit**

```bash
git add src/lyrebird/services/tls_capture.py src/lyrebird/services/tls.py tests/test_tls_grease.py
git -c user.name='cac0ns3c' -c user.email='11958671+cac0ns3c@users.noreply.github.com' commit -s -m "Emit JA3/JA4 enrichment + no-grease tag from TLS services"
```

---

### Task 5: Paired Sigma rule

**Files:**
- Create: `detections/sigma/tls_no_grease_modern_client.yml`

**Interfaces:**
- Consumes: the `no-grease` tag emitted in Task 4. Satisfies the pairing guard.

- [ ] **Step 1: Write the failing guard check**

Run: `PYTHONPATH=src python -m pytest tests/test_detection_pairing.py -v`
Expected: FAIL — `test_every_emitted_tag_is_detected_or_declared_context` reports `tls.py`/`tls_capture.py -> ['no-grease']` (emitted but unpaired).

- [ ] **Step 2: Create the paired rule**

Create `detections/sigma/tls_no_grease_modern_client.yml`:

```yaml
# SPDX-License-Identifier: GPL-3.0-or-later
title: TLS-1.3 Client With No GREASE Seen By Emulator (Non-Browser TLS Stack)
id: bc4fa4bb-86df-4a86-bb61-4b001568a1fb
status: experimental
description: >
  Modern browsers inject GREASE values (RFC 8701) into the ClientHello. A
  TLS-1.3-capable client that sends none is a strong tell of a library or malware
  TLS stack rather than a real browser. The Lyrebird TLS services tag such hellos
  'no-grease', gated to clients that offered TLS 1.3 so legitimately old stacks
  are not flagged. Pair: services/tls.py and services/tls_capture.py tag these
  connections 'no-grease'.
author: Lyrebird
date: 2026/06/30
logsource:
  product: lyrebird
detection:
  selection:
    tags|contains: 'no-grease'
  condition: selection
fields:
  - src_ip
  - request.ja3
  - request.ja4
  - request.ja4_r
  - request.sni
  - request.grease_present
falsepositives:
  - Old or embedded TLS stacks that legitimately predate GREASE
  - Non-browser libraries / pinned enterprise clients that do not implement GREASE
level: medium
```

- [ ] **Step 3: Run the guard + lint to verify pass**

Run: `PYTHONPATH=src python -m pytest tests/test_detection_pairing.py -v && PYTHONPATH=src python scripts/lint_sigma.py`
Expected: PASS — pairing guard green (do NOT touch `CONTEXT_OR_ANALYTIC_TAGS`); `Sigma lint OK`.

- [ ] **Step 4: Commit**

```bash
git add detections/sigma/tls_no_grease_modern_client.yml
git -c user.name='cac0ns3c' -c user.email='11958671+cac0ns3c@users.noreply.github.com' commit -s -m "Pair no-grease TLS signal with a Sigma rule"
```

---

### Task 6: Regenerate `REFERENCE.md` and verify the full suite

**Files:**
- Modify: `REFERENCE.md` (generated)

- [ ] **Step 1: Regenerate the reference**

Run: `PYTHONPATH=src python scripts/gen_reference.py`
Expected: `wrote REFERENCE.md`; `git diff --stat REFERENCE.md` shows the new `no-grease` rule row.

- [ ] **Step 2: Run the FULL suite + lint (the drift guards)**

Run: `PYTHONPATH=src python -m pytest tests/ -q && PYTHONPATH=src python scripts/lint_sigma.py`
Expected: all tests PASS (including `test_reference.py` and `test_detection_pairing.py`); `Sigma lint OK`.

- [ ] **Step 3: Commit**

```bash
git add REFERENCE.md
git -c user.name='cac0ns3c' -c user.email='11958671+cac0ns3c@users.noreply.github.com' commit -s -m "Regenerate REFERENCE.md for the no-grease rule"
```

---

## Self-review

**Spec coverage:**
- Richer fields (`groups`, `sig_algs`, `supported_versions`, `alpn`, `ja4_r`, `grease_present`) → Task 3 (`fingerprint`) + Task 4 (emitted). ✓
- `no-grease` signal gated to TLS 1.3 → Task 1 (`offers_tls13`) + Task 3 (`no_grease_signal`). ✓
- Logic in `tls.py` once; services don't re-derive → Tasks 1-3 in `tls.py`, Task 4 reads `fp["no_grease_signal"]`. ✓
- Paired rule, tag-only selection, not in `CONTEXT_OR_ANALYTIC_TAGS`, level medium → Task 5. ✓
- Unit tests (pure) + integration (poll-for-artifact, one event loop) → Tasks 1-3 (unit), Task 4 (integration). ✓
- Regenerate REFERENCE.md + full suite → Task 6. ✓
- SPDX on new files → test file Step 1 and Sigma rule include the header. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code; the Sigma `id` is a concrete UUID. ✓

**Type consistency:** `grease_present`, `offers_tls13`, `ja4_raw`, `_ja4_parts`, `fingerprint`, `fp_event_fields` names and signatures are consistent across Tasks 1-4. The integration test reads `ev["request"]["grease_present"]` / `["ja4_r"]`, which `fp_event_fields` provides. ✓
