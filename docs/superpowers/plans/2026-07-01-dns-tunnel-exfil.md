<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# DNS Tunneling / Exfil Session Analytic — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A third session analytic — `python -m lyrebird.dns_tunnel` — that flags DNS data-exfil/tunneling channels (sustained, high-entropy, near-all-unique subdomains under one parent domain per source), paired with a coarse Sigma correlation rule.

**Architecture:** A standalone module `src/lyrebird/dns_tunnel.py` mirroring `beacons.py`/`mimicry.py` (pure helpers + `analyze_dns_tunnel(events)` + `argparse` CLI), plus a coarse correlation rule reusing the existing `long-label` tag. No new dependency, no DNS-service change, no new emitted tag.

**Tech Stack:** Python 3.10–3.12, stdlib (`math`, `collections`, `argparse`, `json`), pytest. **No new dependency.**

## Global Constraints

- Run tests with `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest`.
- SPDX header on every new file. Commit with plain `git commit -s` + a second `-m` co-author trailer (`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`); no inline `-c` override.
- **No dependency change** (stdlib). Do NOT touch requirements.txt / pyproject.toml.
- The analytic emits **no service tag**; the correlation rule selects on the already-emitted, already-paired `long-label` tag. So the pairing guard stays green throughout — do NOT modify `CONTEXT_OR_ANALYTIC_TAGS`, and there is no RED-by-design phase.
- Verified (spiked): the three-gate rule flags a 12-query encoded channel (mean_entropy 3.51, unique_ratio 1.0) and rejects benign (entropy 0.86) and high-volume low-entropy repeats (unique 0.08).

---

### Task 1: The `dns_tunnel` analytic

**Files:**
- Create: `src/lyrebird/dns_tunnel.py`
- Test: `tests/test_dns_tunnel.py` (create)

**Interfaces:**
- Produces: `shannon_entropy(s)->float`, `parent_domain(qname, labels=2)->str`, `subdomain(qname, labels=2)->str`, `analyze_dns_tunnel(events)->report`, `load_events(path)->list`, `main()`. Report: `{"session_events", "channels_flagged", "findings":[{src_ip, parent_domain, queries, distinct_subdomains, unique_ratio, mean_entropy, max_label_len, txt_ratio, sample:[qname,...]}]}`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_dns_tunnel.py`:

```python
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests: DNS tunneling / exfil session analytic."""
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.dns_tunnel import (  # noqa: E402
    analyze_dns_tunnel, shannon_entropy, parent_domain, subdomain,
)


def _dns_event(src, qname, qtype="A"):
    return {"service": "dns", "event_type": "request", "src_ip": src,
            "request": {"qname": qname, "qtype": qtype}}


def _encoded(i):
    return base64.b32encode(bytes(range(i, i + 12))).decode().rstrip("=").lower()


def test_helpers():
    assert parent_domain("a.b.evil.com") == "evil.com"
    assert parent_domain("evil.com") == "evil.com"
    assert subdomain("chunk.tunnel.evil.com") == "chunk.tunnel"
    assert subdomain("evil.com") == ""
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("abcdefgh") > 2.5


def test_flags_exfil_tunnel():
    events = [_dns_event("10.0.0.5", f"{_encoded(i)}.t.evil.com") for i in range(12)]
    report = analyze_dns_tunnel(events)
    assert report["channels_flagged"] == 1
    f = report["findings"][0]
    assert f["src_ip"] == "10.0.0.5"
    assert f["parent_domain"] == "evil.com"
    assert f["unique_ratio"] >= 0.9
    assert f["mean_entropy"] >= 3.2
    assert f["queries"] == 12


def test_does_not_flag_benign():
    events = [_dns_event("10.0.0.6", q) for q in
              ["www.google.com", "mail.google.com", "www.google.com",
               "api.github.com", "www.github.com", "cdn.example.net"]]
    assert analyze_dns_tunnel(events)["channels_flagged"] == 0


def test_does_not_flag_single_dga_query():
    events = [_dns_event("10.0.0.7", f"{_encoded(0)}.t.evil.com")]
    assert analyze_dns_tunnel(events)["channels_flagged"] == 0


def test_does_not_flag_high_volume_low_entropy():
    events = [_dns_event("10.0.0.8", "www.example.com") for _ in range(12)]
    assert analyze_dns_tunnel(events)["channels_flagged"] == 0


def test_txt_ratio_recorded():
    events = [_dns_event("10.0.0.9", f"{_encoded(i)}.t.evil.com", "TXT")
              for i in range(12)]
    f = analyze_dns_tunnel(events)["findings"][0]
    assert f["txt_ratio"] == 1.0
```

- [ ] **Step 2: Run to verify failure**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_dns_tunnel.py -v`
Expected: FAIL — `ModuleNotFoundError: lyrebird.dns_tunnel`.

- [ ] **Step 3: Create the analytic**

Create `src/lyrebird/dns_tunnel.py`:

```python
# SPDX-License-Identifier: GPL-3.0-or-later
"""DNS tunneling / exfil detection.

Data-exfil-over-DNS is a *channel*: one source streams data as many high-entropy
encoded subdomains under a single parent domain. The single-query long-label DGA
rule can't see the channel; this session analytic does — grouping a captured
session's DNS queries by (source, parent domain) and flagging channels by volume,
per-label entropy, and subdomain uniqueness.

    python -m lyrebird.dns_tunnel --session labdata/events/<id>.jsonl
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

# Tunables (documented so analysts can adapt). Verified against encoded-vs-benign
# samples: base32/64/hex data lands ~3.1-3.5 bits/char; benign labels are <~2.
MIN_QUERIES = 8            # sustained volume before a channel is assessable
ENTROPY_MIN = 3.2          # mean bits/char over subdomains -> encoded data
UNIQUE_RATIO_MIN = 0.8     # exfil chunks are near-all-unique (not cached lookups)
PARENT_LABELS = 2          # last-2-labels parent (dependency-free eTLD+1 approx)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parent_domain(qname: str, labels: int = PARENT_LABELS) -> str:
    parts = qname.rstrip(".").split(".")
    return ".".join(parts[-labels:]) if len(parts) >= labels else qname.rstrip(".")


def subdomain(qname: str, labels: int = PARENT_LABELS) -> str:
    parts = qname.rstrip(".").split(".")
    return ".".join(parts[:-labels]) if len(parts) > labels else ""


def analyze_dns_tunnel(events: list[dict[str, Any]]) -> dict[str, Any]:
    # Group DNS request events by (source, parent domain).
    channels: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for e in events:
        if e.get("service") != "dns" or e.get("event_type") != "request":
            continue
        req = e.get("request", {}) or {}
        qname = (req.get("qname") or "").rstrip(".")
        if not qname or not subdomain(qname):
            continue
        key = (e.get("src_ip", "?"), parent_domain(qname))
        channels.setdefault(key, []).append(e)

    findings = []
    for (src, parent), evs in channels.items():
        subs = [subdomain((ev.get("request", {}) or {}).get("qname", ""))
                for ev in evs]
        queries = len(evs)
        distinct = len(set(subs))
        unique_ratio = distinct / queries if queries else 0.0
        mean_entropy = (sum(shannon_entropy(s.replace(".", "")) for s in subs)
                        / len(subs)) if subs else 0.0
        max_label_len = max((len(s.split(".")[0]) for s in subs), default=0)
        txt = sum(1 for ev in evs
                  if (ev.get("request", {}) or {}).get("qtype") in ("TXT", "NULL"))
        txt_ratio = txt / queries if queries else 0.0

        if (queries >= MIN_QUERIES and mean_entropy >= ENTROPY_MIN
                and unique_ratio >= UNIQUE_RATIO_MIN):
            findings.append({
                "src_ip": src,
                "parent_domain": parent,
                "queries": queries,
                "distinct_subdomains": distinct,
                "unique_ratio": round(unique_ratio, 3),
                "mean_entropy": round(mean_entropy, 3),
                "max_label_len": max_label_len,
                "txt_ratio": round(txt_ratio, 3),
                "sample": [(ev.get("request", {}) or {}).get("qname", "")
                           for ev in evs[:5]],
            })

    return {
        "session_events": len(events),
        "channels_flagged": len(findings),
        "findings": sorted(findings, key=lambda f: -f["queries"]),
    }


def load_events(path: Path) -> list[dict[str, Any]]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def main() -> None:
    p = argparse.ArgumentParser(
        prog="lyrebird.dns_tunnel",
        description="Detect DNS tunneling / data-exfil channels in a session.")
    p.add_argument("--session", required=True, help="path to a session .jsonl")
    p.add_argument("--out", default=None, help="write JSON report here")
    args = p.parse_args()
    report = analyze_dns_tunnel(load_events(Path(args.session)))
    text = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_dns_tunnel.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add src/lyrebird/dns_tunnel.py tests/test_dns_tunnel.py
git commit -s -m "Add DNS tunneling/exfil session analytic (lyrebird.dns_tunnel)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Paired coarse Sigma correlation rule

**Files:**
- Create: `detections/sigma/dns_tunnel_correlation.yml`

- [ ] **Step 1: Create the rule**

Create `detections/sigma/dns_tunnel_correlation.yml`:

```yaml
# SPDX-License-Identifier: GPL-3.0-or-later
# A coarse SIEM-side companion to lyrebird.dns_tunnel. Entropy / parent-domain /
# uniqueness analysis is statistical and lives in the analytic; this catches the
# sustained-long-label case a single-query DGA rule would miss.
title: Repeated Long DNS Labels From Single Source (DNS Tunnel Base)
name: lyrebird_dns_longlabel_base
status: experimental
description: Base event selection for DNS-tunnel correlation — long-label DNS requests.
author: Lyrebird
date: 2026/07/01
logsource:
  product: lyrebird
  service: dns
detection:
  selection:
    service: 'dns'
    tags|contains: 'long-label'
  condition: selection
level: informational
---
title: Sustained Long-Label DNS From Single Source (Possible Tunnel/Exfil)
id: 7c1e9a52-3f84-4b60-9d17-2a8f0c6b5e43
status: experimental
description: >
  A source issuing many long-label DNS queries to the emulator within a short
  window is consistent with data exfil / tunneling over DNS (one query per data
  chunk). For entropy, parent-domain, and uniqueness specifics, run
  `python -m lyrebird.dns_tunnel` on the session.
author: Lyrebird
date: 2026/07/01
correlation:
  type: event_count
  rules:
    - lyrebird_dns_longlabel_base
  group-by:
    - src_ip
  timespan: 10m
  condition:
    gte: 10
level: high
```

- [ ] **Step 2: Lint + pairing guard**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/lint_sigma.py && PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/test_detection_pairing.py -q`
Expected: `Sigma lint OK` (21 rule files); pairing guard PASS (reuses the emitted `long-label` tag — no dead tag, no new pairing obligation, `CONTEXT_OR_ANALYTIC_TAGS` untouched). If the guard fails, STOP — do NOT edit `CONTEXT_OR_ANALYTIC_TAGS`.

- [ ] **Step 3: Commit**

```bash
git add detections/sigma/dns_tunnel_correlation.yml
git commit -s -m "Pair DNS-tunnel analytic with a coarse Sigma correlation rule" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: README + REFERENCE + full suite

**Files:**
- Modify: `README.md` (analytics section + module listing)
- Modify: `REFERENCE.md` (generated)

- [ ] **Step 1: Update the README analytics section**

In `README.md`, in the `### Detection analytics` section, change `Beyond single-event Sigma rules, two analytics run over a captured session` to `... three analytics run over a captured session`. Then add a bullet after the `mimicry` bullet (match the existing bullet format):

```markdown
- `python -m lyrebird.dns_tunnel --session <jsonl>` — DNS tunneling / data-exfil
  channels: high-entropy, near-all-unique subdomains streamed under one parent
  domain (dns-tunnel-exfil).
```

Then in the `src/lyrebird/` file-tree listing, add after the `mimicry.py` line:

```
  dns_tunnel.py    # DNS tunneling / exfil analytic
```

(Leave the "All fifteen services and all three detection-analytics phases" line as-is — "phases" refers to the roadmap phases, not the analytic-module count.)

- [ ] **Step 2: Regenerate REFERENCE.md**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/gen_reference.py`
Expected: `wrote REFERENCE.md`; `git status --short` shows only `README.md` and `REFERENCE.md` (a new `dns_tunnel_correlation` rule row). If anything else changed, STOP and report.

- [ ] **Step 3: Full suite + lint**

Run: `PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python -m pytest tests/ -q && PYTHONPATH=src /Users/anatneuman/Projects/Lyrebird/.venv/bin/python scripts/lint_sigma.py`
Expected: all PASS (incl. `test_reference.py`, `test_detection_pairing.py`, `test_dns_tunnel.py`); `Sigma lint OK`.

- [ ] **Step 4: Commit**

```bash
git add README.md REFERENCE.md
git commit -s -m "Docs: DNS-tunnel analytic (three analytics); regenerate REFERENCE.md" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-review

**Spec coverage:** analytic module + helpers + CLI (Task 1); paired coarse correlation rule reusing `long-label` (Task 2); README + REFERENCE + full suite (Task 3). ✓
**Placeholder scan:** complete code every step; concrete UUID. ✓
**Type consistency:** report keys (`channels_flagged`, `findings[].{src_ip,parent_domain,queries,unique_ratio,mean_entropy,txt_ratio,...}`) identical across module + tests; helper signatures match their calls + unit tests. ✓
**No new tag:** analytic emits nothing; correlation rule reuses emitted+paired `long-label`; pairing guard green, no `CONTEXT_OR_ANALYTIC_TAGS` change — no RED phase. ✓
