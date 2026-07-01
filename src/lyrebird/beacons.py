# SPDX-License-Identifier: GPL-3.0-or-later
"""Beacon, jitter, and channel-rotation detection.

The offensive techniques on the roadmap — beacon jitter and channel rotation —
are evasions against *timing* and *destination* analysis. This module is their
defensive pair: it ingests a captured session's events and looks for the
fingerprints those techniques leave behind.

  * Periodic beaconing  — a source contacts the same target on a near-constant
    interval. Detected via a low coefficient of variation (CV) on inter-arrival
    times.
  * Jittered beaconing  — the interval is randomized within a band (classic C2
    jitter, e.g. mean ± 30%). Shows up as a moderate, bounded CV rather than the
    near-zero CV of a naive beacon or the high CV of human/random traffic.
  * Channel rotation    — one source cycles across multiple services/ports/
    destinations over time instead of hammering one, to spread its footprint.

Timing detection is inherently statistical, not a single-event signature, so the
primary artifact is this analytic; a coarse Sigma correlation rule
(detections/sigma/beacon_correlation.yml) complements it for SIEM coverage.

    python -m lyrebird.beacons --session labdata/events/<id>.jsonl
"""

from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

# Tunables (documented so analysts can adapt to their environment).
MIN_HITS = 4            # need at least this many requests to assess timing
REGULAR_CV = 0.10       # CV below this -> near-perfect beacon
JITTER_CV = 0.50        # CV below this (and >= REGULAR_CV) -> consistent with jitter
ROTATION_MIN_TARGETS = 3   # distinct targets before we call it rotation
ROTATION_MIN_HITS = 6


def _parse_ts(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts).timestamp()
    except Exception:
        return 0.0


def _target(event: dict[str, Any]) -> str:
    """A logical destination: service + port (+ host/qname where meaningful)."""
    svc = event.get("service", "?")
    req = event.get("request", {}) or {}
    if svc == "http":
        return f"http:{req.get('host') or event.get('dst_port')}"
    if svc == "dns":
        name = (req.get("qname") or "").rstrip(".")
        return f"dns:{name}" if name else "dns"
    return f"{svc}:{event.get('dst_port')}"


def _intervals(times: list[float]) -> list[float]:
    times = sorted(times)
    return [b - a for a, b in zip(times, times[1:], strict=False) if b > a]


def _classify(intervals: list[float]) -> dict[str, Any]:
    if len(intervals) < MIN_HITS - 1:
        return {"classification": "insufficient-data", "hits": len(intervals) + 1}
    mean = statistics.fmean(intervals)
    if mean <= 0:
        return {"classification": "insufficient-data", "hits": len(intervals) + 1}
    stdev = statistics.pstdev(intervals)
    cv = stdev / mean
    lo, hi = min(intervals), max(intervals)
    # Approximate jitter band as a +/- percentage around the mean.
    jitter_pct = round(((hi - lo) / 2) / mean * 100, 1)

    if cv < REGULAR_CV:
        klass = "regular-beacon"
    elif cv < JITTER_CV:
        klass = "jittered-beacon"
    else:
        klass = "sporadic"
    return {
        "classification": klass,
        "hits": len(intervals) + 1,
        "mean_interval_s": round(mean, 2),
        "cv": round(cv, 3),
        "jitter_pct_est": jitter_pct,
    }


def analyze_beacons(events: list[dict[str, Any]]) -> dict[str, Any]:
    # Group request events by source, then by target.
    by_src: dict[str, list[dict[str, Any]]] = {}
    for e in events:
        if e.get("event_type") not in ("request", "capture", "auth"):
            continue
        by_src.setdefault(e.get("src_ip", "?"), []).append(e)

    findings = []
    for src, evs in by_src.items():
        per_target: dict[str, list[float]] = {}
        for e in evs:
            per_target.setdefault(_target(e), []).append(_parse_ts(e.get("ts", "")))

        # Per-target timing classification.
        target_results = []
        for tgt, times in per_target.items():
            result = _classify(_intervals([t for t in times if t]))
            result["target"] = tgt
            if result["classification"] in ("regular-beacon", "jittered-beacon"):
                target_results.append(result)

        # Channel rotation: many distinct targets, enough total hits.
        distinct_targets = len(per_target)
        total_hits = len(evs)
        rotation = (distinct_targets >= ROTATION_MIN_TARGETS
                    and total_hits >= ROTATION_MIN_HITS)

        if target_results or rotation:
            findings.append({
                "src_ip": src,
                "total_events": total_hits,
                "distinct_targets": distinct_targets,
                "channel_rotation": rotation,
                "beacons": sorted(target_results, key=lambda r: r["cv"]),
            })

    return {
        "session_events": len(events),
        "sources_flagged": len(findings),
        "findings": sorted(findings, key=lambda f: -f["total_events"]),
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
        prog="lyrebird.beacons",
        description="Detect beaconing, jitter, and channel rotation in a session.")
    p.add_argument("--session", required=True, help="path to a session .jsonl")
    p.add_argument("--out", default=None, help="write JSON report here")
    args = p.parse_args()

    report = analyze_beacons(load_events(Path(args.session)))
    text = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
