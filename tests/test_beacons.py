# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the beacon/jitter/channel-rotation analytic."""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.beacons import analyze_beacons  # noqa: E402


def _ev(src, svc, host, t):
    return {"service": svc, "src_ip": src, "event_type": "request",
            "dst_port": 80, "ts": t.isoformat(),
            "request": {"host": host} if svc == "http" else {"qname": host}}


def _series(src, svc, host, start, intervals):
    t = start
    evs = []
    for gap in intervals:
        evs.append(_ev(src, svc, host, t))
        t = t + timedelta(seconds=gap)
    return evs


def test_regular_beacon_detected():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    evs = _series("10.0.0.5", "http", "c2.test", start, [60] * 8)
    rep = analyze_beacons(evs)
    f = rep["findings"][0]
    assert f["beacons"][0]["classification"] == "regular-beacon"
    assert abs(f["beacons"][0]["mean_interval_s"] - 60) < 1


def test_jittered_beacon_detected():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    # 60s mean with +/-~30% jitter
    gaps = [60, 78, 45, 66, 51, 72, 57, 63]
    evs = _series("10.0.0.6", "http", "c2.test", start, gaps)
    rep = analyze_beacons(evs)
    klass = rep["findings"][0]["beacons"][0]["classification"]
    assert klass in ("jittered-beacon", "regular-beacon")


def test_random_traffic_not_flagged_as_beacon():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    gaps = [5, 300, 12, 600, 3, 240, 30]   # high variance
    evs = _series("10.0.0.7", "http", "site.test", start, gaps)
    rep = analyze_beacons(evs)
    # no regular/jittered beacon for this source
    beacons = rep["findings"][0]["beacons"] if rep["findings"] else []
    assert all(b["classification"] != "regular-beacon" for b in beacons)


def test_channel_rotation_detected():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    evs = []
    for i, host in enumerate(["a.test", "b.test", "c.test", "d.test"]):
        evs += _series("10.0.0.8", "http", host,
                       start + timedelta(seconds=i), [120, 120])
    rep = analyze_beacons(evs)
    f = next(f for f in rep["findings"] if f["src_ip"] == "10.0.0.8")
    assert f["channel_rotation"] is True
    assert f["distinct_targets"] >= 3
