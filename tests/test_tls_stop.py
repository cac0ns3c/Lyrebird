# SPDX-License-Identifier: GPL-3.0-or-later
"""TlsService.stop() drains in-flight captures, but with a bounded wait.

A capture runs in a background thread pool (MSG_PEEK + handshake + recv). On
shutdown we want those to finish so their events are flushed — but never let a
single stuck connection hang the whole teardown.
"""

import asyncio
import threading
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.events import EventSink  # noqa: E402
from lyrebird.services.tls import TlsService  # noqa: E402


def _svc(tmp_path, **cfg):
    sink = EventSink(session="t", log_path=tmp_path / "e.jsonl", echo=False)
    return TlsService(cfg=cfg, sink=sink, bind_address="127.0.0.1",
                      data_dir=tmp_path, tls={})


def test_stop_drains_inflight_capture(tmp_path):
    svc = _svc(tmp_path)
    done = threading.Event()

    def work():
        time.sleep(0.2)
        done.set()

    svc._track(svc._pool.submit(work))
    asyncio.run(svc.stop())
    assert done.is_set(), "in-flight capture was dropped instead of drained"


def test_stop_is_bounded_when_a_capture_hangs(tmp_path):
    svc = _svc(tmp_path, drain_timeout=0.1)
    started = threading.Event()

    def slow():
        started.set()
        time.sleep(1.0)  # outlives the drain timeout

    svc._track(svc._pool.submit(slow))
    assert started.wait(1.0)

    t0 = time.monotonic()
    asyncio.run(svc.stop())
    elapsed = time.monotonic() - t0
    assert elapsed < 0.8, f"stop() did not bound the drain wait (took {elapsed:.2f}s)"
