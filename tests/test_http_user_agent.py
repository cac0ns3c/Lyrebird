# SPDX-License-Identifier: GPL-3.0-or-later
"""HTTP User-Agent classification: missing vs automation vs browser.

Drives HttpService._handle with a synthetic ASGI request (no uvicorn / no
socket) and checks the tag emitted on the event.
"""

import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from starlette.requests import Request  # noqa: E402

from lyrebird.events import EventSink  # noqa: E402
from lyrebird.services.http import HttpService  # noqa: E402


def _svc(tmp_path):
    sink = EventSink(session="t", log_path=tmp_path / "e.jsonl", echo=False)
    return HttpService(cfg={"port": 80}, sink=sink, bind_address="127.0.0.1",
                       data_dir=tmp_path, tls={}), sink


def _request(headers, method="GET", path="/gate", body=b""):
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    scope = {
        "type": "http", "http_version": "1.1", "method": method, "path": path,
        "raw_path": path.encode(), "query_string": b"", "headers": raw,
        "client": ("10.0.0.5", 5000), "server": ("127.0.0.1", 80),
        "scheme": "http", "root_path": "",
    }
    delivered = {"sent": False}

    async def receive():
        if delivered["sent"]:
            return {"type": "http.disconnect"}
        delivered["sent"] = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


def _tags(tmp_path):
    lines = [l for l in (tmp_path / "e.jsonl").read_text().splitlines() if l]
    return json.loads(lines[-1])["tags"]


def test_automation_user_agent_flagged(tmp_path):
    svc, sink = _svc(tmp_path)
    asyncio.run(svc._handle(_request({"user-agent": "python-requests/2.31.0", "host": "x"})))
    sink.close()
    tags = _tags(tmp_path)
    assert "suspicious-user-agent" in tags
    assert "missing-user-agent" not in tags


def test_browser_user_agent_not_flagged(tmp_path):
    svc, sink = _svc(tmp_path)
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
    asyncio.run(svc._handle(_request({"user-agent": ua, "host": "x"})))
    sink.close()
    tags = _tags(tmp_path)
    assert "suspicious-user-agent" not in tags
    assert "missing-user-agent" not in tags


def test_missing_user_agent_takes_precedence(tmp_path):
    svc, sink = _svc(tmp_path)
    asyncio.run(svc._handle(_request({"host": "x"})))  # no UA header
    sink.close()
    tags = _tags(tmp_path)
    assert "missing-user-agent" in tags
    assert "suspicious-user-agent" not in tags
