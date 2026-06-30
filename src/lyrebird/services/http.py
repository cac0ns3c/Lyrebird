# SPDX-License-Identifier: GPL-3.0-or-later
"""HTTP/HTTPS emulation service.

Answers any method on any path with a believable response, so malware probing
for connectivity, fetching a stage, or beaconing to a hard-coded URL gets a
reply and reveals its behaviour. Every request — headers, method, path, body —
is recorded as a structured event, and request bodies are captured as artifacts.

This is the reframed catch-all listener: same idea, now explicitly a benign
service emulator rather than a C2 endpoint.
"""

from __future__ import annotations

import asyncio
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ..base import BaseService
from ..events import Artifact
from ..profiles import Profiles

# A minimal, generic page. Looks like a working server without pretending to be
# any specific product (which would just create fingerprinting noise).
_DEFAULT_BODY = b"<html><head><title>It works</title></head><body>OK</body></html>"

# Library/automation User-Agent substrings (lowercased) — a hardcoded or
# default-library UA instead of a real browser string is a classic beacon tell.
_SUSPICIOUS_UA = (
    "python-requests", "python-urllib", "urllib", "curl/", "wget",
    "go-http-client", "libwww-perl", "powershell", "winhttp", "microsoft bits",
    "okhttp", "java/", "axios", "node-fetch", "httpclient", "ruby",
)


class HttpService(BaseService):
    name = "http"

    def __init__(self, *args: Any, tls_enabled: bool = False, ca=None,
                 profiles: Profiles | None = None, responder=None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._servers: list[uvicorn.Server] = []
        self._tasks: list[asyncio.Task] = []
        self.tls_enabled = tls_enabled
        self.ca = ca
        self.profiles = profiles or Profiles(base_dir=self.data_dir)
        self.responder = responder      # optional model-backed fallback (opt-in)

    def _choose_response(self, method: str, path: str, host: str,
                         req_summary: dict) -> tuple[int, bytes, str, str]:
        """Return (status, body, content_type, source). Resolution order:
        operator rule -> fakefile -> model responder (if enabled) -> default."""
        rule = self.profiles.match_http(method, path, host)
        if rule is not None:
            return (rule.status, rule.resolve_body(self.profiles.base_dir),
                    rule.content_type, "rule")

        fake = self.profiles.fakefile_for(path)
        if fake is not None:
            return (200, fake, "application/octet-stream", "fakefile")

        if self.responder is not None:
            generated = self.responder.http_body(req_summary)
            if generated is not None:
                return (200, generated, "text/html", "model")

        return (200, _DEFAULT_BODY, "text/html", "default")

    async def _handle(self, request: Request) -> Response:
        body = await request.body()
        artifacts = []
        if body:
            artifacts.append(Artifact.from_bytes("upload", body, self.capture_dir,
                                                 note=f"{request.method} {request.url.path}"))
        tags = []
        # Cheap heuristics that are useful for downstream detection triage.
        ua = request.headers.get("user-agent", "")
        if not ua:
            tags.append("missing-user-agent")
        elif any(s in ua.lower() for s in _SUSPICIOUS_UA):
            tags.append("suspicious-user-agent")
        if request.method in ("POST", "PUT") and body:
            tags.append("data-out")

        host = request.headers.get("host", "")
        req_summary = {
            "method": request.method, "path": request.url.path,
            "host": host, "user_agent": ua, "body_len": len(body),
        }
        status, resp_body, ctype, source = self._choose_response(
            request.method, request.url.path, host, req_summary)
        if source == "model":
            tags.append("model-response")

        self.emit(
            transport="tcp",
            src_ip=request.client.host if request.client else "?",
            src_port=request.client.port if request.client else 0,
            dst_port=int(request.url.port or (443 if request.url.scheme == "https" else 80)),
            event_type="request",
            summary=f"{request.method} {request.url.path} ua='{ua[:60]}' -> {source}",
            request={
                "method": request.method,
                "scheme": request.url.scheme,
                "host": host,
                "path": request.url.path,
                "query": request.url.query,
                "headers": dict(request.headers),
                "body_len": len(body),
            },
            response={"status": status, "body_len": len(resp_body), "source": source},
            artifacts=artifacts,
            tags=tags,
        )
        return Response(content=resp_body, status_code=status, media_type=ctype)

    def _app(self) -> Starlette:
        route = Route("/{path:path}", self._handle,
                      methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        return Starlette(routes=[route])

    async def start(self) -> None:
        app = self._app()
        port = int(self.cfg.get("port", 80))
        cfg = uvicorn.Config(app, host=self.bind_address, port=port,
                             log_level="warning", access_log=False)
        server = uvicorn.Server(cfg)
        server.config.load()
        self._servers.append(server)
        self._tasks.append(asyncio.create_task(server.serve()))

        if self.tls_enabled and self.ca is not None:
            tls_port = int(self.cfg.get("tls_port", 443))
            cert, key = self.ca.leaf("lab.local")
            tcfg = uvicorn.Config(app, host=self.bind_address, port=tls_port,
                                  log_level="warning", access_log=False,
                                  ssl_certfile=str(cert), ssl_keyfile=str(key))
            tserver = uvicorn.Server(tcfg)
            tserver.config.load()
            self._servers.append(tserver)
            self._tasks.append(asyncio.create_task(tserver.serve()))

    async def stop(self) -> None:
        for s in self._servers:
            s.should_exit = True
        for t in self._tasks:
            try:
                await asyncio.wait_for(t, timeout=5)
            except Exception:
                t.cancel()