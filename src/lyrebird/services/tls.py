# SPDX-License-Identifier: GPL-3.0-or-later
"""TLS fingerprinting HTTPS emulator (terminate + serve).

Resolves the tls_capture trade-off. This service peeks the ClientHello to compute
JA3/JA4 + SNI, then completes the TLS handshake with the lab cert and serves a
minimal HTTP response — so the sample's HTTPS connection *succeeds* and it keeps
talking, while we still get the fingerprint. Because the ClientHello SNI and the
decrypted HTTP Host are observed on the **same connection**, it emits a
high-fidelity `sni-host-mismatch` signal (domain fronting) directly, rather than
the cross-connection heuristic in the mimicry analytic.

Everything stays local: TLS is terminated here with a lab-generated cert and the
content is a placeholder. No traffic is forwarded anywhere.

Implementation: a blocking accept loop on a background thread; each connection is
handled in a small thread pool. ``MSG_PEEK`` reads the ClientHello without
consuming it, so the TLS layer re-reads it to finish the handshake.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait as futures_wait
from typing import Any

from ..base import BaseService
from ..tls import fingerprint, fp_event_fields

_RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
             b"Content-Length: 2\r\nConnection: close\r\n\r\nOK")


class TlsService(BaseService):
    name = "tls"

    def __init__(self, *args: Any, ca=None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.ca = ca
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._pool = ThreadPoolExecutor(max_workers=16)
        self._inflight: set[Future] = set()
        self._inflight_lock = threading.Lock()
        # How long stop() waits for in-flight captures to drain before giving up.
        self._drain_timeout = float(self.cfg.get("drain_timeout", 5.0))
        self._stop = False
        self._ctx: ssl.SSLContext | None = None

    def _build_ctx(self) -> ssl.SSLContext | None:
        if self.ca is None:
            return None
        cert, key = self.ca.leaf("lab.local")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))
        return ctx

    def _peek_hello(self, conn: socket.socket) -> bytes:
        """Peek the ClientHello without consuming it (retry briefly for the
        common case where it arrives across a couple of reads)."""
        last = b""
        for _ in range(4):
            try:
                data = conn.recv(8192, socket.MSG_PEEK)
            except (BlockingIOError, ssl.SSLWantReadError):
                data = b""
            if len(data) > len(last):
                last = data
                if fingerprint(last) is not None:
                    break
            time.sleep(0.02)
        return last

    def _handle(self, conn: socket.socket, addr: tuple) -> None:
        port = int(self.cfg.get("port", 443))
        method_path = ""
        host = None
        try:
            conn.settimeout(8)
            hello = self._peek_hello(conn)
            fp = fingerprint(hello) if hello else None
            sni = fp.get("sni") if fp else None

            tls_conn = self._ctx.wrap_socket(conn, server_side=True)  # type: ignore[union-attr]
            try:
                req = tls_conn.recv(8192)
                lines = req.split(b"\r\n")
                if lines:
                    method_path = lines[0].decode("latin-1", "replace")
                for h in lines[1:]:
                    if h.lower().startswith(b"host:"):
                        host = h.split(b":", 1)[1].strip().decode("latin-1", "replace")
                        break
                tls_conn.sendall(_RESPONSE)
            finally:
                try:
                    tls_conn.close()
                except Exception:
                    pass

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
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _accept_loop(self) -> None:
        while not self._stop:
            try:
                conn, addr = self._sock.accept()  # type: ignore[union-attr]
            except OSError:
                break
            fut = self._pool.submit(self._handle, conn, addr)
            self._track(fut)

    def _track(self, fut: Future) -> None:
        with self._inflight_lock:
            self._inflight.add(fut)
        fut.add_done_callback(self._untrack)

    def _untrack(self, fut: Future) -> None:
        with self._inflight_lock:
            self._inflight.discard(fut)

    async def start(self) -> None:
        self._ctx = self._build_ctx()
        if self._ctx is None:
            raise RuntimeError("tls service requires the lab CA (set tls.enabled: true)")
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_address, int(self.cfg.get("port", 443))))
        self._sock.listen(50)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    async def stop(self) -> None:
        self._stop = True
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        if self._thread:
            self._thread.join(timeout=1.0)
        # Let in-flight captures (MSG_PEEK + handshake + recv) finish so their
        # events are flushed, but bound the wait so shutdown can't hang on a
        # stuck connection. Anything still running past the deadline is cancelled.
        with self._inflight_lock:
            pending = set(self._inflight)
        if pending:
            futures_wait(pending, timeout=self._drain_timeout)
        self._pool.shutdown(wait=False, cancel_futures=True)
