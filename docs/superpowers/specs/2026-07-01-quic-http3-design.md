<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Design: QUIC / HTTP-3 emulation service

**Date:** 2026-07-01
**Status:** Approved (pre-implementation)
**Backlog item:** new-service emulator — QUIC / HTTP-3 (service #16)

## Summary

Malware increasingly uses HTTP/3 (QUIC over UDP) for C2 because it evades most
TCP/TLS network inspection. Lyrebird has no QUIC listener, so such a sample goes
dark. This adds a **QUIC / HTTP-3 service** (`services/quic.py`, UDP/443) that
completes the QUIC handshake with a lab cert, speaks HTTP/3, captures each h3
request as structured telemetry, and answers benignly — so the sample keeps
talking. Adds the **`aioquic`** dependency. Paired with a Sigma rule for the
HTTP/3-transport tell.

## Goals

- Terminate QUIC + HTTP/3 on UDP with a lab-CA cert and capture each h3 request
  (method, `:authority`, `:path`, headers, body) as a structured event.
- Respond benignly (a small canned `200`) so the sample proceeds; execute and
  fetch nothing (same posture as the HTTP service).
- Emit a paired `http3-transport` signal (QUIC/h3 = TCP-inspection-evasion
  transport) and reuse the existing `missing-user-agent` beacon signal.

## Non-goals (YAGNI)

- No HTTP/3 server push, no 0-RTT, no app logic beyond request→respond.
- No response-profile reuse yet (static body), no model-layer wiring, no raw
  JA4-QUIC extraction from aioquic internals.

## Current state (verified by spike)

- `aioquic` 1.3.0 installs cleanly (pulls `pylsqpack` C-ext, wheels available);
  a full **H3 server⇄client round-trip in one asyncio loop** works — the server
  captured `:method`/`:authority`/`:path`/`user-agent` and answered `200`.
- `serve(host, port, *, configuration, create_protocol=…)` returns a server with
  `.close()` and `._transport.get_extra_info("sockname")`.
- `QuicConfiguration(is_client=False, alpn_protocols=["h3"])` +
  `config.load_cert_chain(cert, key)` accepts the PEM **paths** that
  `certs.py` `LabCA.leaf(hostname) -> (cert_path, key_path)` produces.
- The orchestrator special-cases cert services: `elif name == "tls": cls(ca=self.ca, …)`.
  `BaseService.__init__(cfg, sink, *, bind_address, data_dir, tls=None)` and
  `self.capture_dir = data_dir/artifacts/<name>`; `self.emit(**kwargs)`.

## Architecture

Single service file `src/lyrebird/services/quic.py`.

- `QuicService(BaseService)`, `name = "quic"`:
  - `__init__(self, *args, ca=None, **kwargs)`: `self.ca = ca or LabCA(self.tls.get("ca_dir", self.data_dir / "ca"))` (QUIC always needs TLS, so it is self-sufficient if `tls` is disabled). `self.port = int(cfg.get("port", 443))`, `self.body = cfg.get("body", "OK").encode()`.
  - `start()`: build `QuicConfiguration(is_client=False, alpn_protocols=["h3"])`, `cert, key = self.ca.leaf("lab.local")`, `config.load_cert_chain(str(cert), str(key))`, then `self._server = await serve(self.bind_address, self.port, configuration=config, create_protocol=self._make_protocol)`.
  - `stop()`: `self._server.close()`.
  - `_make_protocol(*a, **k)`: returns an `_H3Protocol` bound to this service.
- `_H3Protocol(QuicConnectionProtocol)`:
  - On `ProtocolNegotiated(alpn=="h3")` → create `H3Connection(self._quic)`.
  - Route every quic event through `H3Connection.handle_event`; on
    `HeadersReceived` record the pseudo/normal headers per stream; on
    `DataReceived` accumulate the body; on `stream_ended` finalize:
    `service.on_request(peer, headers, body)` then send a benign response
    (`:status 200`, `content-type text/plain`, `service.body`, `end_stream=True`).
- `QuicService.on_request(peer, headers, body)`:
  - Parse `:method`, `:authority`, `:path`, `:scheme`, `user-agent` from headers.
  - If `body` non-empty, write it under `self.capture_dir` (like HTTP/TFTP
    uploads) and record `body_len` + capture path.
  - `self.emit(transport="quic", src_ip=peer[0], src_port=peer[1],
    dst_port=self.port, event_type="request",
    summary=f"h3 {method} {authority}{path}",
    request={"method","authority","path","scheme","user_agent","headers","body_len"},
    tags=["quic", "http3-transport"] + (["missing-user-agent"] if no UA))`.

### Scope guardrail

The service answers with a fixed small benign body and captures request bodies to
disk; it never executes commands, fetches URLs, or initiates egress. It is a
believable responder (like the HTTP service), not an attack tool.

### Telemetry & detection

- `quic` — service-name context tag (add to `CONTEXT_OR_ANALYTIC_TAGS`, alongside
  `sink`/`tftp`/`dns-tcp`).
- `http3-transport` — **SIGNAL**, emitted on every h3 request: a sample using
  QUIC/HTTP-3 in a single-sample lab is a modern-C2 / inspection-evasion tell.
  Paired with `detections/sigma/quic_http3.yml` (`service: quic`,
  `tags|contains: 'http3-transport'`, `fields: src_ip, request.method,
  request.authority, request.path, request.user_agent`, level **medium**).
- `missing-user-agent` — reuse the existing paired beacon signal when an h3
  request carries no User-Agent (no new rule).

## Dependency

- Add `aioquic>=1.0` to **both** `pyproject.toml` `dependencies` and
  `requirements.txt` (CI installs from `requirements.txt`). Verify CI green on
  py3.10–3.12 (aioquic + pylsqpack ship manylinux wheels).

## Error handling / edge cases

- Handshake failure / undecodable packet: aioquic drops it internally; the
  service logs nothing and stays up.
- A request with no `:path`/`:authority`: emit with empty strings; no crash.
- `stop()` before any connection: `self._server.close()` is safe.
- If a cert cannot be minted (CA error), `start()` raises — surfaced by the
  orchestrator's per-service try/except (service disabled, others continue).

## Testing

New `tests/test_quic_service.py` (aioquic client, one event loop, poll-for-artifact):

- **captures an h3 request:** stand up `QuicService` on an ephemeral UDP port,
  connect with an aioquic h3 client, send `GET /beacon` (authority `evil.example`,
  a User-Agent), read the `200`; poll the JSONL log and assert one event with
  `tags` containing `http3-transport`, `request.method=="GET"`,
  `request.path=="/beacon"`, `request.authority=="evil.example"`, and the benign
  body returned.
- **missing-user-agent tell:** an h3 request without a UA header → the event also
  carries `missing-user-agent`.
- **body capture:** a `POST /up` with a body → `request.body_len` > 0 and the body
  written under the capture dir.
- Follows the one-event-loop + poll-for-artifact convention (aioquic is a main
  dependency, available under pytest).

## Packaging / docs

- `aioquic` in `pyproject.toml` + `requirements.txt`.
- README: Services row + count 15 → **16**; regenerate `REFERENCE.md`.
- `CHANGELOG.md`: new `[0.2.0]` section (QUIC/HTTP-3 service + `aioquic` dep).
- Bump `pyproject` version `0.1.0` → **`0.2.0`** (new service; still pre-PyPI).
- Cut a `v0.2.0` tag + GitHub Release at delivery so the first PyPI publish
  includes QUIC.

## Acceptance criteria

- `quic` service registered, configurable, terminates QUIC/h3 with a lab cert,
  captures each request, answers benignly, executes/fetches nothing.
- `http3-transport` paired by `quic_http3.yml`; `quic` context declared;
  `missing-user-agent` reused; pairing guard + Sigma lint green.
- `aioquic` in both dependency files; CI green on py3.10–3.12.
- README (16 services) + REFERENCE regenerated; CHANGELOG `[0.2.0]`; version
  `0.2.0`; SPDX headers; commits DCO-signed + `Co-Authored-By`.

## Files touched

- `src/lyrebird/services/quic.py` (new service)
- `src/lyrebird/orchestrator.py` (import + REGISTRY + `elif name == "quic"` ca branch)
- `src/lyrebird/config.py` (`quic` defaults)
- `detections/sigma/quic_http3.yml` (new, paired)
- `tests/test_detection_pairing.py` (`quic` → `CONTEXT_OR_ANALYTIC_TAGS`)
- `tests/test_quic_service.py` (new)
- `pyproject.toml` + `requirements.txt` (aioquic; version 0.2.0)
- `README.md`, `REFERENCE.md`, `CHANGELOG.md`
