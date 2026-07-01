# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-07-01

First public release: a modern, async-first successor to INetSim with detection
telemetry as a first-class output. Every emulated technique ships with its paired
detection in the same tree.

### Services (15)

- **HTTP/HTTPS** with operator-defined response profiles (the INetSim fakefiles
  successor) and an optional model-assisted responder.
- **DNS** over UDP and TCP (DGA long-label + sandbox-probe/NXDOMAIN tagging).
- **SMTP**, **POP3**, **IMAP** (including **IMAP IDLE** emulation).
- **FTP** (with active-mode / FTP-bounce hardening), **TFTP** (upload capture).
- **SSH** and **Telnet** credential-capture honeypots — brute-force capture then
  a fake shell that logs commands and payload-pull URLs while fetching nothing.
- **IRC**, **NTP** (faketime + mode-6/7 MONLIST detection), **TLS** and a TLS
  capture service, and a generic **TCP sink**.

### Detection & analytics

- Structured JSONL event schema (`events.py`) as the schema contract, with a
  generated catalog (`REFERENCE.md`).
- **21 paired Sigma rules**, enforced by a detection-pairing guard so a new
  behavioural tag can't merge without its rule.
- Lab CA, ClientHello parsing, and **JA3/JA4** fingerprinting (no-grease tell,
  SNI/Host mismatch / domain-fronting).
- **Three session analytics**: `beacons` (beaconing/jitter/rotation), `mimicry`
  (traffic-mimicry / encryption tells), and `dns_tunnel` (DNS tunneling / exfil
  channels).
- Optional model-assisted session triage (`analyze.py`) across Anthropic,
  OpenAI, Gemini, local, and mock providers.

### Tooling & packaging

- Config-driven orchestrator + `python -m lyrebird` / `lyrebird` CLI.
- Container-native: `docker compose up` on an internal, no-egress network.
- Tests green on Python 3.10–3.12; CI runs the suite, the Sigma-content lint,
  and an import/CLI smoke check.

### License

- GPL-3.0-or-later; contributions under the DCO (`git commit -s`).

[Unreleased]: https://github.com/cac0ns3c/Lyrebird/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cac0ns3c/Lyrebird/releases/tag/v0.1.0
