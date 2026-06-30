# Lyrebird

**Modern internet-services emulation suite for malware analysis labs.**

Lyrebird stands up fake-but-believable network services — HTTP/HTTPS, DNS, SMTP,
NTP, and a generic TCP sink — so that a malware sample running in an **isolated
sandbox** behaves as if it were online. Every interaction is recorded as a
structured JSON event, and every payload the sample sends is captured to disk.
It's a spiritual successor to [INetSim](https://www.inetsim.org/) (last release
1.3.2, 2020), rebuilt async-first in Python with detection telemetry as a
first-class output.

> ⚠️ **Authorized, isolated lab use only.** Lyrebird emulates benign services to
> observe malware in containment. It is a defensive/research tool. It contains no
> implant, no command-and-control capability, and no evasion tooling. Run it on a
> segmented, non-routable network. Do not expose it to the internet.

## Demo

A lab boots, a stand-in sample talks to the emulated services, and every
interaction lands as structured JSONL with detections firing as tags:

![Lyrebird demo: a sample checks in over HTTP and DNS while Lyrebird captures each interaction as structured JSONL with detection tags](docs/assets/demo.gif)

> The "sample" is a benign `curl`/`dig` — Lyrebird only observes. The recording
> is generated from [`demo/lyrebird.tape`](demo/lyrebird.tape) with
> [VHS](https://github.com/charmbracelet/vhs); see [`demo/`](demo/) to reproduce it.

### With the AI model layer

Optionally, Lyrebird can call a model to (1) improvise a believable, **inert**
reply for an endpoint no static rule anticipated — so an unfamiliar sample keeps
talking — and (2) triage the captured session into a verdict and candidate Sigma
detections:

![Lyrebird AI demo: the model improvises a benign response for an un-ruled endpoint, then triages the captured session into a verdict and suggested detections](docs/assets/demo-ai.gif)

> Off by default. The responder is constrained to generic placeholder content —
> never payloads, scripts, or tasking (see [`SCOPE.md`](SCOPE.md) and
> [`src/lyrebird/models/responder.py`](src/lyrebird/models/responder.py)).

## Why

INetSim is still the reference tool, but it's Perl-based, synchronous, config is a
custom format, and its logging was designed for human reports rather than SIEM
ingestion. Lyrebird keeps the proven model and modernizes it:

- **Async core** (asyncio / FastAPI / aiosmtpd / dnslib)
- **YAML config** with sane defaults — an empty file still gives a working lab
- **Structured JSONL events** — one normalized object per interaction, tailable
  straight into a SIEM (this is the backbone everything keys off)
- **Artifact capture** — uploads, mail bodies, and raw socket data stored + hashed
- **Auto lab CA** — TLS handshakes just work; certs are minted on first run
- **Container-native** — `docker compose up` on an internal (no-egress) network
- **Paired Sigma detections** — every service ships with detection content

## Quick start

```bash
pip install -r requirements.txt
python -m lyrebird --config config/lyrebird.yaml
```

Or containerized (recommended — the compose network is `internal: true`, so the
lab has no outbound route by default):

```bash
cd docker && docker compose up --build
```

Point your malware analysis VM's default gateway / DNS at the Lyrebird host, then
detonate the sample and watch the events stream in.

## What gets emitted

Each interaction is one line of JSON:

```json
{"schema":"1.0","ts":"2026-06-29T12:00:00.000+00:00","session":"...",
 "service":"dns","transport":"udp","src_ip":"10.13.37.66","src_port":51000,
 "dst_port":53,"event_type":"request","summary":"A evil.example",
 "request":{"qname":"evil.example.","qtype":"A"},
 "response":{"rcode":0,"answer":"10.13.37.1"},"artifacts":[],"tags":[]}
```

Events land in `labdata/events/<session>.jsonl`; captured payloads in
`labdata/artifacts/<service>/`.

The full field-by-field event schema and the complete detection catalog are in
[`REFERENCE.md`](REFERENCE.md) — generated from `events.py` and the Sigma rules,
so it never drifts. Regenerate with `python scripts/gen_reference.py`.

## Services

| Service | Transport | Status | Notes |
|---|---|---|---|
| HTTP / HTTPS | TCP | ✅ implemented | catch-all any method/path; auto-TLS; body capture |
| DNS | UDP | ✅ implemented | sinkhole responder; logs every lookup; optional realistic NXDOMAIN mode (off by default) |
| SMTP | TCP | ✅ implemented | accepts + captures mail; logs envelope |
| POP3 | TCP | ✅ implemented | fake mailbox; logs credentials/commands |
| FTP | TCP | ✅ implemented | passive + active (PORT) mode; captures STOR uploads |
| TFTP | UDP | ✅ implemented | captures WRQ uploads; per-transfer TID |
| IRC | TCP | ✅ implemented | observes bot C2 — nick, channels, PRIVMSG tasking |
| NTP | UDP | ✅ implemented | answers time; configurable faketime delta |
| TCP sink | TCP | ✅ implemented | logs all data to extra ports (INetSim "Dummy") |
| IMAP | TCP | ✅ implemented | fake mailbox; logs LOGIN credentials; IDLE push (mailbox-C2 long-poll) → imap-idle |
| DNS over TCP | TCP | ✅ implemented | sinkhole over TCP transport |
| TLS (fingerprint + serve) | TCP | ✅ implemented | JA3/JA4 + SNI, terminates & serves, same-connection SNI-vs-Host (off by default) |
| TLS fingerprint tap | TCP | ✅ implemented | JA3/JA4 + SNI capture then close (off by default) |

## Customizing responses

Tailor what any service returns without touching code, via a `responses` block
per service (the modern take on INetSim's fakefiles). Resolution order is
**operator rule → fakefile → model responder (if enabled) → built-in default**,
and the chosen source is recorded on every event (`response.source`).

```yaml
services:
  http:
    responses:
      http:
        - path: "/gate.php"        # glob over the URL path
          method: "POST"
          status: 200
          content_type: "application/json"
          body: '{"status":"ok","task":"none"}'
        - path: "/*.exe"
          body_file: "fakefiles/stub.bin"   # relative to data_dir
      fakefiles_dir: "fakefiles"   # also serve real files by URL path
  dns:
    responses:
      dns:
        - qname: "*.evil-c2.com"   # point a family at a specific sink host
          qtype: "A"
          answer: "10.13.37.66"
```

Fakefile serving is path-traversal protected — paths are confined to the
configured directory.

## Enabling / disabling services

Per-service `enabled: true|false` in config, or override at launch:

```bash
python -m lyrebird --disable smtp,ntp
python -m lyrebird --enable http,dns --no-banner
```

## Model layer (frontier + local)

Lyrebird talks to models through one vendor-agnostic interface, so you can use a
frontier API or a fully local model interchangeably. Selecting `local` keeps all
data on-host for air-gapped analysis.

| provider | backend |
|---|---|
| `anthropic` | Claude (`ANTHROPIC_API_KEY`) |
| `openai` | OpenAI (`OPENAI_API_KEY`) |
| `gemini` | Google Gemini (`GEMINI_API_KEY`) |
| `local` | any OpenAI-compatible local server — Ollama, LM Studio, llama.cpp, vLLM |
| `mock` | offline deterministic stub (tests / dry-runs) |

**Primary use — session triage into detections.** Point it at a captured
session and get a structured verdict + candidate Sigma ideas:

```bash
python -m lyrebird.analyze --session labdata/events/<id>.jsonl --provider local
python -m lyrebird.analyze --session <file> --provider anthropic --model claude-sonnet-4-6
```

**Optional use — response generation.** When `models.respond.enabled: true`, an
HTTP request with no matching rule gets a model-generated **benign placeholder**
body so unfamiliar samples keep talking. It's **off by default** (static templates
are preferred), and it's deliberately constrained: captured input is sanitized
first, the model is restricted to generic inert content (never payloads, scripts,
or commands), and output is canary-checked and length-capped — any failure falls
back to the static default.

### Untrusted input is treated as untrusted

Captured traffic is adversary-controlled, so anything that reaches a model is a
prompt-injection surface. `models/sanitize.py` defangs injection markers, frames
captured data as inert observations behind a canary, and validates model output
against a schema. Nothing captured is ever executed — services only serve or log
bytes.

## Adding a service

Subclass `BaseService`, implement `start()` / `stop()`, emit events with
`self.emit(...)`, and register the class in `orchestrator.REGISTRY`. That's the
whole contract — see `services/dns.py` for a compact example.

## Detections

`detections/sigma/` holds Sigma rules that key off the JSONL schema
(`logsource.product: lyrebird`). Shipped so far: DNS long-label/DGA, HTTP
missing-User-Agent beacon, SMTP bulk recipients. The principle is that every
emulated technique ships with its paired detection.

### Detection analytics

Beyond single-event Sigma rules, two analytics run over a captured session for
the statistical / behavioural cases:

- `python -m lyrebird.beacons --session <jsonl>` — beaconing, jitter (via
  inter-arrival CV), and channel rotation. The defensive pair to Phase 2.
- `python -m lyrebird.mimicry --session <jsonl> [--data-dir labdata]` —
  traffic-mimicry and encryption tells: protocol-on-unexpected-port, domain-
  fronting heuristics, browser-UA-but-bot, and high-entropy (encrypted) bodies.
  The defensive pair to Phase 3.

## Layout

```
src/lyrebird/
  events.py        # structured event model + JSONL sink  (the backbone)
  config.py        # YAML loading + defaults
  base.py          # BaseService plugin contract
  certs.py         # lab CA / leaf certs
  tls.py           # ClientHello parsing + JA3 / JA4
  profiles.py      # operator response templates
  orchestrator.py  # loads config, runs enabled services
  cli.py           # `python -m lyrebird`
  analyze.py       # model-assisted session triage
  beacons.py       # beacon / jitter / channel-rotation analytic
  mimicry.py       # traffic-mimicry / encryption-tell analytic
  services/        # http, dns, dns_tcp, smtp, pop3, imap, ftp, tftp,
                   #   irc, ntp, tls_capture, tcp_sink
  models/          # anthropic, openai, gemini, local, mock + sanitize
config/lyrebird.yaml
detections/sigma/
scripts/lint_sigma.py
docker/
tests/
```

## Status

All thirteen services and all three detection-analytics phases are implemented,
tested, and runnable; the suite boots end to end and every service emits
telemetry. The plugin contract is stable, so the remaining items (IMAP IDLE,
active-mode edge cases, packet-layer JA3 enrichment) are additive. See `SCOPE.md`
for positioning and the roadmap.

## Contributing

PRs welcome — see `CONTRIBUTING.md` for setup, the bar for changes, and a
step-by-step walkthrough for adding a new service. CI (GitHub Actions) runs the
test suite on Python 3.10–3.12, lints the Sigma rules, and smoke-tests the CLI on
every push and PR.

```bash
PYTHONPATH=src python -m pytest tests/ -q
PYTHONPATH=src python scripts/lint_sigma.py
```

## License

GPL-3.0-or-later (see `LICENSE`). Chosen to keep Lyrebird a copyleft, fork-friendly community tool in the same spirit as INetSim (GPLv2). Every source file carries an SPDX header.
