# SCOPE.md — what Lyrebird is and is not

Lyrebird is a **defensive** tool. It emulates benign-but-believable internet
services so malware detonating in an isolated analysis lab keeps talking, and it
captures every interaction as structured JSONL with paired detection telemetry.

This document is the canonical statement of project scope. `CLAUDE.md` and
`CONTRIBUTING.md` defer to it. When a proposed change is ambiguous, the
principle below decides it.

## The line

The emulator *responds to* malware; it never *becomes* the malware. If a change
would make Lyrebird more useful for **attacking** rather than **observing**, it
is out of scope — regardless of how interesting or well-built it is.

## In scope ✅

- New service emulators and response profiles.
- Detection analytics and Sigma rules (paired with the behaviour they detect).
- Event-schema, packaging, docs, and test improvements.
- Lab/sandbox ergonomics: configuration, orchestration, observability.

## Out of scope ❌

- Implants, agents, or beacon payloads.
- Real command-and-control infrastructure or channels.
- Evasion tooling whose purpose is to defeat production defenses.
- Anything whose primary value is offensive capability against live targets.

## Why this matters

The audience is malware analysts and detection engineers running isolated labs.
Keeping Lyrebird strictly on the observation side of the line is what makes it
safe to distribute openly under GPL-3.0-or-later and safe to run beside live
samples. Detection content is a first-class output, not an afterthought: every
emulated technique ships with the detection that catches it, in the same change.

## Isolation, and the one mode that relaxes it

Lyrebird is built to run on a segmented, non-routable lab with no egress, and
every default keeps it there. One opt-in feature deliberately reaches the real
internet: the DNS service's realistic mode (`dns.upstream.enabled`, OFF by
default) consults a real resolver to decide whether a domain exists, so it can
return NXDOMAIN for the non-existent domains sandbox-aware malware probes for.

Enabling it **breaks isolation**: the queried name is sent to the upstream
resolver, which can reveal to adversary infrastructure that a sample is under
analysis. It exists because some labs knowingly accept that trade for higher
fidelity. It is not a license to add general egress or outbound connections from
emulated services — it remains decide-then-sink (the sample is never forwarded
to the real host), DGA/tunneling probes are never sent upstream, and every
upstream lookup is recorded as telemetry. Any further network-reaching behaviour
must clear the same bar and be argued explicitly.

See `CONTRIBUTING.md` for how this scope shapes the bar for a change, and
`CLAUDE.md` for the working context Claude Code sessions load first.
