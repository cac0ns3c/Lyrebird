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

See `CONTRIBUTING.md` for how this scope shapes the bar for a change, and
`CLAUDE.md` for the working context Claude Code sessions load first.
