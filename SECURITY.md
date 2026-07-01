# Security Policy

Lyrebird is a **defensive** malware-analysis tool: it emulates benign internet
services so a sample detonating in an isolated lab keeps talking while every
interaction is captured. It contains no implant, no command-and-control, and no
evasion tooling (see [`SCOPE.md`](SCOPE.md)).

## Supported versions

Lyrebird is pre-1.0. Security fixes land on `main` and in the next tagged
release; only the latest release is supported.

| Version | Supported |
| ------- | --------- |
| latest release / `main` | ✅ |
| older tags | ❌ |

## Operational safety

Lyrebird is intended to run on a **segmented, non-routable lab network** with the
malware guest and no egress. Do **not** expose it to the internet: its whole job
is to answer untrusted clients believably, and several services (SSH/Telnet
honeypots, TFTP/FTP file capture) accept and record attacker-controlled input.
Running it on a reachable network is a misconfiguration, not a vulnerability.

## Reporting a vulnerability

Report vulnerabilities **privately** — do not open a public issue.

- Preferred: GitHub **private vulnerability reporting** — the *Report a
  vulnerability* button under the repository's **Security** tab
  (`Security → Advisories`).
- Please include: affected version/commit, a description, reproduction steps or
  a proof of concept, and the impact you observed.

What to expect:

- We aim to acknowledge a report within a few days and to agree on a disclosure
  timeline with you.
- Please give us reasonable time to ship a fix before any public disclosure.
- We credit reporters in the release notes unless you ask us not to.

### In scope

- Bugs in Lyrebird that let untrusted client input escape the intended
  emulation boundary (e.g. code execution, path traversal out of the lab data
  directory, resource-exhaustion crashes reachable from a single connection).
- Detection-integrity issues where a paired signal can be silently suppressed.

### Out of scope

- The tool "responding to malware" — that is its purpose.
- Findings that require exposing Lyrebird to a hostile network against the
  documented lab-only guidance.
- Requests for offensive capability (implants, C2, evasion) — explicitly out of
  scope by design.
