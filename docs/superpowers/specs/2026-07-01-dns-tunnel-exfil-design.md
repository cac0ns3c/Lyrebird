<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Design: DNS tunneling / exfil session analytic

**Date:** 2026-07-01
**Status:** Approved (pre-implementation)
**Backlog item:** more detections on existing services — DNS data-exfil channel

## Summary

DNS already flags a *single* long query label (`long-label` tag → `dns_long_label_dga.yml`), but data-exfil-over-DNS is inherently a **channel**: one source streams data as many high-entropy encoded subdomains under one parent domain. This adds a third session-level analytic — `python -m lyrebird.dns_tunnel` — joining `beacons`/`mimicry`, that ingests a captured session's DNS events and flags exfil tunnels by volume + entropy + uniqueness, paired with a coarse Sigma correlation rule. No new dependency, no DNS-service change, no new emitted tag.

## Goals

- Detect DNS-exfil channels a single-query rule misses: sustained, high-entropy,
  near-all-unique subdomains under one parent, per source — with a documented,
  tunable statistical basis (like `beacons.py`).
- Complement (not duplicate) the single-query `long-label` DGA rule; pair the
  analytic with a coarse SIEM correlation rule.

## Non-goals (YAGNI)

- No Public-Suffix-List dependency (last-2-labels parent approximation).
- No live/inline detection — offline over a captured session, like its siblings.
- No change to the DNS service or its tags; no decoding of exfiltrated data; no
  new dependency (stdlib only).

## Current state

`services/dns.py` emits per-query events: `event_type="request"`, `service="dns"`,
`request={"qname","qtype"}`, `tags` including `long-label` (first label ≥
`DGA_LABEL_LEN`) and `txt-query`. Analytics `beacons.py` and `mimicry.py` are
standalone modules: `load_events(path)`, `analyze_X(events)->report`, an
`argparse` CLI (`python -m lyrebird.X --session <jsonl>`), tunables as documented
module constants; each pairs with a coarse Sigma **correlation** rule
(`beacon_correlation.yml`). The pairing guard (`tests/test_detection_pairing.py`)
recognizes analytics — a correlation rule that selects on an already-emitted tag
adds no new pairing obligation.

## Architecture

New standalone module `src/lyrebird/dns_tunnel.py`, mirroring `beacons.py`:

- `load_events(path)` (same JSONL loader shape as the siblings).
- Pure helpers (unit-tested):
  - `shannon_entropy(s: str) -> float` — bits/char over the string.
  - `parent_domain(qname, labels=2) -> str` — last `labels` dot-parts of the
    (dot-stripped) qname.
  - `subdomain(qname, labels=2) -> str` — the dot-parts left of the parent,
    joined with `.` (`""` if none).
- `analyze_dns_tunnel(events) -> report`:
  - Consider events with `service == "dns"` and `event_type == "request"` that
    have a non-empty subdomain.
  - Group by `(src_ip, parent_domain(qname))`. Per channel compute:
    `queries`, `distinct_subdomains`, `unique_ratio = distinct/queries`,
    `mean_entropy` (mean of `shannon_entropy(subdomain-without-dots)` over the
    channel's queries), `max_label_len`, `txt_ratio` (fraction of
    `qtype in {"TXT","NULL"}`).
  - Flag a channel as an exfil tunnel when
    `queries >= MIN_QUERIES and mean_entropy >= ENTROPY_MIN and unique_ratio >= UNIQUE_RATIO_MIN`.
  - Return `{"session_events", "sources_flagged", "findings": [...]}` where each
    finding is `{src_ip, parent_domain, queries, distinct_subdomains,
    unique_ratio, mean_entropy, max_label_len, txt_ratio, sample: [qname,...]}`,
    sorted by `-queries`.
- `main()` — `argparse` CLI `python -m lyrebird.dns_tunnel --session <jsonl>
  [--out FILE]`, prints/writes the JSON report (same shape as `beacons.main`).

### Tunables (documented constants; verified by spike)

`MIN_QUERIES = 8`, `ENTROPY_MIN = 3.2` (bits/char — base32/64/hex encoded data
lands ~3.1–3.5; benign labels ≪1–2), `UNIQUE_RATIO_MIN = 0.8`,
`PARENT_LABELS = 2`. Spiked: a 12-query encoded channel → flagged
(entropy 3.51, unique 1.0); benign (entropy 0.86) and high-volume repeated
low-entropy lookups (unique 0.08) → not flagged.

### Detection (paired)

`detections/sigma/dns_tunnel_correlation.yml` — a coarse SIEM companion mirroring
`beacon_correlation.yml`:

- Base rule (`name: lyrebird_dns_longlabel_base`): `logsource.product: lyrebird`,
  `detection.selection: {service: 'dns', tags|contains: 'long-label'}`,
  `level: informational`.
- Correlation doc: `type: event_count`, `rules: [lyrebird_dns_longlabel_base]`,
  `group-by: [src_ip]`, `timespan: 10m`, `condition: {gte: 10}`, `level: high`,
  description pointing to `python -m lyrebird.dns_tunnel` for the
  entropy/parent-domain specifics.

Reuses the already-emitted, already-paired `long-label` tag (so the pairing guard
and `CONTEXT_OR_ANALYTIC_TAGS` are untouched); it is distinct from
`dns_long_label_dga.yml` (a single-event rule) by requiring sustained volume from
one source.

## Error handling / edge cases

- qname with ≤ 2 labels (e.g. `example.com`, `localhost.`) → empty subdomain →
  excluded (no exfil signal).
- Missing/empty `src_ip` or `qname` → grouped under a `?`/skipped safely; no
  crash. Malformed events (missing keys) are tolerated via `.get(...)`.
- A source below any one threshold is not flagged (all three gates required).

## Testing

New `tests/test_dns_tunnel.py` (pure, no network — synthesize event dicts):

- `shannon_entropy` / `parent_domain` / `subdomain` unit assertions.
- **flags a tunnel:** 12 unique high-entropy encoded subdomains under one parent
  from one src → one finding, correct `src_ip`/`parent_domain`, `unique_ratio`
  ~1.0, `mean_entropy ≥ ENTROPY_MIN`.
- **does not flag benign:** a handful of normal `www/mail/api` lookups → no
  findings.
- **does not flag a single DGA query:** one long-label query (below
  `MIN_QUERIES`) → no findings.
- **does not flag high-volume low-entropy:** 12 identical repeated lookups
  (`unique_ratio` low, entropy ~0) → no findings.
- **TXT ratio recorded:** a tunnel using TXT qtype reports `txt_ratio` > 0.
- Sigma lint accepts the correlation rule; pairing guard stays green; regenerate
  `REFERENCE.md`; full suite green.

## Acceptance criteria

- `python -m lyrebird.dns_tunnel --session <jsonl>` reports exfil channels by
  the three-gate rule; helpers correct; benign / single-query / low-entropy
  cases not flagged.
- `dns_tunnel_correlation.yml` lints clean and selects on the existing
  `long-label` tag (no new tag, `CONTEXT_OR_ANALYTIC_TAGS` untouched, pairing
  guard green).
- README updated (two → three analytics + the CLI bullet + module listing);
  `REFERENCE.md` regenerated; SPDX headers; commits DCO-signed + `Co-Authored-By`;
  NO dependency change.

## Files touched

- `src/lyrebird/dns_tunnel.py` (new analytic + CLI)
- `detections/sigma/dns_tunnel_correlation.yml` (new, paired coarse rule)
- `tests/test_dns_tunnel.py` (new)
- `README.md` (analytics section + module listing)
- `REFERENCE.md` (regenerated)
