# SPDX-License-Identifier: GPL-3.0-or-later
"""Guard for Lyrebird's core principle: every emulated technique ships a detection.

Statically scans the service emulators for the behavioural tags they emit and the
Sigma rules for the tags they select on, then asserts the two stay in sync. A
service cannot start emitting a new tag without either a paired Sigma rule or an
explicit, reviewed decision to treat the tag as context/analytic-only. This is
what stops the signal and the rule from drifting apart over time (see CLAUDE.md,
"Core principle: detection pairing").

It is a deliberately lightweight static check — no services are started — so it
runs instantly and never races a background handler.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "src" / "lyrebird" / "services"
SIGMA = ROOT / "detections" / "sigma"

# Tags emitted as connection context / captured evidence, or covered by a session
# analytic (lyrebird.beacons / lyrebird.mimicry) rather than a single-event Sigma
# rule. Adding a tag here is the explicit escape hatch the guard forces you
# through: it shows up in the diff and gets reviewed, instead of drifting in
# silently. The behavioural *signals* (long-label, missing-user-agent,
# bulk-recipients, channel-join, upload, sni-host-mismatch, ja3/ja4) are paired
# with rules and must NOT be listed here.
CONTEXT_OR_ANALYTIC_TAGS = {
    "tls", "fingerprint",          # present on every TLS event as context
    "irc", "privmsg",              # session context; channel-join is the signal
    "credentials",                 # captured evidence (pop3/imap/ftp/smtp auth)
    "txt-query",                   # dns context; long-label is the signal
    "data-out", "model-response",  # http response provenance
    "faketime",                    # benign lab-clock shift, not malicious
    "sink", "tftp", "dns-tcp",     # service-name context tags
    "upstream-resolved",           # egress-occurred marker (realistic DNS mode)
}

# `tags=[...]`, `tags = [...]`, or `tags.append(...)` — capture the argument text.
_TAG_LITERAL = re.compile(r"""tags(?:\s*=\s*\[|\.append\()\s*([^\]\)]*)""")
# string literals inside that text that look like a tag slug
_STRING = re.compile(r"""['"]([a-z0-9][a-z0-9\-]*)['"]""")


def _emitted_tags() -> dict[str, set[str]]:
    """Map each service file to the set of tag string literals it emits."""
    out: dict[str, set[str]] = {}
    for py in sorted(SERVICES.glob("*.py")):
        if py.name == "__init__.py":
            continue
        text = py.read_text(encoding="utf-8")
        tags: set[str] = set()
        for chunk in _TAG_LITERAL.findall(text):
            tags.update(_STRING.findall(chunk))
        if tags:
            out[py.name] = tags
    return out


def _rule_tags() -> set[str]:
    """Every tag value any Sigma rule selects on via a `tags`/`tags|...` key."""
    tags: set[str] = set()
    for y in sorted(SIGMA.glob("*.yml")):
        for doc in yaml.safe_load_all(y.read_text(encoding="utf-8")):
            if not isinstance(doc, dict):
                continue
            det = doc.get("detection", {})
            if not isinstance(det, dict):
                continue
            for sel in det.values():
                if not isinstance(sel, dict):
                    continue
                for key, val in sel.items():
                    if key.split("|", 1)[0] != "tags":
                        continue
                    if isinstance(val, list):
                        tags.update(str(v) for v in val)
                    else:
                        tags.add(str(val))
    return tags


def test_sni_host_mismatch_is_paired():
    """The specific gap this test was written to close stays closed."""
    emitted = set().union(*_emitted_tags().values())
    assert "sni-host-mismatch" in emitted, "tls service no longer emits the tag"
    assert "sni-host-mismatch" in _rule_tags(), (
        "services/tls.py emits 'sni-host-mismatch' (a domain-fronting signal) "
        "but no Sigma rule selects on it — core-principle violation"
    )


def test_every_emitted_tag_is_detected_or_declared_context():
    rule_tags = _rule_tags()
    offenders: dict[str, list[str]] = {}
    for fname, tags in _emitted_tags().items():
        for t in sorted(tags):
            if t not in rule_tags and t not in CONTEXT_OR_ANALYTIC_TAGS:
                offenders.setdefault(fname, []).append(t)
    assert not offenders, (
        "Emitted tag(s) with no paired Sigma rule and not declared "
        "context/analytic. Add a paired rule under detections/sigma/, or — if the "
        "tag is genuinely context — add it to CONTEXT_OR_ANALYTIC_TAGS with a "
        "reason: " + "; ".join(f"{f} -> {ts}" for f, ts in offenders.items())
    )


def test_no_dead_rule_tags():
    """Every tag a rule selects on must actually be emitted by some service."""
    emitted = set().union(*_emitted_tags().values())
    dead = sorted(_rule_tags() - emitted)
    assert not dead, (
        f"Sigma rule(s) select on tag(s) no service emits (typo or stale rule): {dead}"
    )
