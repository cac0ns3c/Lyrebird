<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Demo walkthrough

A short, reproducible terminal recording that shows Lyrebird in action: a lab
boots, a stand-in "sample" talks to the emulated services, and every interaction
lands as structured JSONL with detection tags firing.

The published GIF lives at `docs/assets/demo.gif` and is embedded in the
[README](../README.md) and the [docs site](../docs/index.html).

## What the recording shows

1. **Stand up the lab** — `python -m lyrebird --config demo/lyrebird.demo.yaml`
   brings up HTTP, DNS, and a TCP sink on unprivileged localhost ports.
2. **HTTP check-in** — a `curl` POST to `/gate.php` stands in for a sample
   beaconing home; the body is a candidate exfil. Fires `data-out` (and
   `suspicious-user-agent`, since `curl/*` is a known-automation UA).
3. **DNS lookups** — a long random leftmost label (DGA-style) fires `long-label`;
   a benign `windowsupdate.microsoft.com` lookup fires **nothing** — showing the
   emulator flags behaviour, not every packet.
4. **The payoff** — `jq` over the events JSONL shows each interaction as one
   normalized object, with detections surfaced as `tags`.

> The "sample" is a benign `curl`/`dig` — Lyrebird only *observes*; it never
> executes anything. See [`SCOPE.md`](../SCOPE.md).

## Rendering it

The recording is defined declaratively in [`lyrebird.tape`](lyrebird.tape) and
rendered with [VHS](https://github.com/charmbracelet/vhs), so it regenerates
deterministically — no binary screen-capture in git history.

```bash
# prerequisites
brew install vhs                          # the recorder (also pulls ttyd + ffmpeg)
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt           # lyrebird runtime
# curl, dig, jq are used by the session (preinstalled on most systems)

# render (writes docs/assets/demo.gif)
./demo/render.sh
```

Then commit the generated `docs/assets/demo.gif`.

## Files

| File | Purpose |
|------|---------|
| `lyrebird.tape` | VHS script — the recorded session, step by step |
| `lyrebird.demo.yaml` | No-root demo config (high ports, focused service subset) |
| `render.sh` | One-command render wrapper |
| `.labdata/` | Generated lab output during a render (gitignored) |
