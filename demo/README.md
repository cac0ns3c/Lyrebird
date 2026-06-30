<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Demo walkthrough

A short, reproducible terminal recording that shows Lyrebird in action: a lab
boots, a stand-in "sample" talks to the emulated services, and every interaction
lands as structured JSONL with detection tags firing.

There are two clips:

- **Base demo** (`docs/assets/demo.gif`) — fully offline/air-gapped, reproducible
  by anyone.
- **AI-assisted demo** (`docs/assets/demo-ai.gif`) — shows the optional model
  layer; needs a real `ANTHROPIC_API_KEY` to render (it makes live Claude calls).

Both are embedded in the [README](../README.md) and the [docs site](../docs/index.html).

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

# base demo (offline) -> docs/assets/demo.gif
./demo/render.sh

# AI demo -> docs/assets/demo-ai.gif  (live Claude calls; needs a real key)
export ANTHROPIC_API_KEY=sk-ant-...
./demo/render.sh ai
```

Then commit the generated GIF(s).

## The AI-assisted clip

`lyrebird.ai.tape` records two things the model layer adds (both real, live calls):

1. **Responder** — a sample requests `/api/v2/telemetry`, an endpoint no static
   rule anticipated. Instead of a canned default, the model improvises a
   believable but **inert** body (e.g. `{"status":"ok"}`) so the sample keeps
   talking; the event records `source=model` and the `model-response` tag. The
   responder is constrained to generic placeholder content — never payloads,
   scripts, or tasking (see `../src/lyrebird/models/responder.py` and `../SCOPE.md`).
2. **Triage** — `python -m lyrebird.analyze` hands the captured session to the
   model and gets back a structured verdict + indicators + candidate Sigma
   detections — turning raw lab telemetry into detection content.

The key is read from the environment and is never typed in the tape, so it
cannot appear in the recording.

## Files

| File | Purpose |
|------|---------|
| `lyrebird.tape` | Base VHS script — the offline recorded session |
| `lyrebird.demo.yaml` | No-root demo config (high ports, focused service subset) |
| `lyrebird.ai.tape` | AI-assisted VHS script (responder + analyze; live Claude) |
| `lyrebird.ai.demo.yaml` | Demo config with the model layer enabled |
| `render.sh` | One-command render wrapper (`render.sh [base\|ai]`) |
| `.labdata/` | Generated lab output during a render (gitignored) |
