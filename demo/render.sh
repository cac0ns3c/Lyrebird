#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Render a demo GIF from a VHS tape.
#
#   ./demo/render.sh           # base demo  -> docs/assets/demo.gif    (offline)
#   ./demo/render.sh ai        # AI demo    -> docs/assets/demo-ai.gif (needs a key)
#
# Prerequisites:
#   - vhs            : brew install vhs   (https://github.com/charmbracelet/vhs)
#   - lyrebird deps  : pip install -r requirements.txt   (ideally in a venv)
#   - curl, dig, jq  : used by the recorded session
#   - ai mode only   : ANTHROPIC_API_KEY set to a real sk-ant-* key (live Claude calls)
#
# Run from anywhere; it renders relative to the repo root.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-base}"
case "$mode" in
  base) tape="demo/lyrebird.tape";    out="docs/assets/demo.gif" ;;
  ai)   tape="demo/lyrebird.ai.tape"; out="docs/assets/demo-ai.gif" ;;
  *)    echo "usage: $0 [base|ai]" >&2; exit 2 ;;
esac

if ! command -v vhs >/dev/null 2>&1; then
  echo "error: 'vhs' not found. Install it with:  brew install vhs" >&2
  exit 1
fi
if [ "$mode" = "ai" ] && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "error: ai mode needs ANTHROPIC_API_KEY (a real sk-ant-* key) for live Claude calls." >&2
  echo "       export it first:  export ANTHROPIC_API_KEY=sk-ant-..." >&2
  exit 1
fi

mkdir -p docs/assets
echo "rendering $tape -> $out ..."
vhs "$tape"
echo "done. Commit $out to publish it."
