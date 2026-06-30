#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Render the demo GIF (docs/assets/demo.gif) from demo/lyrebird.tape.
#
# Prerequisites:
#   - vhs            : brew install vhs   (https://github.com/charmbracelet/vhs)
#   - lyrebird deps  : pip install -r requirements.txt   (ideally in a venv)
#   - curl, dig, jq  : used by the recorded session
#
# Run from anywhere; it renders relative to the repo root.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v vhs >/dev/null 2>&1; then
  echo "error: 'vhs' not found. Install it with:  brew install vhs" >&2
  echo "       (or see https://github.com/charmbracelet/vhs)" >&2
  exit 1
fi

mkdir -p docs/assets
echo "rendering demo/lyrebird.tape -> docs/assets/demo.gif ..."
vhs demo/lyrebird.tape
echo "done. Commit docs/assets/demo.gif to publish it."
