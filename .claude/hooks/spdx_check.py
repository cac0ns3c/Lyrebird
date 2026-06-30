#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""PostToolUse guard: every Lyrebird source file needs the SPDX header.

Reads the hook payload on stdin, and if the edited/written file is a Python
source under src/ or scripts/ that is missing
``SPDX-License-Identifier: GPL-3.0-or-later``, exits 2 so the message is fed
back to Claude to fix before the change is reviewed. Anything else exits 0.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REQUIRED = "SPDX-License-Identifier: GPL-3.0-or-later"
# Directories where the SPDX convention is enforced (100% compliant today).
WATCHED_DIRS = ("src", "scripts", "tests")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0  # not our place to fail the tool on a malformed payload

    raw = (payload.get("tool_input") or {}).get("file_path")
    if not raw:
        return 0

    path = Path(raw)
    if path.suffix != ".py":
        return 0

    # Resolve against cwd so we can test "is this under src/ or scripts/".
    cwd = Path(payload.get("cwd") or ".").resolve()
    try:
        rel = path.resolve().relative_to(cwd)
    except ValueError:
        return 0  # outside the project tree
    if rel.parts and rel.parts[0] not in WATCHED_DIRS:
        return 0

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0  # file gone (e.g. a move) — nothing to check

    if REQUIRED in text:
        return 0

    sys.stderr.write(
        f"SPDX header missing in {rel}. Add this as the first line "
        f"(or directly after a shebang):\n# {REQUIRED}\n"
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
