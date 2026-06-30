# SPDX-License-Identifier: GPL-3.0-or-later
#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Lightweight Sigma linter for Lyrebird's detection content.

Validates every rule in detections/sigma/ without pulling in a heavy dependency:
each YAML document must parse, carry a title, and be either a detection rule
(logsource + detection) or a correlation rule (correlation block). For deeper
validation, run `sigma check` from sigma-cli (optional, not required by CI).

    python scripts/lint_sigma.py            # lint the default directory
    python scripts/lint_sigma.py path/...   # lint specific files/dirs
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

DEFAULT_DIR = Path(__file__).resolve().parents[1] / "detections" / "sigma"


def _iter_yaml(paths: list[Path]):
    for p in paths:
        if p.is_dir():
            yield from sorted(p.rglob("*.yml"))
            yield from sorted(p.rglob("*.yaml"))
        elif p.suffix in (".yml", ".yaml"):
            yield p


def lint_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except yaml.YAMLError as e:
        return [f"{path.name}: YAML parse error: {e}"]

    docs = [d for d in docs if d]
    if not docs:
        return [f"{path.name}: no YAML documents"]

    for i, doc in enumerate(docs):
        where = f"{path.name}[doc {i}]"
        if not isinstance(doc, dict):
            errors.append(f"{where}: top level is not a mapping")
            continue
        if "title" not in doc:
            errors.append(f"{where}: missing 'title'")

        is_detection = "detection" in doc and "logsource" in doc
        is_correlation = "correlation" in doc
        if not (is_detection or is_correlation):
            errors.append(f"{where}: must have (logsource + detection) "
                          f"or a 'correlation' block")

        if is_detection:
            det = doc.get("detection", {})
            if not isinstance(det, dict) or "condition" not in det:
                errors.append(f"{where}: detection needs a 'condition'")
        if is_correlation:
            corr = doc["correlation"]
            for key in ("type", "rules", "condition"):
                if key not in corr:
                    errors.append(f"{where}: correlation missing '{key}'")
    return errors


def main(argv: list[str]) -> int:
    targets = [Path(a) for a in argv[1:]] or [DEFAULT_DIR]
    files = list(_iter_yaml(targets))
    if not files:
        print("no Sigma rules found")
        return 1

    all_errors: list[str] = []
    for f in files:
        all_errors.extend(lint_file(f))

    if all_errors:
        print("Sigma lint FAILED:")
        for e in all_errors:
            print(f"  - {e}")
        return 1
    print(f"Sigma lint OK — {len(files)} rule file(s) valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))