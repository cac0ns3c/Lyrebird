# SPDX-License-Identifier: GPL-3.0-or-later
"""Lyrebird command-line entrypoint.

    python -m lyrebird --config config/lyrebird.yaml
"""

from __future__ import annotations

import argparse
import asyncio

from .config import Config
from .orchestrator import Orchestrator

BANNER = r"""
 ┌─────────────────────────────────────────────┐
 │   L Y R E B I R D                             │
 │   the bird that mimics any service it hears   │
 │   internet-services emulation for malware labs│
 │   ** authorized, isolated lab use only **     │
 └─────────────────────────────────────────────┘
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="lyrebird",
        description="Modern internet-services emulation suite for malware analysis labs.")
    parser.add_argument("-c", "--config", default=None,
                        help="path to YAML config (defaults apply if omitted)")
    parser.add_argument("--enable", default=None,
                        help="comma-separated services to force on (e.g. http,dns)")
    parser.add_argument("--disable", default=None,
                        help="comma-separated services to force off")
    parser.add_argument("--no-banner", action="store_true")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    cfg = Config.load(args.config)

    # CLI overrides take precedence over the config file.
    for name in (args.enable or "").split(","):
        name = name.strip()
        if name:
            cfg.services.setdefault(name, {})["enabled"] = True
    for name in (args.disable or "").split(","):
        name = name.strip()
        if name and name in cfg.services:
            cfg.services[name]["enabled"] = False

    orch = Orchestrator(cfg)
    try:
        asyncio.run(orch.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()