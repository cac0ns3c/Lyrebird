# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure command emulator for the SSH fake shell.

Returns canned, inert output and recognises payload-pull commands
(wget/curl/tftp/busybox). Executes NOTHING, reads/writes NO files, and makes NO
network connections — it only inspects the command string. This is the scope
line for the honeypot: capture intent, perform nothing.
"""

from __future__ import annotations

import re
import shlex

_CANNED = {
    "uname": "Linux",
    "uname -a": "Linux lab 5.15.0-generic #1 SMP x86_64 GNU/Linux",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "whoami": "root",
    "pwd": "/root",
    "ls": "",
    "hostname": "lab",
    "ps": "  PID TTY          TIME CMD\n    1 ?        00:00:00 init",
    "w": " 00:00:00 up 1 day,  0 users,  load average: 0.00, 0.00, 0.00",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
}

_PULL_TOOLS = ("wget", "curl", "tftp", "busybox")
_URL_RE = re.compile(r"((?:https?|ftp|tftp)://[^\s'\"]+)")
_HOST_RE = re.compile(r"^[\w-]+(?:\.[\w-]+)+$")  # e.g. 10.0.0.9 or evil.example
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _first_host(tokens: list[str]) -> str | None:
    # Host-like args, minus option flags. A filename like "m.bin" also looks
    # host-like, so prefer an IPv4 address; otherwise take the last candidate
    # (in `tftp -g -r <file> <host>` the host trails the filename).
    candidates = [t for t in tokens[1:]
                  if not t.startswith("-") and _HOST_RE.match(t)]
    for tok in candidates:
        if _IPV4_RE.match(tok):
            return tok
    return candidates[-1] if candidates else None


def respond(command: str) -> tuple[str, dict | None]:
    cmd = command.strip()
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()

    tool = next((t.rsplit("/", 1)[-1] for t in tokens
                 if t.rsplit("/", 1)[-1] in _PULL_TOOLS), None)
    pull: dict | None = None
    if tool is not None:
        m = _URL_RE.search(cmd)
        url = m.group(1) if m else _first_host(tokens)
        if url:
            pull = {"tool": tool, "url": url}

    if cmd in _CANNED:
        out = _CANNED[cmd]
    elif tokens and tokens[0].rsplit("/", 1)[-1] in _CANNED:
        out = _CANNED[tokens[0].rsplit("/", 1)[-1]]
    elif tool is not None:
        out = ""  # download tools write to a file; benign empty stdout
    else:
        out = f"-bash: {tokens[0]}: command not found" if tokens else ""
    return out, pull
