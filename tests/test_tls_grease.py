# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for GREASE / TLS-1.3 detection and JA4 raw enrichment."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lyrebird.tls import ClientHello, grease_present, offers_tls13  # noqa: E402


def build_client_hello(ciphers: list[int], extensions: list[tuple[int, bytes]]) -> bytes:
	"""Minimal raw ClientHello handshake message (starts with 0x01)."""
	body = b"\x03\x03"                                   # legacy_version TLS1.2
	body += b"\x00" * 32                                 # random
	body += b"\x00"                                      # session_id length 0
	cs = b"".join(c.to_bytes(2, "big") for c in ciphers)
	body += len(cs).to_bytes(2, "big") + cs             # cipher_suites
	body += b"\x01\x00"                                  # compression: len 1, null
	ext = b"".join(et.to_bytes(2, "big") + len(ed).to_bytes(2, "big") + ed
	               for et, ed in extensions)
	body += len(ext).to_bytes(2, "big") + ext           # extensions block
	return b"\x01" + len(body).to_bytes(3, "big") + body


def supported_versions_ext(versions: list[int]) -> tuple[int, bytes]:
	"""Build a supported_versions extension (0x002b)."""
	payload = b"".join(v.to_bytes(2, "big") for v in versions)
	return (0x002b, bytes([len(payload)]) + payload)


def test_grease_present_true_when_grease_in_ciphers():
    ch = ClientHello(ciphers=[0x0a0a, 0x1301])
    assert grease_present(ch) is True


def test_grease_present_false_without_grease():
    ch = ClientHello(ciphers=[0x1301], extensions=[0x002b], supported_versions=[0x0304])
    assert grease_present(ch) is False


def test_offers_tls13_true():
    ch = ClientHello(supported_versions=[0x0303, 0x0304])
    assert offers_tls13(ch) is True


def test_offers_tls13_false_when_only_12():
    ch = ClientHello(supported_versions=[0x0303])
    assert offers_tls13(ch) is False


from lyrebird.tls import ja4, ja4_raw  # noqa: E402


def _sample_ch():
    return ClientHello(legacy_version=0x0303, ciphers=[0x1302, 0x1301],
                       extensions=[0x0000, 0x002b, 0x000d],
                       sig_algs=[0x0403], supported_versions=[0x0304])


def test_ja4_unchanged_shape():
    # JA4 is three underscore-separated parts; b and c are 12-hex-char hashes.
    parts = ja4(_sample_ch()).split("_")
    assert len(parts) == 3
    assert len(parts[1]) == 12 and len(parts[2]) == 12


def test_ja4_raw_shares_prefix_and_is_unhashed():
    ch = _sample_ch()
    raw = ja4_raw(ch)
    assert raw.split("_")[0] == ja4(ch).split("_")[0]          # same ja4_a prefix
    # raw cipher list is the literal sorted hex, not a 12-char hash
    assert raw.split("_")[1] == "1301,1302"


from lyrebird.tls import fingerprint, fp_event_fields  # noqa: E402


def test_no_grease_signal_fires_for_tls13_without_grease():
    data = build_client_hello([0x1301, 0x1302], [supported_versions_ext([0x0304])])
    fp = fingerprint(data)
    assert fp is not None
    assert fp["grease_present"] is False
    assert fp["no_grease_signal"] is True
    assert fp["ja4_r"].split("_")[0] == fp["ja4"].split("_")[0]
    assert fp["supported_versions"] == [0x0304]


def test_no_grease_signal_gated_off_for_tls12_only():
    data = build_client_hello([0x1301], [supported_versions_ext([0x0303])])
    fp = fingerprint(data)
    assert fp["grease_present"] is False
    assert fp["no_grease_signal"] is False   # gated: no TLS 1.3 offered


def test_no_grease_signal_false_when_grease_sent():
    data = build_client_hello([0x0a0a, 0x1301], [(0x1a1a, b""), supported_versions_ext([0x0304])])
    fp = fingerprint(data)
    assert fp["grease_present"] is True
    assert fp["no_grease_signal"] is False


def test_fp_event_fields_subset():
    data = build_client_hello([0x1301], [supported_versions_ext([0x0304])])
    fields = fp_event_fields(fingerprint(data))
    assert set(fields) == {"ja4_r", "groups", "sig_algs", "supported_versions", "grease_present"}


import asyncio  # noqa: E402
import json     # noqa: E402
import time     # noqa: E402

from lyrebird.events import EventSink  # noqa: E402
from lyrebird.services.tls_capture import TlsCaptureService  # noqa: E402


def _wait_for_events(log: Path, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log.exists():
            lines = [l for l in log.read_text().splitlines() if l.strip()]
            if lines:
                return [json.loads(l) for l in lines]
        time.sleep(0.05)
    return []


def test_tls_capture_emits_no_grease_tag(tmp_path):
    log = tmp_path / "e.jsonl"
    sink = EventSink(session="t", log_path=log, echo=False)
    svc = TlsCaptureService(cfg={"port": 0}, sink=sink, bind_address="127.0.0.1",
                            data_dir=tmp_path, tls={})
    hello = build_client_hello([0x1301, 0x1302], [supported_versions_ext([0x0304])])

    async def scenario():
        # tls_capture is asyncio.start_server: client+server share ONE loop.
        await svc.start()
        port = svc._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(hello)
        await writer.drain()
        await reader.read(64)   # service sends a TLS alert, then closes
        writer.close()
        await svc.stop()

    asyncio.run(scenario())
    sink.close()
    events = _wait_for_events(log)
    assert events, "no event flushed"
    ev = events[0]
    assert "no-grease" in ev.get("tags", [])
    assert ev["request"]["grease_present"] is False
    assert ev["request"]["ja4_r"]
