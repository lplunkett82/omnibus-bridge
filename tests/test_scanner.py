"""Tests for the 43690 device scanner.

Parsing is validated against a real capture of OMNIBUS Software's
"List Devices" feature — the full T->PC byte stream is extracted from
the pcap and fed to the pure-function parsers in omnibus_bridge.scanner.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from omnibus_bridge.scanner import (
    DIMMER,
    DISCOVERY_FRAME_1,
    DISCOVERY_FRAME_2,
    Device,
    RELAY,
    TRANSLATOR,
    WALLSWITCH_BUTTON,
    parse_device_record,
    split_frames,
    _decode_name,
)

CAPTURE = (
    Path(__file__).resolve().parent.parent
    / "captures"
    / "omnibus_listdevices_20260422_103628.pcap"
)


# -- Pure-function tests ---------------------------------------------------


def test_discovery_frames_are_exactly_18_bytes():
    # 1 start (7E) + 15 body + 1 CRC + 1 end (7F)
    assert len(DISCOVERY_FRAME_1) == 18
    assert len(DISCOVERY_FRAME_2) == 18
    assert DISCOVERY_FRAME_1[0] == 0x7E
    assert DISCOVERY_FRAME_1[-1] == 0x7F
    # Frame 2 broadcasts to dst=0xFFFFFFFF
    assert DISCOVERY_FRAME_2[9:13] == b"\xff\xff\xff\xff"


def test_decode_name_masks_bit_7():
    # "Kitchen door" with bit-7 set on h (0xE8), n (0xEE), d (0xE4)
    raw = bytes([0x4B, 0x69, 0x74, 0x63, 0xE8, 0x65, 0xEE, 0x20, 0xE4, 0x6F, 0x6F, 0x72])
    assert _decode_name(raw) == "Kitchen door"


def test_decode_name_stops_at_null():
    raw = bytes([0x48, 0x69, 0x00, 0x58, 0x58])
    assert _decode_name(raw) == "Hi"


def test_decode_name_handles_empty_slot():
    assert _decode_name(b"\x00" * 15) == ""


def test_parse_relay_record_unit_13_hall_floor():
    # Exact 49B raw frame (incl trailing CRC byte) of frame[19] from capture
    raw = bytes.fromhex(
        "0026032724ffffffff040023171381001e0100ff007cff"
        "48616c6c20466cefef7220000000000d000000000000001e5a"
        "3e"  # CRC
    )
    assert len(raw) == 49
    dev = parse_device_record(raw)
    assert dev is not None
    assert dev.unit_number == 13
    assert dev.name == "Hall Floor"
    assert dev.device_type == RELAY


def test_parse_wallswitch_button_unit_14_kitchen_door():
    # 47B raw frame: Kitchen door button 6, unit 14 (full hex from capture)
    raw = bytes.fromhex(
        "002ca311fbffffffff04ff21111081ffff0601ff007cff"
        "4b697463e865ee20e46f6f720000000e0000000000"
        "0001"
        "d3"  # CRC
    )
    assert len(raw) == 47
    dev = parse_device_record(raw)
    assert dev is not None
    assert dev.unit_number == 14
    assert dev.name == "Kitchen door"
    assert dev.device_type == WALLSWITCH_BUTTON


def test_parse_dimmer_record_unit_33():
    # 53B raw frame: dimmer at addr 33, no name stored (full hex from capture)
    raw = bytes.fromhex(
        "002e031c9effffffff040027132382001fff01ff007cff"
        "00000000000000008000000000000021000000000000"
        "056400010110ff"
        "97"  # CRC
    )
    assert len(raw) == 53
    dev = parse_device_record(raw)
    assert dev is not None
    assert dev.unit_number == 33
    assert dev.name == ""  # Translator stores no name for the dimmer
    assert dev.device_type == DIMMER


def test_parse_device_record_rejects_relay_with_empty_name():
    # frame[20] from capture — has 1E 5A trailer, but name is all zeros
    raw = bytes.fromhex(
        "0026432724ffffffff040023171381001f0200ff007cff"
        "000000000000000000000000000000000000000000001e5a"
        "fc"  # CRC
    )
    assert parse_device_record(raw) is None


def test_parse_device_record_rejects_unknown_frame_size():
    # 46B frame (frame[18] from capture) — unidentified, all zeros after header
    raw = bytes.fromhex(
        "001b0312bfffffffff040a20141081ffffffffff007cff"
        "00000000000000000000000000000000000000000000"
        "20"  # CRC
    )
    assert parse_device_record(raw) is None


def test_parse_translator_discovery_frame():
    # 71B discovery reply (frame[0] from capture), full hex including CRC
    raw = bytes.fromhex(
        "00deadbeef0000000004ff3923238bff"
        "ffffff15047cff000000000000000000"
        "0000000000000084000000000003c000"
        "020affffff00c0a80101aaaa12340105"
        "ff0000f31426e4"
    )
    assert len(raw) == 71
    dev = parse_device_record(raw)
    assert dev is not None
    assert dev.device_type == TRANSLATOR
    assert dev.device_id == "DEADBEEF"
    assert dev.ip == "192.0.2.10"
    assert dev.netmask == "255.255.255.0"
    assert dev.gateway == "192.168.1.1"
    assert dev.port == 43690  # 0xAAAA
    assert dev.unit_number == 0  # no unit assignment for the Translator


# -- Integration: capture-driven ------------------------------------------


def _pcap_tcp_stream_from_ip(pcap_path: Path, src_ip: str) -> bytes:
    """Extract the concatenated TCP payload stream whose source IP matches.

    Tiny re-implementation of what tools/omnibus_sw_decode.py does, but scoped
    to one direction and minus timing reassembly — we rely on TCP sequence
    ordering of the captured packets.
    """
    raw = pcap_path.read_bytes()
    magic = struct.unpack("<I", raw[:4])[0]
    if magic not in (0xA1B2C3D4, 0xA1B23C4D):
        pytest.skip(f"pcap magic 0x{magic:08x} unsupported in this test")
    _, _, _, _, _, linktype = struct.unpack("<HHiIII", raw[4:24])
    assert linktype == 1  # Ethernet
    pos = 24
    segments: list[tuple[int, bytes]] = []  # (tcp_seq, payload)
    while pos + 16 <= len(raw):
        _, _, incl_len, _ = struct.unpack("<IIII", raw[pos : pos + 16])
        pos += 16
        pkt = raw[pos : pos + incl_len]
        pos += incl_len
        if len(pkt) < 14 or struct.unpack(">H", pkt[12:14])[0] != 0x0800:
            continue
        ip = pkt[14:]
        if (ip[0] >> 4) != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack(">H", ip[2:4])[0]
        sip = ".".join(str(b) for b in ip[12:16])
        if sip != src_ip:
            continue
        tcp = ip[ihl:total]
        if len(tcp) < 20:
            continue
        seq = struct.unpack(">I", tcp[4:8])[0]
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if payload:
            segments.append((seq, bytes(payload)))
    segments.sort(key=lambda s: s[0])
    return b"".join(p for _, p in segments)


@pytest.mark.skipif(not CAPTURE.exists(), reason="capture fixture not present")
def test_parses_full_device_inventory_from_live_listdevices_capture():
    """All 36 devices that OMNIBUS Software lists: 19 relays + 16 wall-switch
    buttons + 1 dimmer (39 minus PSU + Translator + 1 empty relay slot).

    The pcap source IP is read from the SCANNER_SRC_IP env var so this test
    can be run against any local capture; default is the TEST-NET-1 address
    used in the synthetic test fixtures above."""
    import os
    src_ip = os.environ.get("SCANNER_SRC_IP", "192.0.2.10")
    stream = _pcap_tcp_stream_from_ip(CAPTURE, src_ip)
    frames = split_frames(stream)
    devices: list[Device] = []
    for f in frames:
        if len(f) >= 2:
            d = parse_device_record(f)  # parse_device_record now wants the full raw, including CRC
            if d is not None:
                devices.append(d)

    by_type: dict[str, list[Device]] = {}
    for d in devices:
        by_type.setdefault(d.device_type, []).append(d)

    assert len(by_type[RELAY]) == 19
    assert len(by_type[WALLSWITCH_BUTTON]) == 16
    assert len(by_type[DIMMER]) == 1
    # Two back-to-back 71B frames in the capture, but parse_device_record on
    # this raw stream returns both — dedup only happens in scan() at runtime.
    assert len(by_type[TRANSLATOR]) == 2
    assert sum(len(v) for v in by_type.values()) == 38

    t = by_type[TRANSLATOR][0]
    assert t.ip == src_ip
    assert t.port == 43690

    # Device-name assertions are site-specific; only verify structural
    # properties that hold for any 36-device installation of this kind.
    relays = {d.unit_number: d.name for d in by_type[RELAY]}
    assert 1 in relays and 4 in relays and 7 in relays and 13 in relays

    # Kitchen door 6BUT spans wall-switch units {14, 21, 32, 34, 35, 36}
    ws_units = {d.unit_number for d in by_type[WALLSWITCH_BUTTON]}
    assert {14, 21, 32, 34, 35, 36} <= ws_units

    assert by_type[DIMMER][0].unit_number == 33
    assert by_type[DIMMER][0].name == ""
