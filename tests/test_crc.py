"""Tests for CRC-16/A001 used in Omni-Link II inner frames."""
from __future__ import annotations

from omnibus_bridge.crc import crc16, crc16_le_bytes


def test_spec_sample_ack() -> None:
    # Spec Appendix B sample ACK: inner frame is 21 01 01 C0 50.
    # CRC is over length+type = 0x01 0x01, and should serialise as C0 50 (LSB first).
    assert crc16_le_bytes(b"\x01\x01") == b"\xC0\x50"
    assert crc16(b"\x01\x01") == 0x50C0


def test_empty_input_is_zero() -> None:
    assert crc16(b"") == 0x0000
    assert crc16_le_bytes(b"") == b"\x00\x00"


def test_single_byte_zero() -> None:
    # CRC of a single zero byte is still zero (initial value 0x0000, XOR 0 is no-op).
    assert crc16(b"\x00") == 0x0000


def test_crc_is_deterministic() -> None:
    payload = bytes(range(32))
    assert crc16(payload) == crc16(payload)
