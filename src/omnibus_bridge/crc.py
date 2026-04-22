"""CRC-16 with polynomial 0xA001 (reflected 0x8005), initial value 0x0000.

Used by the Omni-Link II inner frame. Per spec Appendix B, the CRC is computed
over `length + type + data` and transmitted LSB first, MSB second.
"""
from __future__ import annotations


def crc16(data: bytes) -> int:
    """Compute CRC-16/A001 of *data*, returning a 16-bit int."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def crc16_le_bytes(data: bytes) -> bytes:
    """Return CRC-16 of *data* as two bytes, LSB first (wire order)."""
    crc = crc16(data)
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])
