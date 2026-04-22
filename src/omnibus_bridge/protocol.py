"""Omni-Link II message encode/decode.

Two framing layers:

1. **Outer packet** — what appears on the wire:

       seq(2 MSB) | mtype(1) | reserved(1=0x00) | body

   `body` is empty for handshake types 1, 5, 6; plaintext for types 2 and 7;
   AES ciphertext for types 3, 4, and 32 (application data). The ciphertext
   layer is handled in `crypto.py`, not here.

2. **Inner frame** — the plaintext inside the AES payload of a type-32 packet:

       0x21 | length(1) | msg_type(1) | data(variable) | CRC_lo | CRC_hi

   `length` = 1 + len(data) (i.e. msg_type byte + data bytes).
   CRC-16/A001 is computed over `length + msg_type + data` and transmitted
   LSB first.

This module owns both layers as pure functions. Typed helpers for the handful
of opcodes the bridge actually speaks are included at the bottom.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from .crc import crc16

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INNER_START = 0x21
OUTER_HEADER_LEN = 4
INNER_MIN_LEN = 5  # start + length + type + CRC_lo + CRC_hi


class OuterType(IntEnum):
    """Message types for the outer-packet header (spec Appendix A)."""

    NO_MSG = 0
    CLIENT_REQ_NEW_SESSION = 1
    CONTROLLER_ACK_NEW_SESSION = 2
    CLIENT_REQ_SECURE = 3
    CONTROLLER_ACK_SECURE = 4
    CLIENT_TERMINATED = 5
    CONTROLLER_TERMINATED = 6
    CONTROLLER_CANNOT_START = 7
    APP_DATA = 32


class InnerType(IntEnum):
    """Inner-frame message types (spec Appendix A, opcodes used by the bridge)."""

    ACK = 0x01
    NACK = 0x02
    END_OF_DATA = 0x03
    CONTROLLER_COMMAND = 0x14
    ENABLE_NOTIFICATIONS = 0x15
    REQ_SYSTEM_INFORMATION = 0x16
    SYSTEM_INFORMATION = 0x17
    REQ_OBJECT_TYPE_CAPACITIES = 0x1E
    OBJECT_TYPE_CAPACITIES = 0x1F
    REQ_OBJECT_PROPERTIES = 0x20
    OBJECT_PROPERTIES = 0x21
    REQ_OBJECT_STATUS = 0x22
    OBJECT_STATUS = 0x23
    OTHER_EVENT_NOTIFICATIONS = 0x37
    REQ_EXT_OBJECT_STATUS = 0x3A
    EXT_OBJECT_STATUS = 0x3B


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ProtocolError(Exception):
    """Base class for malformed Omni-Link II bytes."""


class InvalidFrame(ProtocolError):
    """Inner frame failed structural or CRC validation."""


class InvalidOuterPacket(ProtocolError):
    """Outer packet failed structural validation."""


# ---------------------------------------------------------------------------
# Outer packet
# ---------------------------------------------------------------------------


def encode_outer(seq: int, mtype: int, body: bytes = b"") -> bytes:
    """Serialise an outer packet: seq(2 MSB) + type(1) + reserved(1=0) + body."""
    if not 0 <= seq <= 0xFFFF:
        raise ValueError(f"seq must be 0..65535, got {seq}")
    if not 0 <= mtype <= 0xFF:
        raise ValueError(f"mtype must be 0..255, got {mtype}")
    return struct.pack(">HBB", seq, mtype, 0) + body


def decode_outer(packet: bytes) -> tuple[int, int, bytes]:
    """Parse an outer packet. Returns (seq, mtype, body)."""
    if len(packet) < OUTER_HEADER_LEN:
        raise InvalidOuterPacket(
            f"outer packet too short: {len(packet)}B (need {OUTER_HEADER_LEN})"
        )
    seq, mtype, _reserved = struct.unpack(">HBB", packet[:OUTER_HEADER_LEN])
    return seq, mtype, packet[OUTER_HEADER_LEN:]


# ---------------------------------------------------------------------------
# Inner frame
# ---------------------------------------------------------------------------


def encode_inner(msg_type: int, data: bytes = b"") -> bytes:
    """Serialise an inner frame: 0x21 | length | type | data | CRC_lo | CRC_hi.

    `length` = 1 (type) + len(data). CRC-16/A001 over `length + type + data`.
    """
    if not 0 <= msg_type <= 0xFF:
        raise ValueError(f"msg_type must be 0..255, got {msg_type}")
    length = 1 + len(data)
    if not 1 <= length <= 0xFF:
        raise ValueError(f"inner data too long: {len(data)}B (max 254)")
    body = bytes([length, msg_type]) + data
    crc = crc16(body)
    return bytes([INNER_START]) + body + bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def decode_inner(frame: bytes) -> tuple[int, bytes]:
    """Parse an inner frame. Returns (msg_type, data). Raises `InvalidFrame`."""
    if len(frame) < INNER_MIN_LEN:
        raise InvalidFrame(f"frame too short: {len(frame)}B (min {INNER_MIN_LEN})")
    if frame[0] != INNER_START:
        raise InvalidFrame(f"bad start byte: 0x{frame[0]:02X} (expected 0x21)")
    length = frame[1]
    if length < 1:
        raise InvalidFrame(f"length byte must be >=1, got {length}")
    end = 2 + length
    if end + 2 > len(frame):
        raise InvalidFrame(
            f"length byte says {length} but only {len(frame) - 2} bytes available"
        )
    msg_type = frame[2]
    data = frame[3:end]
    crc_observed = frame[end] | (frame[end + 1] << 8)
    crc_expected = crc16(frame[1:end])
    if crc_observed != crc_expected:
        raise InvalidFrame(
            f"CRC mismatch: observed 0x{crc_observed:04X}, "
            f"expected 0x{crc_expected:04X}"
        )
    return msg_type, data


def inner_frame_length(frame: bytes) -> int:
    """Return total bytes consumed by the inner frame at the start of `frame`.

    Used by callers peeling multiple back-to-back frames out of a single
    decrypted AES payload. Raises `InvalidFrame` if the header is malformed.
    """
    if len(frame) < 2 or frame[0] != INNER_START:
        raise InvalidFrame("not an inner frame (missing 0x21 start byte)")
    return 2 + frame[1] + 2  # start + length + (type+data) + CRC(2)


# ---------------------------------------------------------------------------
# Typed helpers — inbound (we decode these from the Translator)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReqObjectStatus:
    """REQ_OBJECT_STATUS (0x22) — Translator polling for status.

    Observed: Translator asks for Units (obj_type=2) indexes 1..36 every ~130ms.
    """

    obj_type: int
    start_index: int
    end_index: int

    @classmethod
    def decode(cls, data: bytes) -> ReqObjectStatus:
        if len(data) != 5:
            raise InvalidFrame(f"REQ_OBJECT_STATUS data must be 5B, got {len(data)}")
        obj_type, start, end = struct.unpack(">BHH", data)
        return cls(obj_type, start, end)


@dataclass(frozen=True)
class ControllerCommand:
    """CONTROLLER_COMMAND (0x14).

    Normally a Controller→client write, but in the inverted topology the
    Translator sends this UP to the bridge to report physical events (wall
    switch presses observed on the Omni-Bus wire). data = cmd + p1 + p2(2).
    """

    cmd: int
    p1: int
    p2: int

    @classmethod
    def decode(cls, data: bytes) -> ControllerCommand:
        if len(data) != 4:
            raise InvalidFrame(f"CONTROLLER_COMMAND data must be 4B, got {len(data)}")
        cmd, p1, p2 = struct.unpack(">BBH", data)
        return cls(cmd, p1, p2)

    def encode(self) -> bytes:
        return struct.pack(">BBH", self.cmd, self.p1, self.p2)


# ---------------------------------------------------------------------------
# Typed helpers — outbound (bridge → Translator)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UnitStatusRecord:
    """Single 5-byte record inside OBJECT_STATUS for Units (obj_type=2).

    `status` semantics (ALC-style, confirmed for Omni-Bus):
      0 = OFF, 1 = ON, 100..200 = level 0..100% (subtract 100).
    """

    unit: int
    status: int
    time_remaining: int = 0

    def encode(self) -> bytes:
        return struct.pack(">HBH", self.unit, self.status, self.time_remaining)


def encode_object_status_units(records: list[UnitStatusRecord]) -> bytes:
    """Encode OBJECT_STATUS (0x23) data field for Unit records."""
    body = bytes([0x02])  # obj_type = 2 (Unit)
    for r in records:
        body += r.encode()
    return body


# EXT_OBJECT_STATUS (0x3B) push carries a fixed-shape 9-byte record. The
# constant 0x07 marker after obj_type is present in every observed push;
# purpose is TBD, so we emit it unconditionally and verify the Translator
# accepts it in Phase 3 live testing.
EXT_STATUS_MARKER = 0x07


def encode_ext_object_status_push(unit: int, status: int) -> bytes:
    """Encode EXT_OBJECT_STATUS (0x3B) data for a single Unit state change.

    Wire format (9 bytes):
        02 07 <unit_MSB> <unit_LSB> <status> 00 00 00 00

    This is the inner-frame payload that wraps a seq=0 outer packet push to
    drive the Translator — the documented command path for HA→light.
    """
    if not 0 <= unit <= 0xFFFF:
        raise ValueError(f"unit must be 0..65535, got {unit}")
    if not 0 <= status <= 0xFF:
        raise ValueError(f"status must be 0..255, got {status}")
    return struct.pack(">BBHB4x", 0x02, EXT_STATUS_MARKER, unit, status)


@dataclass(frozen=True)
class ExtObjectStatusPush:
    """Parsed 0x3B seq=0 push record (for inbound Translator→bridge pushes, if any)."""

    obj_type: int
    marker: int
    unit: int
    status: int

    @classmethod
    def decode(cls, data: bytes) -> ExtObjectStatusPush:
        if len(data) != 9:
            raise InvalidFrame(f"EXT_OBJECT_STATUS push data must be 9B, got {len(data)}")
        obj_type, marker, unit, status = struct.unpack(">BBHB", data[:5])
        return cls(obj_type, marker, unit, status)
