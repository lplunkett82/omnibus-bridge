"""Protocol encode/decode tests.

Fixtures in `tests/fixtures/samples.py` are exact bytes from a real
OmniPro II ↔ Translator session. Every fixture must round-trip:
decode(fixture) → encode(...) == fixture.
"""
from __future__ import annotations

import pytest

from omnibus_bridge.protocol import (
    ControllerCommand,
    ExtObjectStatusPush,
    InnerType,
    InvalidFrame,
    InvalidOuterPacket,
    OuterType,
    ReqObjectStatus,
    UnitStatusRecord,
    decode_inner,
    decode_outer,
    encode_ext_object_status_push,
    encode_inner,
    encode_object_status_units,
    encode_outer,
    inner_frame_length,
)
from tests.fixtures.samples import (
    CONTROLLER_COMMAND_UNIT1_OFF,
    ENABLE_NOTIFICATIONS_ON,
    EXT_OBJECT_STATUS_PUSH_UNIT1_OFF,
    EXT_OBJECT_STATUS_PUSH_UNIT4_ON,
    HANDSHAKE_PROTOCOL_VERSION,
    HANDSHAKE_SESSION_ID,
    HANDSHAKE_TYPE1,
    HANDSHAKE_TYPE2,
    OBJECT_STATUS_36_UNITS,
    REQ_OBJECT_STATUS_UNITS_1_36,
)


# ---------------------------------------------------------------------------
# Outer packet
# ---------------------------------------------------------------------------


def test_outer_encode_type1_matches_wire() -> None:
    # Type 1 handshake: seq=1, no body.
    assert encode_outer(seq=1, mtype=OuterType.CLIENT_REQ_NEW_SESSION) == HANDSHAKE_TYPE1


def test_outer_decode_type2_from_wire() -> None:
    seq, mtype, body = decode_outer(HANDSHAKE_TYPE2)
    assert seq == 1
    assert mtype == OuterType.CONTROLLER_ACK_NEW_SESSION
    # body = 2B protocol_version + 5B session_id
    assert body[:2] == HANDSHAKE_PROTOCOL_VERSION.to_bytes(2, "big")
    assert body[2:7] == HANDSHAKE_SESSION_ID


def test_outer_round_trip_all_types() -> None:
    for seq in (0, 1, 0x1234, 0xFFFF):
        for mtype in (0, 1, 2, 3, 4, 5, 32):
            for body in (b"", b"\x00\x01\x02", b"\xFF" * 16):
                pkt = encode_outer(seq, mtype, body)
                s, m, b = decode_outer(pkt)
                assert (s, m, b) == (seq, mtype, body)


def test_outer_decode_rejects_truncated() -> None:
    with pytest.raises(InvalidOuterPacket):
        decode_outer(b"\x00\x01\x01")  # 3 bytes, need 4


def test_outer_encode_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        encode_outer(seq=-1, mtype=1)
    with pytest.raises(ValueError):
        encode_outer(seq=0x10000, mtype=1)
    with pytest.raises(ValueError):
        encode_outer(seq=0, mtype=256)


def test_outer_reserved_byte_is_zero() -> None:
    # The 4th byte of the outer header is always 0x00 per spec.
    pkt = encode_outer(seq=0x1234, mtype=32, body=b"\xFF")
    assert pkt[3] == 0x00


# ---------------------------------------------------------------------------
# Inner frame
# ---------------------------------------------------------------------------


def test_inner_spec_sample_ack_round_trip() -> None:
    # Spec Appendix B sample: `21 01 01 C0 50` — ACK (type 0x01), no data.
    # CRC over length+type (01 01) is 0x50C0, serialised LSB-first as C0 50.
    frame = encode_inner(InnerType.ACK)
    assert frame == bytes.fromhex("210101C050")
    msg_type, data = decode_inner(frame)
    assert msg_type == InnerType.ACK
    assert data == b""


def test_inner_decode_rejects_bad_start() -> None:
    with pytest.raises(InvalidFrame):
        decode_inner(bytes.fromhex("20010150C0"))  # start byte 0x20 not 0x21


def test_inner_decode_rejects_bad_crc() -> None:
    # Flip the last byte of a valid frame — CRC should fail.
    frame = bytearray(REQ_OBJECT_STATUS_UNITS_1_36)
    frame[-1] ^= 0xFF
    with pytest.raises(InvalidFrame, match="CRC mismatch"):
        decode_inner(bytes(frame))


def test_inner_decode_rejects_truncated() -> None:
    with pytest.raises(InvalidFrame):
        decode_inner(b"\x21\x05\x22")  # length says 5 but no data/CRC follow


def test_inner_encode_rejects_zero_length() -> None:
    # length byte must be >=1 (type byte is part of the length).
    # encode_inner computes length from data — an empty msg_type still has length=1.
    # But enforcing max 254 data bytes:
    with pytest.raises(ValueError):
        encode_inner(msg_type=0x14, data=b"\x00" * 255)


def test_inner_frame_length_helper() -> None:
    assert inner_frame_length(REQ_OBJECT_STATUS_UNITS_1_36) == len(REQ_OBJECT_STATUS_UNITS_1_36)
    assert inner_frame_length(OBJECT_STATUS_36_UNITS) == len(OBJECT_STATUS_36_UNITS)


# ---------------------------------------------------------------------------
# Fixture round-trips — every wire fixture must survive decode → encode
# ---------------------------------------------------------------------------


def test_fixture_req_object_status_decodes() -> None:
    msg_type, data = decode_inner(REQ_OBJECT_STATUS_UNITS_1_36)
    assert msg_type == InnerType.REQ_OBJECT_STATUS
    req = ReqObjectStatus.decode(data)
    assert req == ReqObjectStatus(obj_type=2, start_index=1, end_index=36)


def test_fixture_req_object_status_round_trips() -> None:
    msg_type, data = decode_inner(REQ_OBJECT_STATUS_UNITS_1_36)
    assert encode_inner(msg_type, data) == REQ_OBJECT_STATUS_UNITS_1_36


def test_fixture_object_status_decodes_all_36_units() -> None:
    msg_type, data = decode_inner(OBJECT_STATUS_36_UNITS)
    assert msg_type == InnerType.OBJECT_STATUS
    assert data[0] == 0x02  # obj_type = Unit
    records = data[1:]
    assert len(records) == 180  # 36 × 5B

    # ON units per the capture: 1, 18, 29, 30, 31, 33, 35.
    on_units = set()
    for i in range(36):
        r = records[i * 5 : (i + 1) * 5]
        unit = (r[0] << 8) | r[1]
        status = r[2]
        if status == 1:
            on_units.add(unit)
    assert on_units == {1, 18, 29, 30, 31, 33, 35}


def test_fixture_object_status_round_trips_from_records() -> None:
    # Rebuild the data field from UnitStatusRecord objects and confirm the
    # full frame re-encodes byte-identically to the wire.
    msg_type, data = decode_inner(OBJECT_STATUS_36_UNITS)
    on_units = {1, 18, 29, 30, 31, 33, 35}
    records = [
        UnitStatusRecord(unit=u, status=1 if u in on_units else 0)
        for u in range(1, 37)
    ]
    rebuilt_data = encode_object_status_units(records)
    assert rebuilt_data == data
    assert encode_inner(InnerType.OBJECT_STATUS, rebuilt_data) == OBJECT_STATUS_36_UNITS


def test_fixture_ext_object_status_push_unit4_on() -> None:
    msg_type, data = decode_inner(EXT_OBJECT_STATUS_PUSH_UNIT4_ON)
    assert msg_type == InnerType.EXT_OBJECT_STATUS
    push = ExtObjectStatusPush.decode(data)
    assert push.obj_type == 2
    assert push.marker == 0x07
    assert push.unit == 4
    assert push.status == 1


def test_fixture_ext_object_status_push_round_trip() -> None:
    rebuilt_data = encode_ext_object_status_push(unit=4, status=1)
    assert encode_inner(InnerType.EXT_OBJECT_STATUS, rebuilt_data) == EXT_OBJECT_STATUS_PUSH_UNIT4_ON

    rebuilt_off = encode_ext_object_status_push(unit=1, status=1)
    assert encode_inner(InnerType.EXT_OBJECT_STATUS, rebuilt_off) == EXT_OBJECT_STATUS_PUSH_UNIT1_OFF


def test_fixture_controller_command_unit1_off() -> None:
    msg_type, data = decode_inner(CONTROLLER_COMMAND_UNIT1_OFF)
    assert msg_type == InnerType.CONTROLLER_COMMAND
    cmd = ControllerCommand.decode(data)
    assert cmd == ControllerCommand(cmd=0, p1=0, p2=1)  # UNIT_OFF, unit 1
    # Round-trip through the encoder.
    assert encode_inner(msg_type, cmd.encode()) == CONTROLLER_COMMAND_UNIT1_OFF


def test_fixture_enable_notifications_on() -> None:
    msg_type, data = decode_inner(ENABLE_NOTIFICATIONS_ON)
    assert msg_type == InnerType.ENABLE_NOTIFICATIONS
    assert data == b"\x01"
    # Round-trip.
    assert encode_inner(msg_type, data) == ENABLE_NOTIFICATIONS_ON
