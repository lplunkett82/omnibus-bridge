"""End-to-end Bridge integration tests.

Spin up a `Bridge` on 127.0.0.1:0, point a ScriptedTranslator at it, and
verify the full round-trip: HA-side `bridge.set_unit()` produces a seq=0
0x3B on the wire; Translator-side REQ_OBJECT_STATUS gets a state-reflected
reply; CONTROLLER_COMMAND updates the state table.
"""
from __future__ import annotations

import asyncio
import struct
import time
from pathlib import Path

import pytest

from omnibus_bridge.crypto import BLOCK_SIZE
from omnibus_bridge.main import PENDING_PUSH_TTL_S, Bridge
from omnibus_bridge.protocol import (
    InnerType,
    OuterType,
    decode_inner,
    decode_outer,
    encode_inner,
)
from omnibus_bridge.state import UnitStateTable
from tests.test_transport import PRIVATE_KEY, ScriptedTranslator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


async def _spin_up_bridge() -> Bridge:
    bridge = Bridge(PRIVATE_KEY, host="127.0.0.1", port=0)
    await bridge.start()
    return bridge


async def _connect_scripted(bridge: Bridge) -> ScriptedTranslator:
    reader, writer = await asyncio.open_connection("127.0.0.1", bridge.server.port)
    trans = ScriptedTranslator(reader, writer)
    await trans.full_handshake()
    # Let the handshake-complete event fire.
    await asyncio.sleep(0.05)
    return trans


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_req_object_status_returns_current_state() -> None:
    bridge = await _spin_up_bridge()
    try:
        # Seed state: units 4 and 18 ON.
        bridge.state.set_status(4, 1)
        bridge.state.set_status(18, 1)

        trans = await _connect_scripted(bridge)

        # Translator polls units 1..36.
        req_data = struct.pack(">BHH", 2, 1, 36)
        await trans.send_app(
            encode_inner(InnerType.REQ_OBJECT_STATUS, req_data), seq=3
        )
        _seq, plain = await trans.recv_app()
        msg_type, data = decode_inner(_strip_padding(plain))
        assert msg_type == InnerType.OBJECT_STATUS
        assert _seq == 3, "OBJECT_STATUS reply must echo REQ_OBJECT_STATUS seq"
        assert data[0] == 0x02  # obj_type = Unit
        records = data[1:]
        assert len(records) == 36 * 5
        # Parse back the status byte for each unit.
        statuses = {
            (records[i * 5] << 8) | records[i * 5 + 1]: records[i * 5 + 2]
            for i in range(36)
        }
        assert statuses[4] == 1
        assert statuses[18] == 1
        assert statuses[1] == 0
        trans.close()
    finally:
        await bridge.stop()


@pytest.mark.asyncio
async def test_enable_notifications_acked() -> None:
    bridge = await _spin_up_bridge()
    try:
        trans = await _connect_scripted(bridge)
        await trans.send_app(
            encode_inner(InnerType.ENABLE_NOTIFICATIONS, b"\x01"), seq=3
        )
        _seq, plain = await trans.recv_app()
        msg_type, data = decode_inner(_strip_padding(plain))
        assert msg_type == InnerType.ACK
        assert data == b""
        assert _seq == 3, "ACK reply must echo ENABLE_NOTIFICATIONS seq"
        trans.close()
    finally:
        await bridge.stop()


@pytest.mark.asyncio
async def test_set_unit_pushes_seq0_ext_status() -> None:
    bridge = await _spin_up_bridge()
    try:
        trans = await _connect_scripted(bridge)

        # HA turns on unit 4.
        await bridge.set_unit(4, 1)
        # Translator should receive a seq=0 push.
        seq, plain = await trans.recv_app()
        assert seq == 0
        msg_type, data = decode_inner(_strip_padding(plain))
        assert msg_type == InnerType.EXT_OBJECT_STATUS
        # data = 02 07 <unit> <status> 00 00 00 00
        assert data[0] == 0x02
        assert data[1] == 0x07
        assert (data[2] << 8) | data[3] == 4
        assert data[4] == 1
        # State table also updated.
        assert bridge.state.get(4).status == 1
        trans.close()
    finally:
        await bridge.stop()


@pytest.mark.asyncio
async def test_push_requeued_when_socket_dies_mid_send() -> None:
    """A ConnectionError during the wire write must re-queue the push, not
    silently drop it — HA commands issued in the reconnect window would
    otherwise vanish."""
    bridge = await _spin_up_bridge()
    try:
        class _DeadClient:
            async def send_inner(self, *args, **kwargs):
                raise ConnectionResetError("peer went away mid-write")

        await bridge._send_push(_DeadClient(), 4, 1)
        assert 4 in bridge._pending_pushes
        assert bridge._pending_pushes[4][0] == 1
    finally:
        await bridge.stop()


@pytest.mark.asyncio
async def test_stale_pending_push_discarded_on_flush() -> None:
    """A push queued longer than PENDING_PUSH_TTL_S ago no longer reflects
    current intent — flushing it on reconnect would be a bridge-originated
    phantom actuation. It must be dropped, not sent."""
    bridge = await _spin_up_bridge()
    try:
        await bridge.set_unit(7, 1)
        assert 7 in bridge._pending_pushes
        # Age the entry past the TTL.
        status, _ = bridge._pending_pushes[7]
        bridge._pending_pushes[7] = (status, time.monotonic() - PENDING_PUSH_TTL_S - 10)

        trans = await _connect_scripted(bridge)
        # Nothing must arrive on the wire, and the queue must be empty.
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(trans.recv_app(), timeout=0.3)
        assert bridge._pending_pushes == {}
        trans.close()
    finally:
        await bridge.stop()


@pytest.mark.asyncio
async def test_set_unit_queued_while_offline_then_flushed_on_next_handshake() -> None:
    """Pushes issued while the Translator is disconnected should be held and
    flushed as the first thing we send on the next session."""
    bridge = await _spin_up_bridge()
    try:
        # Toggle before any Translator ever connects.
        await bridge.set_unit(7, 1)
        assert bridge.state.get(7).status == 1
        # Nothing on the wire yet — no client to send to.

        # Translator connects + handshakes — bridge should immediately flush.
        trans = await _connect_scripted(bridge)
        seq, plain = await trans.recv_app()
        assert seq == 0
        msg_type, data = decode_inner(_strip_padding(plain))
        assert msg_type == InnerType.EXT_OBJECT_STATUS
        assert (data[2] << 8) | data[3] == 7
        assert data[4] == 1
        trans.close()
    finally:
        await bridge.stop()


def test_state_roundtrips_through_save_and_load(tmp_path: Path) -> None:
    """State table persists to disk and reloads — fix for 'bridge reboot
    turns all lights off' (the Translator syncs devices to our table at
    session start; a fresh all-OFF table = all lights off)."""
    path = tmp_path / "state.json"
    s1 = UnitStateTable(36)
    s1.set_status(4, 1)
    s1.set_status(33, 198)   # dimmer at 98 %
    s1.save(path)

    s2 = UnitStateTable(36)
    loaded = s2.load(path)
    assert loaded == 36
    assert s2.get(4).status == 1
    assert s2.get(33).status == 198
    assert s2.get(1).status == 0


def test_state_load_missing_file_is_noop(tmp_path: Path) -> None:
    s = UnitStateTable(36)
    assert s.load(tmp_path / "nope.json") == 0
    assert s.get(4).status == 0


def test_state_load_skips_malformed_entries(tmp_path: Path) -> None:
    """A corrupt state file must never crash startup — bad entries are
    skipped, good ones still load."""
    import json
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"units": {
        "3": {"status": 1},          # good
        "bad": 5,                     # value not a dict
        "7": {"status": "x"},         # non-numeric status
        "9": None,                    # null value
        "11": {"status": 999},        # out of range
    }}))
    s = UnitStateTable(36)
    assert s.load(path) == 1
    assert s.get(3).status == 1
    assert s.get(11).status == 0


def test_state_load_handles_non_dict_json(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("[1, 2, 3]")
    s = UnitStateTable(36)
    assert s.load(path) == 0


def test_bridge_restores_state_from_file_on_startup(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    # Prime the file via a pre-bridge state table.
    seed = UnitStateTable(36)
    seed.set_status(11, 1)
    seed.set_status(33, 165)
    seed.save(path)

    bridge = Bridge(PRIVATE_KEY, host="127.0.0.1", port=0, state_file=path)
    assert bridge.state.get(11).status == 1
    assert bridge.state.get(33).status == 165


def test_button_dim_alternates_direction_between_holds() -> None:
    """The Translator always sends a decreasing UNIT_LEVEL_PCT stream during
    a long-press. The published level sensor should alternate direction
    across consecutive holds: hold 1 = down, hold 2 = up, hold 3 = down."""
    bridge = Bridge(PRIVATE_KEY, host="127.0.0.1", port=0)
    unit = 29

    # --- hold 1 (bridge starts with direction="up", flips to "down") ---
    # Stream: 98 → 75 → 47 (trans deltas -23, -28). From initial 100:
    # new stream baseline = 98 (no level change); then 75: delta -23, down → 100-23=77; then 47: -28 → 49.
    l1a = bridge._compute_button_level(unit, 100 + 98)
    l1b = bridge._compute_button_level(unit, 100 + 75)
    l1c = bridge._compute_button_level(unit, 100 + 47)
    assert (l1a, l1b, l1c) == (100, 77, 49)

    # --- hold 2 (after a gap, flips to "up") ---
    # Force a fresh stream by resetting the time.
    ds = bridge._button_dim[unit]
    ds.last_event_time = None
    # Stream: 99 → 70 → 40 (trans deltas -29, -30). Starting virtual_level=49.
    # new stream baseline = 99 (no change); 70: delta -29, up → 49+29=78; 40: -30 → 100 clamp.
    l2a = bridge._compute_button_level(unit, 100 + 99)
    l2b = bridge._compute_button_level(unit, 100 + 70)
    l2c = bridge._compute_button_level(unit, 100 + 40)
    assert l2a == 49           # baseline, no change
    assert l2b == 78           # +29
    assert l2c == 100          # clamped at 100

    # --- hold 3 (flips back to "down") ---
    ds.last_event_time = None
    l3a = bridge._compute_button_level(unit, 100 + 99)
    l3b = bridge._compute_button_level(unit, 100 + 70)  # delta -29, down
    assert l3a == 100
    assert l3b == 71


def test_button_short_press_resets_dim_state() -> None:
    """Short-press ON/OFF (status=1 / status=0) resets the alternation
    state — the next long-press is a fresh cycle."""
    bridge = Bridge(PRIVATE_KEY, host="127.0.0.1", port=0)
    unit = 29
    # Prime with a hold to get some virtual level.
    bridge._compute_button_level(unit, 100 + 90)
    bridge._compute_button_level(unit, 100 + 50)
    # Short press OFF.
    assert bridge._compute_button_level(unit, 0) == 0
    # Short press ON.
    assert bridge._compute_button_level(unit, 1) == 100


@pytest.mark.asyncio
async def test_controller_command_unit_level_pct_sets_brightness() -> None:
    """Long-press dimming on a wall switch fires CONTROLLER_COMMAND cmd=9
    (UNIT_LEVEL_PCT) with p1=<percent> at ~4 Hz during the hold. The linked
    dimmer's state should track each update so HA sees live brightness."""
    bridge = await _spin_up_bridge()
    try:
        trans = await _connect_scripted(bridge)

        # Simulate the dim stream: unit 33 at 98%, then 75%, then 47%.
        for seq, pct in enumerate([98, 75, 47], start=3):
            cc_data = struct.pack(">BBH", 9, pct, 33)
            await trans.send_app(
                encode_inner(InnerType.CONTROLLER_COMMAND, cc_data), seq=seq
            )
            ack_seq, ack_plain = await asyncio.wait_for(trans.recv_app(), timeout=1.0)
            ack_type, _ = decode_inner(_strip_padding(ack_plain))
            assert ack_type == InnerType.ACK and ack_seq == seq

        # ALC-style encoding: 100 + percent.
        assert bridge.state.get(33).status == 100 + 47
        trans.close()
    finally:
        await bridge.stop()


@pytest.mark.asyncio
async def test_controller_command_updates_state_and_acks_with_echo_seq() -> None:
    """Physical event from Translator updates bridge state and gets an ACK
    with echoed seq (matches OmniPro's observed behavior). The bridge must
    NOT 0x3B-push the state back — the Translator is the source of truth
    for the physical event."""
    bridge = await _spin_up_bridge()
    try:
        trans = await _connect_scripted(bridge)

        # Send a CONTROLLER_COMMAND: cmd=1 (UNIT_ON), p1=0, p2=9 (unit 9 turned on at the wall).
        cc_data = struct.pack(">BBH", 1, 0, 9)
        await trans.send_app(
            encode_inner(InnerType.CONTROLLER_COMMAND, cc_data), seq=3
        )
        # Bridge must respond with ACK echoing seq=3.
        ack_seq, ack_plain = await asyncio.wait_for(trans.recv_app(), timeout=1.0)
        ack_type, _ = decode_inner(_strip_padding(ack_plain))
        assert ack_type == InnerType.ACK
        assert ack_seq == 3, f"ACK must echo inbound seq (got {ack_seq})"
        # State updated.
        assert bridge.state.get(9).status == 1
        # No further pushes — no 0x3B echo back.
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(trans.recv_app(), timeout=0.2)
        trans.close()
    finally:
        await bridge.stop()


@pytest.mark.asyncio
async def test_set_unit_without_client_is_noop_on_wire() -> None:
    """set_unit should update state even when no Translator is connected."""
    bridge = await _spin_up_bridge()
    try:
        await bridge.set_unit(4, 1)
        assert bridge.state.get(4).status == 1
    finally:
        await bridge.stop()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strip_padding(plain: bytes) -> bytes:
    """Trim zero-padding past the inner frame (AES block-padded to 16B)."""
    if len(plain) < 2 or plain[0] != 0x21:
        return plain
    inner_total = 2 + plain[1] + 2
    return plain[:inner_total]
