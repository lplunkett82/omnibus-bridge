"""Device scanner — reads the Omni-Bus device list from the Translator.

Speaks the 43690 *device-enumeration* dialect (see docs/PROTOCOL.md). Opens
a short-lived TCP session, sends two static discovery frames (replayed from
the capture of OMNIBUS Software's "List Devices" feature), reads the
Translator's push of device records, parses name + unit number from each,
and returns a list of `Device` records.

This is a one-shot bootstrap used by the HA add-on at startup (and by
`tools/scan.py` for manual runs). It is NOT part of the runtime 4369
Omni-Link II controller path.

Safety: this channel is the same one OMNIBUS Software uses. Don't run the
scanner while OMNIBUS Software is actively uploading/downloading — the
Translator arbitrates per-TCP-session, not per-operation.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# -- Wire format ------------------------------------------------------------

FRAME_START = 0x7E
FRAME_END = 0x7F

# The two discovery frames, replayed byte-for-byte from OMNIBUS Software's
# "List Devices" capture (2026-04-22). Each frame is `7E <body> <crc> 7F`
# where the body is 15 bytes and the CRC is CRC-8/MAXIM (poly 0x8C) with
# init=0x05.
DISCOVERY_FRAME_1 = bytes([
    0x7E,
    0x03, 0x01, 0x12, 0x34,              # framing marker
    0x00, 0x00, 0x00, 0x00,              # src device ID (zero = "don't know yet")
    0x00, 0x00, 0x00, 0x00,              # dst device ID (zero = broadcast-ish)
    0x02, 0x01, 0x00,                    # op (discovery)
    0x8B,                                # CRC-8/MAXIM init=0x05
    0x7F,
])
DISCOVERY_FRAME_2 = bytes([
    0x7E,
    0x03, 0x01, 0x12, 0x34,
    0x00, 0x00, 0x00, 0x00,              # src device ID (still unknown at this point)
    0xFF, 0xFF, 0xFF, 0xFF,              # dst device ID (0xFFFFFFFF = broadcast to all)
    0x02, 0x01, 0x00,
    0xF9,
    0x7F,
])

# Record byte offsets within the raw (7E/7F-stripped, CRC-stripped) body of
# a T->PC device record frame. Three record kinds appear in the wire:
#
#   * Relay channel  (49B raw, 48B body) — one per 4CH relay channel.
#                    Name field [0x17..0x25] is 15 bytes; unit at [0x26];
#                    `1E 5A` trailer at [0x2E..0x2F].
#   * Wall-switch    (47B raw, 46B body) — one per button on a multi-button
#                    wall station. Name field [0x17..0x26] is 16 bytes;
#                    unit at [0x27]; no `1E 5A` trailer.
#   * Dimmer         (53B raw, 52B body) — single dimmer module. Same name
#                    field/unit-offset as wall-switch, but Translator stores
#                    no name (all zeros). Followed by extra brightness/state
#                    bytes.
#
# CRCs on these record bodies use a non-standard algorithm we have not
# cracked. Read-only scanning makes the CRC irrelevant — TCP guarantees
# integrity end-to-end.

# All three record kinds share the same field layout for the parts we care
# about: a 23-byte header, a 15-byte name, and a unit-number byte. The frame
# length and the bytes after the unit number distinguish them.
NAME_OFFSET = 0x17
NAME_LENGTH = 15
UNIT_NUMBER_OFFSET = 0x26
RELAY_TRAILER_OFFSET = 0x2E  # '1E 5A' marker present only on relay records


RELAY = "relay"
WALLSWITCH_BUTTON = "wallswitch_button"
DIMMER = "dimmer"
FAN = "fan"
LOCK = "lock"
TRANSLATOR = "translator"


@dataclass
class Device:
    """A single device discovered on the Omni-Bus wire.

    For regular devices (relay / wall-switch / dimmer), only `unit_number`,
    `name`, and `device_type` are meaningful. The Translator record additionally
    populates `ip`, `netmask`, `gateway`, `port`, and `device_id` from the
    discovery-reply frame, leaving `unit_number` as 0 (Translator has no unit
    number in the user addressable space).
    """

    unit_number: int
    name: str
    device_type: str  # one of RELAY, WALLSWITCH_BUTTON, DIMMER, FAN, LOCK, TRANSLATOR
    raw_frame: bytes = field(repr=False)
    header: bytes = field(repr=False, default=b"")
    # Translator-only metadata (None for other device kinds)
    ip: str | None = None
    netmask: str | None = None
    gateway: str | None = None
    port: int | None = None
    device_id: str | None = None  # 4-byte hex, e.g. "XXXXXXXX"


# -- Frame parsing ----------------------------------------------------------


def _decode_name(raw_name: bytes) -> str:
    """Decode a 16-byte name field.

    Some characters have bit 7 set as a wire-encoding artifact — mask it off
    to recover clean ASCII. Null bytes pad the field; stop at the first one.
    """
    out = []
    for b in raw_name:
        if b == 0x00:
            break
        c = b & 0x7F
        if 32 <= c < 127:
            out.append(chr(c))
    return "".join(out).rstrip()


def parse_device_record(raw: bytes) -> Device | None:
    """Parse a device record frame (raw = bytes between 7E and 7F markers,
    including the trailing CRC byte).

    Dispatches by frame length to one of the three known record kinds:
      * 49 raw → relay channel (must have `1E 5A` trailer; empty name rejected)
      * 47 raw → wall-switch button (empty name allowed; consumer can default)
      * 53 raw → dimmer (Translator stores no name; consumer must default)

    Returns None for unknown lengths, malformed records, or empty relay slots.
    """
    if len(raw) < UNIT_NUMBER_OFFSET + 1:
        return None
    if len(raw) == 49:
        return _parse_record(raw, RELAY, require_trailer=True, allow_empty_name=False)
    if len(raw) == 47:
        return _parse_record(raw, WALLSWITCH_BUTTON, require_trailer=False, allow_empty_name=True)
    if len(raw) == 53:
        return _parse_record(raw, DIMMER, require_trailer=False, allow_empty_name=True)
    if len(raw) == 71:
        return _parse_translator(raw)
    return None


# Field offsets within the 71-byte discovery reply. Mapped against the two
# frames captured in omnibus_listdevices_20260422_103628.pcap:
#   bytes[0x01..0x04] — Translator's assigned 4-byte device ID
#   bytes[0x2E..0x31] — Translator IP (big-endian IPv4)
#   bytes[0x32..0x35] — netmask (big-endian IPv4)
#   bytes[0x36..0x39] — gateway (big-endian IPv4)
#   bytes[0x3A..0x3B] — Translator listen port (big-endian u16; observed 0xAAAA = 43690)
TRANSLATOR_DEVICE_ID_OFFSET = 0x01
TRANSLATOR_IP_OFFSET = 0x2E
TRANSLATOR_NETMASK_OFFSET = 0x32
TRANSLATOR_GATEWAY_OFFSET = 0x36
TRANSLATOR_PORT_OFFSET = 0x3A


def _parse_translator(raw: bytes) -> Device | None:
    """Parse a 71-byte discovery reply into a Translator Device record.

    Two of these frames appear at the start of each List-Devices burst (one
    with dst=00000000, one with dst=FFFFFFFF). They contain identical
    identity/network fields — we accept the first and ignore duplicates in
    the scan() loop.
    """
    def _ip(off: int) -> str:
        return ".".join(str(b) for b in raw[off : off + 4])

    device_id = raw[TRANSLATOR_DEVICE_ID_OFFSET : TRANSLATOR_DEVICE_ID_OFFSET + 4].hex().upper()
    ip = _ip(TRANSLATOR_IP_OFFSET)
    netmask = _ip(TRANSLATOR_NETMASK_OFFSET)
    gateway = _ip(TRANSLATOR_GATEWAY_OFFSET)
    port = (raw[TRANSLATOR_PORT_OFFSET] << 8) | raw[TRANSLATOR_PORT_OFFSET + 1]
    return Device(
        unit_number=0,
        name="Translator",
        device_type=TRANSLATOR,
        raw_frame=bytes(raw),
        header=bytes(raw[:NAME_OFFSET]),
        ip=ip,
        netmask=netmask,
        gateway=gateway,
        port=port,
        device_id=device_id,
    )


def _parse_record(
    raw: bytes,
    device_type: str,
    *,
    require_trailer: bool,
    allow_empty_name: bool,
) -> Device | None:
    if require_trailer:
        if raw[RELAY_TRAILER_OFFSET] != 0x1E or raw[RELAY_TRAILER_OFFSET + 1] != 0x5A:
            return None
    name = _decode_name(raw[NAME_OFFSET : NAME_OFFSET + NAME_LENGTH])
    if not name and not allow_empty_name:
        return None
    unit = raw[UNIT_NUMBER_OFFSET]
    if not 1 <= unit <= 255:
        return None
    return Device(
        unit_number=unit,
        name=name,
        device_type=device_type,
        raw_frame=bytes(raw),
        header=bytes(raw[:NAME_OFFSET]),
    )


def split_frames(stream: bytes) -> list[bytes]:
    """Split a stream of HDLC-framed bytes into individual 7E…7F frame bodies.

    Returns a list of `raw` byte sequences — everything strictly between each
    7E start marker and the next 7F end marker. 7E bytes inside a frame (none
    observed in practice) would currently terminate the frame prematurely;
    acceptable for read-only parsing given the empirical absence of embedded
    delimiter bytes.
    """
    frames: list[bytes] = []
    i = 0
    n = len(stream)
    while i < n:
        if stream[i] != FRAME_START:
            i += 1
            continue
        start = i + 1
        end = start
        while end < n and stream[end] != FRAME_END:
            end += 1
        if end >= n:
            break  # truncated frame
        if end > start:
            frames.append(stream[start:end])
        i = end + 1
    return frames


# -- Async client -----------------------------------------------------------


class ScanError(Exception):
    """Raised when the scanner cannot complete a scan."""


async def scan(
    host: str,
    port: int = 43690,
    *,
    read_timeout: float = 3.0,
    total_timeout: float = 10.0,
) -> list[Device]:
    """Run a one-shot device scan against the Translator.

    Connects, sends both discovery frames, drains responses until
    `read_timeout` elapses with no new bytes (the Translator sends an
    unsolicited burst and then goes quiet), closes the socket, parses
    frames, returns the discovered devices sorted by unit number.

    Raises `ScanError` on connection failure, timeout, or if no frames
    parse cleanly.
    """
    log.info("scanner connecting to %s:%d", host, port)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=total_timeout
        )
    except (OSError, asyncio.TimeoutError) as e:
        raise ScanError(f"cannot connect to {host}:{port}: {e}") from e

    try:
        # Send both discovery frames back-to-back with a small pause between
        # them to mirror what OMNIBUS Software did on the wire.
        writer.write(DISCOVERY_FRAME_1)
        await writer.drain()
        await asyncio.sleep(0.1)
        writer.write(DISCOVERY_FRAME_2)
        await writer.drain()

        # Read until the Translator goes quiet. Use a short idle timeout
        # since the full burst of 40 frames arrives in < 1s typically.
        buf = bytearray()
        deadline = asyncio.get_running_loop().time() + total_timeout
        while asyncio.get_running_loop().time() < deadline:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=read_timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf.extend(chunk)
        log.info("scanner received %d bytes", len(buf))
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionResetError):
            pass

    frames = split_frames(bytes(buf))
    log.info("scanner parsed %d raw frames", len(frames))
    devices: list[Device] = []
    seen_translator = False
    for f in frames:
        if len(f) < 2:
            continue
        dev = parse_device_record(f)
        if dev is None:
            continue
        if dev.device_type == TRANSLATOR:
            # The Translator announces itself in two back-to-back 71B frames
            # (dst=0 then dst=FFFFFFFF). Same identity; keep only the first.
            if seen_translator:
                continue
            seen_translator = True
        devices.append(dev)

    # Sort: Translator first (diagnostic), then relays, wall-switches, dimmers.
    type_order = {TRANSLATOR: -1, RELAY: 0, WALLSWITCH_BUTTON: 1, DIMMER: 2}
    devices.sort(key=lambda d: (type_order.get(d.device_type, 99), d.unit_number))
    if not devices:
        raise ScanError(
            f"scan of {host}:{port} parsed 0 devices from {len(frames)} frames; "
            "check that OMNIBUS Software is not running"
        )
    return devices
