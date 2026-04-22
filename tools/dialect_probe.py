"""Phase 1 Omni-Link II dialect probe.

Connects to the Translator at 192.0.2.10:4106, completes a secure session,
sends REQ_SYSTEM_INFORMATION (0x16), decodes the reply, and terminates cleanly.

READ-ONLY: does not issue any CONTROLLER COMMAND or write operations.

Usage:
    python -m tools.dialect_probe                 # uses defaults
    python -m tools.dialect_probe --host 192.0.2.10 --port 4106

Reads AES-128 private key from .env as OMNILINK_KEY1 + OMNILINK_KEY2
(each 16 hex chars, concatenated to form the 128-bit private key).
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from dataclasses import dataclass
from pathlib import Path

# Allow running from repo root without installing the package.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from dotenv import load_dotenv  # noqa: E402

from omnibus_bridge.crc import crc16_le_bytes  # noqa: E402
from omnibus_bridge.crypto import (  # noqa: E402
    BLOCK_SIZE,
    decrypt,
    derive_session_key,
    encrypt,
)

DEFAULT_HOST = "192.0.2.10"
DEFAULT_PORT = 4106

# Outer message types (spec Appendix A).
MSG_NEW_SESSION_REQ = 1
MSG_NEW_SESSION_ACK = 2
MSG_SECURE_REQ = 3
MSG_SECURE_ACK = 4
MSG_CLIENT_TERM = 5
MSG_CONTROLLER_TERM = 6
MSG_NEW_SESSION_FAIL = 7
MSG_APP_DATA = 32  # 0x20: Omni-Link II application data (encrypted)

# Inner frame types we use in Phase 1.
INNER_ACK = 0x01
INNER_NACK = 0x02
INNER_END_OF_DATA = 0x03
INNER_REQ_SYSTEM_INFORMATION = 0x16
INNER_SYSTEM_INFORMATION = 0x17

START_BYTE = 0x21


class ProtocolError(Exception):
    """Raised when the wire protocol is violated."""


@dataclass
class OuterPacket:
    seq: int
    msg_type: int
    data: bytes


# -- framing ------------------------------------------------------------------

def pack_outer(seq: int, msg_type: int, data: bytes) -> bytes:
    return seq.to_bytes(2, "big") + bytes([msg_type, 0x00]) + data


def build_inner_frame(inner_type: int, data: bytes) -> bytes:
    """Build start + length + type + data + crc_lo + crc_hi."""
    length = 1 + len(data)  # type byte + data
    if length > 0xFF:
        raise ValueError(f"inner frame too long: {length}")
    body = bytes([length, inner_type]) + data
    return bytes([START_BYTE]) + body + crc16_le_bytes(body)


def parse_inner_frame(plaintext: bytes) -> tuple[int, bytes]:
    """Return (inner_type, data). Verifies start byte and CRC."""
    if len(plaintext) < 5:
        raise ProtocolError(f"inner frame too short: {len(plaintext)} bytes")
    if plaintext[0] != START_BYTE:
        raise ProtocolError(f"bad start byte: 0x{plaintext[0]:02X}")
    length = plaintext[1]
    total = 2 + length + 2  # start excluded; length+type+data + crc
    if len(plaintext) < total + 1:
        raise ProtocolError(f"inner frame truncated: need {total + 1}, have {len(plaintext)}")
    body = plaintext[1 : 2 + length]  # length + type + data
    crc_lo, crc_hi = plaintext[2 + length], plaintext[3 + length]
    expected = crc16_le_bytes(body)
    if bytes([crc_lo, crc_hi]) != expected:
        raise ProtocolError(
            f"inner CRC mismatch: got {crc_lo:02X}{crc_hi:02X}, expected {expected.hex().upper()}"
        )
    inner_type = plaintext[2]
    data = plaintext[3 : 2 + length]
    return inner_type, data


# -- transport ----------------------------------------------------------------

async def _read_outer_plain(
    reader: asyncio.StreamReader, expected_data_len: int
) -> OuterPacket:
    hdr = await reader.readexactly(4)
    seq = int.from_bytes(hdr[:2], "big")
    msg_type = hdr[2]
    data = await reader.readexactly(expected_data_len) if expected_data_len else b""
    return OuterPacket(seq=seq, msg_type=msg_type, data=data)


async def _read_outer_encrypted(
    reader: asyncio.StreamReader, session_key: bytes
) -> tuple[OuterPacket, bytes]:
    """Read a type-32 (or other encrypted) packet. Returns (packet, decrypted_plaintext)."""
    hdr = await reader.readexactly(4)
    seq = int.from_bytes(hdr[:2], "big")
    msg_type = hdr[2]
    # Read the first ciphertext block, decrypt to peek at inner frame length.
    first_ct = await reader.readexactly(BLOCK_SIZE)
    first_pt = decrypt(first_ct, session_key, seq)
    if first_pt[0] != START_BYTE:
        raise ProtocolError(f"bad inner start byte: 0x{first_pt[0]:02X}")
    inner_length = first_pt[1]
    inner_total = 1 + 1 + inner_length + 2  # start + length + (type+data) + crc
    blocks_needed = (inner_total + BLOCK_SIZE - 1) // BLOCK_SIZE
    extra_bytes = (blocks_needed - 1) * BLOCK_SIZE
    if extra_bytes:
        rest_ct = await reader.readexactly(extra_bytes)
        rest_pt = decrypt(rest_ct, session_key, seq)
        plaintext = first_pt + rest_pt
    else:
        plaintext = first_pt
    return OuterPacket(seq=seq, msg_type=msg_type, data=first_ct + (rest_ct if extra_bytes else b"")), plaintext


# -- key loading --------------------------------------------------------------

def load_private_key() -> bytes:
    load_dotenv(_REPO_ROOT / ".env")
    k1 = os.environ.get("OMNILINK_KEY1", "").strip().replace("-", "").replace(":", "")
    k2 = os.environ.get("OMNILINK_KEY2", "").strip().replace("-", "").replace(":", "")
    if len(k1) != 16 or len(k2) != 16:
        raise SystemExit(
            "OMNILINK_KEY1 and OMNILINK_KEY2 must each be 16 hex chars in .env"
        )
    try:
        return bytes.fromhex(k1 + k2)
    except ValueError as e:
        raise SystemExit(f"invalid hex in OMNILINK_KEY1/KEY2: {e}")


# -- main probe ---------------------------------------------------------------

# Model number lookup from spec (extend as we learn).
MODEL_NAMES = {
    2: "Omni",
    3: "Omni II",
    4: "Omni LT",
    15: "Lumina",
    16: "OmniPro II",
    30: "Omni IIe",
    36: "Lumina",
    37: "Lumina Pro",
    38: "Omni IIe (Pro)",
}


async def probe(host: str, port: int, timeout: float) -> int:
    private_key = load_private_key()

    print(f"Connecting to {host}:{port} ...")
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout
    )

    try:
        # 1. Client requests new session (type 1, seq=0, no data).
        writer.write(pack_outer(0, MSG_NEW_SESSION_REQ, b""))
        await writer.drain()

        # 2. Controller replies with protocol version + session id.
        pkt = await asyncio.wait_for(_read_outer_plain(reader, 7), timeout=timeout)
        if pkt.msg_type == MSG_NEW_SESSION_FAIL:
            raise ProtocolError("controller rejected new session (type 7)")
        if pkt.msg_type != MSG_NEW_SESSION_ACK:
            raise ProtocolError(f"expected NEW_SESSION_ACK (2), got {pkt.msg_type}")
        protocol_version = int.from_bytes(pkt.data[:2], "big")
        session_id = pkt.data[2:7]
        print(f"  Protocol version: {protocol_version}")
        print(f"  Session ID:       {session_id.hex().upper()}")

        session_key = derive_session_key(private_key, session_id)

        # 3. Client sends encrypted session_id (type 3, seq=1).
        enc_session_id = encrypt(session_id, session_key, seq=1)
        writer.write(pack_outer(1, MSG_SECURE_REQ, enc_session_id))
        await writer.drain()

        # 4. Controller replies with encrypted session_id (type 4).
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        seq_in = int.from_bytes(hdr[:2], "big")
        msg_type_in = hdr[2]
        if msg_type_in != MSG_SECURE_ACK:
            raise ProtocolError(
                f"expected SECURE_ACK (4), got {msg_type_in} (seq {seq_in})"
            )
        ct = await asyncio.wait_for(reader.readexactly(BLOCK_SIZE), timeout=timeout)
        pt = decrypt(ct, session_key, seq_in)
        returned_sid = pt[:5]
        if returned_sid != session_id:
            raise ProtocolError(
                "session_id mismatch after secure handshake — likely wrong keys.\n"
                f"  sent:     {session_id.hex().upper()}\n"
                f"  received: {returned_sid.hex().upper()}"
            )
        print("  Secure session established.")

        # 5. REQ_SYSTEM_INFORMATION (0x16), seq=2.
        inner = build_inner_frame(INNER_REQ_SYSTEM_INFORMATION, b"")
        writer.write(pack_outer(2, MSG_APP_DATA, encrypt(inner, session_key, seq=2)))
        await writer.drain()

        # 6. Read SYSTEM INFORMATION (0x17).
        pkt, plaintext = await asyncio.wait_for(
            _read_outer_encrypted(reader, session_key), timeout=timeout
        )
        if pkt.msg_type != MSG_APP_DATA:
            raise ProtocolError(f"expected APP_DATA (32), got {pkt.msg_type}")
        inner_type, inner_data = parse_inner_frame(plaintext)
        if inner_type == INNER_NACK:
            raise ProtocolError("controller returned NACK to SYSTEM_INFORMATION request")
        if inner_type != INNER_SYSTEM_INFORMATION:
            raise ProtocolError(
                f"expected SYSTEM_INFORMATION (0x17), got 0x{inner_type:02X}"
            )

        if len(inner_data) < 4:
            raise ProtocolError(f"SYSTEM_INFORMATION too short: {len(inner_data)} bytes")
        model = inner_data[0]
        major = inner_data[1]
        minor = inner_data[2]
        revision = inner_data[3]
        phone = inner_data[4:29].rstrip(b"\x00") if len(inner_data) >= 29 else b""

        print()
        print("=== SYSTEM INFORMATION ===")
        print(f"  Model number:    {model}  ({MODEL_NAMES.get(model, 'unknown')})")
        print(f"  Firmware:        {major}.{minor}.{revision}")
        if phone:
            try:
                phone_str = phone.decode("ascii", errors="replace")
                print(f"  Local phone:     {phone_str!r}")
            except Exception:
                print(f"  Local phone:     {phone.hex()}")
        print(f"  Raw data ({len(inner_data)}B): {inner_data.hex().upper()}")
        print()

        return 0

    finally:
        # Clean teardown: send CLIENT_TERM (type 5) and wait briefly for CONTROLLER_TERM.
        try:
            writer.write(pack_outer(0, MSG_CLIENT_TERM, b""))
            await writer.drain()
            try:
                await asyncio.wait_for(reader.readexactly(4), timeout=2.0)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                pass
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        print("Session terminated.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Omni-Link II dialect probe (read-only).")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    try:
        return asyncio.run(probe(args.host, args.port, args.timeout))
    except KeyboardInterrupt:
        print("Interrupted.")
        return 130
    except ProtocolError as e:
        print(f"Protocol error: {e}")
        return 2
    except ConnectionError as e:
        print(f"Connection error: {e}")
        return 3
    except asyncio.TimeoutError:
        print("Timed out.")
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
