"""Ground-truth byte fixtures captured from the live OmniPro II ↔ Translator
Omni-Link II session on TCP :4369.

All inner-frame bytes are the exact plaintext that appeared inside the AES
payload of a real packet (decrypted via `tools/pcap_decrypt.py` against the
verified `.env` private key). Handshake outer packets are wire-bytes as sent.

Extracted from:
  - captures/omnibus_hs_toggle_20260421_233617.pcap (session_id B456A347B2)
  - captures/omnibus_reconnect_20260421_225621.pcap (for 0x3B seq=0 pushes)

These fixtures are the single source of ground truth for the protocol module.
Any change to encode/decode must still round-trip against every fixture below.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Handshake — outer packets (wire bytes: seq(2) + type(1) + reserved(1) + body)
# ---------------------------------------------------------------------------

# Type 1 — CLIENT_REQ_NEW_SESSION (Translator → Controller, seq=1, no body)
HANDSHAKE_TYPE1 = bytes.fromhex("00010100")

# Type 2 — CONTROLLER_ACK_NEW_SESSION (Controller → Translator, seq=1)
# body = protocol_version (2B: 0x0001) + session_id (5B: B4 56 A3 47 B2)
HANDSHAKE_TYPE2 = bytes.fromhex("000102000001B456A347B2")
HANDSHAKE_SESSION_ID = bytes.fromhex("B456A347B2")
HANDSHAKE_PROTOCOL_VERSION = 0x0001

# Type 3 — CLIENT_REQ_SECURE (Translator → Controller, seq=2)
# body = AES_encrypt(session_id + 11 × 0x00, session_key, seq=2)
HANDSHAKE_TYPE3 = bytes.fromhex("0002030030448998BB705825665073DFA8DE53F2")

# Type 4 — CONTROLLER_ACK_SECURE (Controller → Translator, seq=2)
# body = AES_encrypt(session_id + 11 × 0x00, session_key, seq=2)  -- identical to type 3
HANDSHAKE_TYPE4 = bytes.fromhex("0002040030448998BB705825665073DFA8DE53F2")

# ---------------------------------------------------------------------------
# Inner frames — full plaintext bytes (start | length | type | data | CRC_lo | CRC_hi)
# ---------------------------------------------------------------------------

# REQ_OBJECT_STATUS (0x22)
# Asks for Unit status, indices 1..36. Translator's standard poll.
# data = obj_type(1)=02 + start(2)=0001 + end(2)=0024
REQ_OBJECT_STATUS_UNITS_1_36 = bytes.fromhex("21062202000100244899")
REQ_OBJECT_STATUS_DATA = bytes.fromhex("0200010024")

# OBJECT_STATUS (0x23) — 36-record reply to the above REQ_OBJECT_STATUS
# data = obj_type(1)=02 + 36 × (unit_MSB, unit_LSB, status, time_MSB, time_LSB)
# Units 18, 29, 30, 31, 33, 35 are ON (status=1); all others OFF.
OBJECT_STATUS_36_UNITS = bytes.fromhex(
    # start(0x21) | length(0xB6=182) | type(0x23) | obj_type(0x02)
    "21B62302"
    # 36 × 5-byte unit records (unit_MSB, unit_LSB, status, time_MSB, time_LSB)
    "0001010000000200000000030000000004000000"  # u1=ON  u2..u4 OFF
    "0005000000000600000000070000000008000000"  # u5..u8 OFF
    "0009000000000A000000000B000000000C000000"  # u9..u12 OFF
    "000D000000000E000000000F0000000010000000"  # u13..u16 OFF
    "0011000000001201000000130000000014000000"  # u18=ON, others OFF
    "0015000000001600000000170000000018000000"  # u21..u24 OFF
    "0019000000001A000000001B000000001C000000"  # u25..u28 OFF
    "001D010000001E010000001F0100000020000000"  # u29,30,31=ON, u32 OFF
    "0021010000002200000000230100000024000000"  # u33=ON, u34 OFF, u35=ON, u36 OFF
    # CRC (LSB, MSB)
    "6FC0"
)

# EXT_OBJECT_STATUS (0x3B) as seq=0 push — HA toggle → Translator.
# Observed push for unit 4 ON from the toggle capture.
# data = 02 07 <unit_MSB> <unit_LSB> <status> 00 00 00 00
#        ├─ obj_type=02 (Unit)
#        ├─ marker/constant = 0x07 (purpose TBD — constant across all observed pushes)
#        └─ unit 4 (0x0004), status=0x01 (ON), 4 × 0x00 reserved
EXT_OBJECT_STATUS_PUSH_UNIT4_ON = bytes.fromhex("210A3B0207000401000000003400")
EXT_OBJECT_STATUS_PUSH_UNIT1_OFF = bytes.fromhex("210A3B0207000101000000003455")  # from reconnect capture

# CONTROLLER_COMMAND (0x14) — Translator → Controller, physical event on the wire.
# data = cmd(1) + p1(1) + p2(2 MSB-first)
# Observed: cmd=0 (UNIT_OFF), p1=0, p2=1 → "unit 1 went off" (wall-switch press).
CONTROLLER_COMMAND_UNIT1_OFF = bytes.fromhex("21051400000001F196")
CONTROLLER_COMMAND_DATA = bytes.fromhex("00000001")

# ENABLE_NOTIFICATIONS (0x15) — Translator → Controller, right after handshake.
# data = 0x01 (enable)
ENABLE_NOTIFICATIONS_ON = bytes.fromhex("210215016E90")
