"""Offline Omni-Link II decryptor for 4106↔4369 pcap captures.

Parses a libpcap file, extracts the TCP payloads between Translator (4106
side) and OmniPro II (4369 side), finds the session handshake (types 1/2/3/4),
derives the session key from .env, decrypts every type-0x20 application data
packet, parses the inner frame, validates CRC-16/A001, and pretty-prints
every message. CONTROLLER COMMAND (0x14) frames are highlighted.

Usage:
    python tools/pcap_decrypt.py captures/<file>.pcap
    python tools/pcap_decrypt.py <file> --only-writes       # show 0x14 only
    python tools/pcap_decrypt.py <file> --max-bytes 96

Reads OMNILINK_KEY1 and OMNILINK_KEY2 from .env (hex, no separators).
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from omnibus_bridge.crc import crc16  # noqa: E402
from omnibus_bridge.crypto import BLOCK_SIZE, decrypt, derive_session_key  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
TRANSLATOR_IP_DEFAULT = "192.0.2.10"
CONTROLLER_IP_DEFAULT = "192.0.2.11"
TRANSLATOR_PORT = 4106
CONTROLLER_PORT = 4370

PCAP_MAGIC_LE_US = 0xA1B2C3D4
PCAP_MAGIC_LE_NS = 0xA1B23C4D
PCAP_MAGIC_BE_US = 0xD4C3B2A1
PCAP_MAGIC_BE_NS = 0x4D3CB2A1
LINKTYPE_ETHERNET = 1
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100
IPPROTO_TCP = 6

INNER_START = 0x21
MSG_NAMES = {
    0x00: "NO_MSG",
    0x01: "ACK",
    0x02: "NACK",
    0x03: "END_OF_DATA",
    0x14: "CONTROLLER_COMMAND",
    0x15: "ENABLE_NOTIFICATIONS",
    0x16: "REQ_SYSTEM_INFORMATION",
    0x17: "SYSTEM_INFORMATION",
    0x1E: "REQ_OBJECT_TYPE_CAPACITIES",
    0x1F: "OBJECT_TYPE_CAPACITIES",
    0x20: "REQ_OBJECT_PROPERTIES",
    0x21: "OBJECT_PROPERTIES",
    0x22: "REQ_OBJECT_STATUS",
    0x23: "OBJECT_STATUS",
    0x37: "OTHER_EVENT_NOTIFICATIONS",
    0x3A: "REQ_EXT_OBJECT_STATUS",
    0x3B: "EXT_OBJECT_STATUS",
}
OUTER_NAMES = {
    0: "NO_MSG",
    1: "CLIENT_REQ_NEW_SESSION",
    2: "CONTROLLER_ACK_NEW_SESSION",
    3: "CLIENT_REQ_SECURE",
    4: "CONTROLLER_ACK_SECURE",
    5: "CLIENT_TERMINATED",
    6: "CONTROLLER_TERMINATED",
    7: "CONTROLLER_CANNOT_START",
    32: "APP_DATA",
}


@dataclass
class TcpPayload:
    ts: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: bytes


def _load_env_keys(env_path: Path) -> bytes:
    if not env_path.exists():
        raise SystemExit(f".env not found at {env_path}")
    key1 = key2 = None
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k == "OMNILINK_KEY1":
            key1 = v
        elif k == "OMNILINK_KEY2":
            key2 = v
    if not key1 or not key2:
        raise SystemExit("OMNILINK_KEY1 and OMNILINK_KEY2 must be set in .env")
    def _clean(h: str) -> str:
        return "".join(c for c in h if c not in "-: ")
    try:
        raw = bytes.fromhex(_clean(key1)) + bytes.fromhex(_clean(key2))
    except ValueError as e:
        raise SystemExit(f"invalid hex in OMNILINK_KEY1/2: {e}") from e
    if len(raw) != 16:
        raise SystemExit(f"combined private key must be 16 bytes, got {len(raw)}")
    return raw


def _parse_pcap(path: Path) -> list[TcpPayload]:
    raw = path.read_bytes()
    if len(raw) < 24:
        raise ValueError(f"{path}: truncated")
    magic = struct.unpack("<I", raw[:4])[0]
    if magic == PCAP_MAGIC_LE_US:
        endian, divisor = "<", 1_000_000
    elif magic == PCAP_MAGIC_LE_NS:
        endian, divisor = "<", 1_000_000_000
    elif magic == PCAP_MAGIC_BE_US:
        endian, divisor = ">", 1_000_000
    elif magic == PCAP_MAGIC_BE_NS:
        endian, divisor = ">", 1_000_000_000
    else:
        raise ValueError(f"{path}: not a classic pcap (magic=0x{magic:08X})")
    _, _, _, _, _, linktype = struct.unpack(endian + "HHiIII", raw[4:24])
    if linktype != LINKTYPE_ETHERNET:
        raise ValueError(f"{path}: linktype {linktype} unsupported")

    pos = 24
    out: list[TcpPayload] = []
    while pos < len(raw):
        if pos + 16 > len(raw):
            break
        ts_sec, ts_sub, incl_len, _orig = struct.unpack(endian + "IIII", raw[pos : pos + 16])
        pos += 16
        if pos + incl_len > len(raw):
            break
        pkt = raw[pos : pos + incl_len]
        pos += incl_len
        ts = ts_sec + ts_sub / divisor

        if len(pkt) < 14:
            continue
        ethertype = struct.unpack(">H", pkt[12:14])[0]
        off = 14
        while ethertype == ETHERTYPE_VLAN and len(pkt) >= off + 4:
            ethertype = struct.unpack(">H", pkt[off + 2 : off + 4])[0]
            off += 4
        if ethertype != ETHERTYPE_IPV4:
            continue
        ip = pkt[off:]
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl or ip[9] != IPPROTO_TCP:
            continue
        total_len = struct.unpack(">H", ip[2:4])[0]
        src_ip = ".".join(str(b) for b in ip[12:16])
        dst_ip = ".".join(str(b) for b in ip[16:20])
        tcp = ip[ihl:total_len]
        if len(tcp) < 20:
            continue
        src_port, dst_port = struct.unpack(">HH", tcp[0:4])
        data_offset = (tcp[12] >> 4) * 4
        if data_offset < 20 or len(tcp) < data_offset:
            continue
        payload = tcp[data_offset:]
        if not payload:
            continue
        out.append(TcpPayload(ts, src_ip, src_port, dst_ip, dst_port, bytes(payload)))
    return out


def _filter_session(
    payloads: list[TcpPayload],
    translator_ip: str,
    controller_ip: str,
) -> list[TcpPayload]:
    """Keep only payloads on the Translator ↔ Controller:4369 Omni-Link II session.

    The Translator connects outbound to Controller:4369 with an ephemeral source
    port (observed: 4106, 4111, 4097, …). Match any such pairing.
    """
    kept: list[TcpPayload] = []
    for p in payloads:
        a = (p.src_ip, p.src_port)
        b = (p.dst_ip, p.dst_port)
        if (b == (controller_ip, CONTROLLER_PORT) and a[0] == translator_ip) or (
            a == (controller_ip, CONTROLLER_PORT) and b[0] == translator_ip
        ):
            kept.append(p)
    return kept


def _parse_outer(payload: bytes) -> tuple[int, int, bytes] | None:
    """Return (seq, mtype, body) or None if too short."""
    if len(payload) < 4:
        return None
    seq = (payload[0] << 8) | payload[1]
    mtype = payload[2]
    # payload[3] is reserved
    return seq, mtype, payload[4:]


def _tcp_tuple(p: TcpPayload) -> tuple[str, int, str, int]:
    """Return a canonical (order-independent) tuple for the TCP session."""
    a = (p.src_ip, p.src_port)
    b = (p.dst_ip, p.dst_port)
    return (*min(a, b), *max(a, b))


def _collect_session_ids(
    session: list[TcpPayload], translator_ip: str
) -> dict[tuple[str, int, str, int], bytes]:
    """Map each TCP 4-tuple to the session_id observed in its type-2 handshake.

    The capture may contain several independent TCP sessions (reconnect
    retries, terminated sessions). Each one has its own handshake.
    """
    session_ids: dict[tuple[str, int, str, int], bytes] = {}
    for p in session:
        parsed = _parse_outer(p.payload)
        if parsed is None:
            continue
        _seq, mtype, body = parsed
        if mtype == 2 and p.dst_ip == translator_ip and len(body) >= 7:
            session_ids[_tcp_tuple(p)] = body[2:7]
    return session_ids


def _parse_inner_frame(plain: bytes) -> tuple[int, bytes, bool] | None:
    """Parse an inner frame. Return (msg_type, data, crc_ok) or None."""
    if len(plain) < 5 or plain[0] != INNER_START:
        return None
    length = plain[1]
    if length < 1 or 2 + length + 2 > len(plain):
        return None
    msg_type = plain[2]
    data = plain[3 : 2 + length]
    crc_lo = plain[2 + length]
    crc_hi = plain[2 + length + 1]
    observed = crc_lo | (crc_hi << 8)
    expected = crc16(plain[1 : 2 + length])
    return msg_type, data, observed == expected


def _decode_controller_command(data: bytes) -> str:
    """Decode a CONTROLLER_COMMAND (0x14) payload: command(1) + p1(1) + p2(2, MSB)."""
    if len(data) < 4:
        return f"  malformed (len={len(data)})"
    cmd, p1 = data[0], data[1]
    p2 = (data[2] << 8) | data[3]
    name = {
        0: "UNIT_OFF", 1: "UNIT_ON",
        2: "UNIT_OFF_FOR", 3: "UNIT_ON_FOR", 4: "UNIT_LEVEL_FOR",
        9: "UNIT_LEVEL_PCT",
        60: "SCENE_OFF", 61: "SCENE_ON", 62: "SCENE_SET",
    }.get(cmd)
    if 16 <= cmd <= 25:
        name = f"UNIT_DIM_STEP_{cmd - 16}"
    elif 32 <= cmd <= 41:
        name = f"UNIT_BRIGHT_STEP_{cmd - 32}"
    name = name or f"CMD_{cmd:#04x}"
    return f"  cmd={cmd} ({name})  p1={p1}  p2={p2} (unit# / link#)"


def _decode_object_status(data: bytes) -> str:
    """Decode an OBJECT_STATUS (0x23) payload: obj_type(1) + N × record."""
    if not data:
        return "  empty"
    obj_type = data[0]
    records = data[1:]
    if obj_type == 0x02:  # Unit
        rec_len = 5
        if len(records) % rec_len != 0:
            return f"  obj_type=2 (Unit) malformed records (len={len(records)})"
        n = len(records) // rec_len
        sample = []
        for i in range(min(n, 6)):
            r = records[i * rec_len : (i + 1) * rec_len]
            unit = (r[0] << 8) | r[1]
            status = r[2]
            sample.append(f"u{unit}={status}")
        more = "" if n <= 6 else f" ... ({n} total)"
        return f"  obj_type=2 (Unit)  records={n}  {' '.join(sample)}{more}"
    return f"  obj_type={obj_type}  data={data[1:].hex()}"


def _decode_req_object_status(data: bytes) -> str:
    """Decode REQ_OBJECT_STATUS (0x22): obj_type(1) + start(2) + end(2)."""
    if len(data) < 5:
        return f"  malformed (len={len(data)})"
    return (
        f"  obj_type={data[0]}  "
        f"start={(data[1] << 8) | data[2]}  "
        f"end={(data[3] << 8) | data[4]}"
    )


def _decode_other_events(data: bytes) -> str:
    """Decode OTHER_EVENT_NOTIFICATIONS (0x37): list of 16-bit event codes."""
    if len(data) % 2 != 0:
        return f"  malformed (len={len(data)})"
    codes = [(data[i] << 8) | data[i + 1] for i in range(0, len(data), 2)]
    parts = []
    for c in codes:
        nibble = (c >> 12) & 0xF
        if nibble == 0xF:
            sw = (c >> 8) & 0xF
            unit = c & 0xFF
            parts.append(f"ALC/UPB/RRA sw={sw} unit={unit}")
        else:
            parts.append(f"0x{c:04X}")
    return "  " + "  ".join(parts)


def _decode_inner(msg_type: int, data: bytes) -> str:
    if msg_type == 0x14:
        return _decode_controller_command(data)
    if msg_type == 0x22:
        return _decode_req_object_status(data)
    if msg_type == 0x23:
        return _decode_object_status(data)
    if msg_type == 0x37:
        return _decode_other_events(data)
    return f"  data={data.hex()}"


def run(
    pcap_path: Path,
    translator_ip: str,
    controller_ip: str,
    only_writes: bool,
    max_bytes: int,
) -> int:
    private_key = _load_env_keys(REPO_ROOT / ".env")
    all_payloads = _parse_pcap(pcap_path)
    session = _filter_session(all_payloads, translator_ip, controller_ip)
    print(f"# {pcap_path.name}: {len(all_payloads)} total payloads, "
          f"{len(session)} on {translator_ip}:{TRANSLATOR_PORT} ↔ "
          f"{controller_ip}:{CONTROLLER_PORT}")
    if not session:
        return 1

    session_ids = _collect_session_ids(session, translator_ip)
    if not session_ids:
        print("# ⚠️  no type-2 handshake packet found; cannot derive session key.")
        print("#    If the capture starts mid-session, re-capture with a fresh reconnect.")
        t0 = session[0].ts
        for p in session:
            parsed = _parse_outer(p.payload)
            if parsed is None:
                continue
            seq, mtype, body = parsed
            direction = "T→C" if p.src_ip == translator_ip else "C→T"
            tname = OUTER_NAMES.get(mtype, f"0x{mtype:02X}")
            print(f"  T+{p.ts - t0:7.3f}s  {direction}  seq={seq:5d}  "
                  f"type={mtype:3d} ({tname})  body={len(body)}B")
        return 2

    session_keys: dict[tuple[str, int, str, int], bytes] = {
        t: derive_session_key(private_key, sid) for t, sid in session_ids.items()
    }
    print(f"# {len(session_ids)} session(s) with captured handshakes:")
    for t, sid in session_ids.items():
        print(f"#   {t[0]}:{t[1]} ↔ {t[2]}:{t[3]}  session_id={sid.hex().upper()}")
    print()

    t0 = session[0].ts
    command_count = 0
    for p in session:
        parsed = _parse_outer(p.payload)
        if parsed is None:
            continue
        seq, mtype, body = parsed
        direction = "T→C" if p.src_ip == translator_ip else "C→T"
        tname = OUTER_NAMES.get(mtype, f"0x{mtype:02X}")

        header = (f"T+{p.ts - t0:7.3f}s  {direction}  seq={seq:5d}  "
                  f"type={mtype:3d} ({tname})  body={len(body)}B")

        # Only types 3, 4, and 32 carry AES ciphertext.
        if mtype not in (3, 4, 32) or len(body) == 0 or len(body) % BLOCK_SIZE != 0:
            if not only_writes:
                print(header)
                if body:
                    print(f"    body_hex={body.hex()}")
            continue

        key = session_keys.get(_tcp_tuple(p))
        if key is None:
            if not only_writes:
                print(header)
                print("    [skipped] no handshake captured for this TCP session")
            continue

        try:
            plain = decrypt(body, key, seq)
        except Exception as e:
            print(header)
            print(f"    decrypt failed: {e}")
            continue

        if mtype in (3, 4):
            if not only_writes:
                print(header)
                print(f"    plain={plain.hex().upper()}  (session_id + zero-padding)")
            continue

        # Type 32: application data — parse inner frame
        frame = _parse_inner_frame(plain)
        if frame is None:
            if not only_writes:
                print(header)
                print(f"    inner frame unparseable  plain={plain[:max_bytes].hex()}"
                      f"{'...' if len(plain) > max_bytes else ''}")
            continue
        msg_type, msg_data, crc_ok = frame
        is_write = (msg_type == 0x14)
        if only_writes and not is_write:
            continue
        mname = MSG_NAMES.get(msg_type, f"0x{msg_type:02X}")
        flag = "✓" if crc_ok else "✗CRC"
        marker = "  ★ WRITE" if is_write else ""
        print(header + marker)
        print(f"    inner type=0x{msg_type:02X} ({mname})  "
              f"len={len(msg_data)}B  crc={flag}")
        print(_decode_inner(msg_type, msg_data))
        if is_write:
            command_count += 1

    print()
    print(f"# CONTROLLER_COMMAND (0x14) frames decoded: {command_count}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypt an Omni-Link II 4106 pcap.")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--translator", default=TRANSLATOR_IP_DEFAULT)
    parser.add_argument("--controller", default=CONTROLLER_IP_DEFAULT)
    parser.add_argument("--only-writes", action="store_true",
                        help="Print only CONTROLLER_COMMAND (0x14) frames")
    parser.add_argument("--max-bytes", type=int, default=64,
                        help="Max hex bytes to print per unparsed payload (default: 64)")
    args = parser.parse_args()

    if not args.pcap.exists():
        print(f"file not found: {args.pcap}", file=sys.stderr)
        return 2
    try:
        return run(args.pcap, args.translator, args.controller,
                   args.only_writes, args.max_bytes)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
