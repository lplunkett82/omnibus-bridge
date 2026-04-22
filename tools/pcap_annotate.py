"""Offline annotator for Translator pcap captures.

Reads a classic libpcap file (not pcapng), extracts TCP payloads on ports
43690 and 43694 to/from 192.0.2.10, and prints each payload as timestamp +
direction + ASCII preview + hex dump. Adjacent payloads are grouped by
TCP 4-tuple so request/response pairs are easy to eyeball.

Pure stdlib — no scapy, no tshark dependency. Accepts the pcap on argv.

Usage:
    python tools/pcap_annotate.py captures/omnibus_toggle_<ts>.pcap
    python tools/pcap_annotate.py <file> --port 43694
    python tools/pcap_annotate.py <file> --translator 192.0.2.10
"""
from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

PCAP_MAGIC_LE_US = 0xA1B2C3D4
PCAP_MAGIC_LE_NS = 0xA1B23C4D
PCAP_MAGIC_BE_US = 0xD4C3B2A1
PCAP_MAGIC_BE_NS = 0x4D3CB2A1

LINKTYPE_ETHERNET = 1
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100
IPPROTO_TCP = 6


@dataclass
class TcpPayload:
    ts: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: bytes


def _ipv4_str(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _parse_pcap(path: Path) -> tuple[list[TcpPayload], str]:
    raw = path.read_bytes()
    if len(raw) < 24:
        raise ValueError(f"{path}: truncated (pcap header)")

    magic = struct.unpack("<I", raw[:4])[0]
    if magic == PCAP_MAGIC_LE_US:
        endian, ts_divisor = "<", 1_000_000
    elif magic == PCAP_MAGIC_LE_NS:
        endian, ts_divisor = "<", 1_000_000_000
    elif magic == PCAP_MAGIC_BE_US:
        endian, ts_divisor = ">", 1_000_000
    elif magic == PCAP_MAGIC_BE_NS:
        endian, ts_divisor = ">", 1_000_000_000
    else:
        raise ValueError(
            f"{path}: not a classic pcap file (magic=0x{magic:08X}). "
            "If this is pcapng, re-export as pcap: `editcap -F pcap in.pcapng out.pcap`"
        )

    # (version_major, version_minor, thiszone, sigfigs, snaplen, linktype)
    _, _, _, _, _, linktype = struct.unpack(endian + "HHiIII", raw[4:24])
    if linktype != LINKTYPE_ETHERNET:
        raise ValueError(f"{path}: unsupported linktype {linktype} (expected 1=Ethernet)")

    pos = 24
    payloads: list[TcpPayload] = []

    while pos < len(raw):
        if pos + 16 > len(raw):
            break  # trailing garbage
        ts_sec, ts_sub, incl_len, _orig_len = struct.unpack(
            endian + "IIII", raw[pos : pos + 16]
        )
        pos += 16
        if pos + incl_len > len(raw):
            break
        pkt = raw[pos : pos + incl_len]
        pos += incl_len
        ts = ts_sec + ts_sub / ts_divisor

        # Ethernet (strip VLAN tags if present)
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
        if len(ip) < 20:
            continue
        version_ihl = ip[0]
        if version_ihl >> 4 != 4:
            continue
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl:
            continue
        protocol = ip[9]
        if protocol != IPPROTO_TCP:
            continue
        total_len = struct.unpack(">H", ip[2:4])[0]
        src_ip = _ipv4_str(ip[12:16])
        dst_ip = _ipv4_str(ip[16:20])

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

        payloads.append(
            TcpPayload(
                ts=ts,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                payload=bytes(payload),
            )
        )

    return payloads, f"{len(payloads)} payloads extracted"


def _ascii_preview(data: bytes, limit: int = 60) -> str:
    text = data.decode("ascii", errors="replace")
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return text if len(text) <= limit else text[:limit] + "..."


def _hex_dump(data: bytes, limit: int = 48) -> str:
    clipped = data[:limit]
    hex_part = clipped.hex().upper()
    suffix = "..." if len(data) > limit else ""
    return hex_part + suffix


def annotate(
    path: Path,
    translator_ip: str,
    ports: set[int],
    max_bytes: int,
) -> int:
    payloads, summary = _parse_pcap(path)
    print(f"# {path.name}: {summary}")

    # Filter to only Translator-involved traffic on the requested ports.
    kept = [
        p
        for p in payloads
        if (p.src_ip == translator_ip or p.dst_ip == translator_ip)
        and (p.src_port in ports or p.dst_port in ports)
    ]
    if not kept:
        print(f"# no payloads match host {translator_ip} on ports {sorted(ports)}")
        return 1

    t0 = kept[0].ts
    last_tuple: tuple[str, int, str, int] | None = None

    for p in kept:
        direction = "→ Translator" if p.dst_ip == translator_ip else "← Translator"
        port = p.dst_port if p.dst_port in ports else p.src_port
        peer_ip = p.src_ip if p.dst_ip == translator_ip else p.dst_ip
        peer_port = p.src_port if p.dst_ip == translator_ip else p.dst_port
        tup = (peer_ip, peer_port, p.src_ip if p.src_ip == translator_ip else p.dst_ip, port)

        if last_tuple != tup:
            if last_tuple is not None:
                print()
            print(f"-- conn {peer_ip}:{peer_port} ↔ translator:{port} --")
            last_tuple = tup

        t_rel = p.ts - t0
        print(
            f"  T+{t_rel:6.3f}s  {direction:12s}  "
            f"({len(p.payload):4d}B)  "
            f"ascii={_ascii_preview(p.payload)!r}  "
            f"hex={_hex_dump(p.payload, limit=max_bytes)}"
        )

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Annotate a Translator pcap (ports 43690/43694)."
    )
    parser.add_argument("pcap", type=Path, help="Path to the .pcap file")
    parser.add_argument("--translator", default="192.0.2.10",
                        help="Translator IP (default: 192.0.2.10)")
    parser.add_argument("--port", type=int, action="append",
                        help="TCP port to include (repeat for multiple). "
                             "Default: 43690 and 43694.")
    parser.add_argument("--max-bytes", type=int, default=48,
                        help="Max hex bytes shown per payload (default: 48)")
    args = parser.parse_args()

    if not args.pcap.exists():
        print(f"file not found: {args.pcap}", file=sys.stderr)
        return 2

    ports = set(args.port) if args.port else {43690, 43694}
    try:
        return annotate(args.pcap, args.translator, ports, args.max_bytes)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
