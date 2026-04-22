"""Offline decoder for the OMNIBUS Software programming channel (TCP 43690).

Parses a libpcap file, extracts the plaintext HDLC-style 43690 frames between
Translator (192.0.2.10:43690) and the OMNIBUS Software PC (192.0.2.21),
reassembles fragmented TCP payloads per direction, splits on 7E…7F boundaries,
and attempts to verify several checksum algorithms against the byte that
precedes each trailing 7F.

Three questions this tool exists to answer:
    1. What checksum algorithm does the 1-byte trailer use?
    2. Are 7E / 7F bytes inside the payload escaped? If so, how?
    3. Where in an obj_type=02 page read response do unit names live?

Usage:
    python tools/omnibus_sw_decode.py captures/omnibus_omnibusSW_20260421_235941.pcap
    python tools/omnibus_sw_decode.py <file> --limit 20
    python tools/omnibus_sw_decode.py <file> --dump-payloads    # write each reply body to /tmp
"""
from __future__ import annotations

import argparse
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from omnibus_bridge.crc import crc16  # noqa: E402

OMNIBUS_SW_PORT = 43690

PCAP_MAGIC_LE_US = 0xA1B2C3D4
PCAP_MAGIC_LE_NS = 0xA1B23C4D
PCAP_MAGIC_BE_US = 0xD4C3B2A1
PCAP_MAGIC_BE_NS = 0x4D3CB2A1
LINKTYPE_ETHERNET = 1
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100
IPPROTO_TCP = 6

FRAME_START = 0x7E
FRAME_END = 0x7F


@dataclass
class TcpPayload:
    ts: float
    seq: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: bytes


@dataclass
class Frame:
    ts: float
    src_ip: str
    dst_ip: str
    raw: bytes  # everything between 7E and 7F, exclusive


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
        ts_sec, ts_sub, incl_len, _orig = struct.unpack(
            endian + "IIII", raw[pos : pos + 16]
        )
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
        tcp_seq = struct.unpack(">I", tcp[4:8])[0]
        data_offset = (tcp[12] >> 4) * 4
        if data_offset < 20 or len(tcp) < data_offset:
            continue
        payload = tcp[data_offset:]
        if not payload:
            continue
        out.append(TcpPayload(ts, tcp_seq, src_ip, src_port, dst_ip, dst_port, bytes(payload)))
    return out


def _reassemble_streams(payloads: list[TcpPayload]) -> dict[tuple, list[tuple[float, bytes]]]:
    """Group 43690 TCP payloads by directional stream, ordered by TCP sequence.

    Returns a dict keyed by (src_ip, src_port, dst_ip, dst_port) whose values
    are lists of (first_timestamp, payload_bytes) tuples sorted by TCP seq.
    TCP seq ordering correctly handles retransmits and out-of-order frames.
    """
    buckets: dict[tuple, list[TcpPayload]] = defaultdict(list)
    for p in payloads:
        if p.src_port != OMNIBUS_SW_PORT and p.dst_port != OMNIBUS_SW_PORT:
            continue
        key = (p.src_ip, p.src_port, p.dst_ip, p.dst_port)
        buckets[key].append(p)
    out: dict[tuple, list[tuple[float, bytes]]] = {}
    for key, items in buckets.items():
        items.sort(key=lambda p: p.seq)
        out[key] = [(p.ts, p.payload) for p in items]
    return out


def _split_frames(
    stream: list[tuple[float, bytes]], src_ip: str, dst_ip: str
) -> list[Frame]:
    """Concatenate a directional stream's payloads, then split on 7E…7F pairs.

    Keeps the timestamp of the *first* TCP payload that contained the 7E
    start byte (so we know when the frame began transmitting).
    """
    frames: list[Frame] = []
    # Build a flat list of (byte_index_in_stream, ts) so each byte knows its
    # arrival timestamp.
    stream_bytes = bytearray()
    byte_ts: list[float] = []
    for ts, payload in stream:
        for b in payload:
            stream_bytes.append(b)
            byte_ts.append(ts)
    i = 0
    while i < len(stream_bytes):
        if stream_bytes[i] != FRAME_START:
            i += 1
            continue
        start = i
        i += 1
        # Walk forward until FRAME_END. We naively treat the first 7F we see
        # as the end — if there's byte stuffing this will be wrong and we'll
        # detect it when checksums don't match.
        while i < len(stream_bytes) and stream_bytes[i] != FRAME_END:
            i += 1
        if i >= len(stream_bytes):
            break  # truncated trailing frame
        # raw = bytes between 7E and 7F, exclusive of both
        raw = bytes(stream_bytes[start + 1 : i])
        frames.append(Frame(ts=byte_ts[start], src_ip=src_ip, dst_ip=dst_ip, raw=raw))
        i += 1  # advance past the 7F
    return frames


# ---- Checksum candidates ---------------------------------------------------
#
# `frame.raw` = everything between 7E and 7F. The last byte of raw is the
# transmitted checksum; the bytes before it are what the checksum was
# computed over.


def _sum8(data: bytes) -> int:
    return sum(data) & 0xFF


def _sum8_twos_complement(data: bytes) -> int:
    return (-sum(data)) & 0xFF


def _xor8(data: bytes) -> int:
    x = 0
    for b in data:
        x ^= b
    return x


def _crc8(data: bytes, poly: int, init: int = 0x00, xor_out: int = 0x00) -> int:
    crc = init
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
    return (crc ^ xor_out) & 0xFF


def _crc16_a001_lo(data: bytes) -> int:
    return crc16(data) & 0xFF


def _crc16_a001_hi(data: bytes) -> int:
    return (crc16(data) >> 8) & 0xFF


CHECKSUM_CANDIDATES = {
    "sum8": _sum8,
    "sum8_2c": _sum8_twos_complement,
    "xor8": _xor8,
    "crc16_A001_lo": _crc16_a001_lo,
    "crc16_A001_hi": _crc16_a001_hi,
    "crc8_07": lambda d: _crc8(d, 0x07),
    "crc8_8C": lambda d: _crc8(d, 0x8C),
    "crc8_31": lambda d: _crc8(d, 0x31),
    "crc8_8C_init_FF": lambda d: _crc8(d, 0x8C, init=0xFF),
    "crc8_8C_xor_FF": lambda d: _crc8(d, 0x8C, xor_out=0xFF),
    "crc8_8C_init_FF_xor_FF": lambda d: _crc8(d, 0x8C, init=0xFF, xor_out=0xFF),
}


def _test_checksums(frames: list[Frame]) -> dict[str, tuple[int, int]]:
    """Run every candidate checksum over every frame. Return hits/total per algo."""
    results: dict[str, tuple[int, int]] = {}
    for name, fn in CHECKSUM_CANDIDATES.items():
        hits = 0
        total = 0
        for f in frames:
            if len(f.raw) < 2:
                continue
            body = f.raw[:-1]
            trailer = f.raw[-1]
            try:
                calc = fn(body) & 0xFF
            except Exception:
                continue
            total += 1
            if calc == trailer:
                hits += 1
        results[name] = (hits, total)
    return results


def _test_checksums_varied_regions(frames: list[Frame]) -> None:
    """Explore different regions the checksum might cover, per direction.

    Regions tested:
      - raw[:-1]                 (everything between 7E and 7F except trailer)
      - raw[1:-1]                (skip first body byte — in case start marker is counted)
      - b"\\x7e" + raw[:-1]      (include a leading 7E in the computation)
      - raw[9:-1] for PC->T      (skip the 9B header: 03 01 12 34 + 4B src + dst counts as ??)
      - raw[8:-1] or raw[9:-1] per direction
    """
    regions = {
        "raw[:-1]":               lambda f: f.raw[:-1],
        "7E+raw[:-1]":            lambda f: bytes([0x7E]) + f.raw[:-1],
        "raw[1:-1]":              lambda f: f.raw[1:-1],
        "raw[9:-1]":              lambda f: f.raw[9:-1],
        "raw[13:-1]":             lambda f: f.raw[13:-1],  # after PC->T 13B header
        "raw[9:-1] T, raw[13:-1] PC":
            lambda f: f.raw[9:-1] if f.src_ip == "192.0.2.10" else f.raw[13:-1],
    }
    print()
    print("=" * 78)
    print("Extended checksum search: regions x algorithms (match % over all frames)")
    print("=" * 78)
    for algo_name, fn in CHECKSUM_CANDIDATES.items():
        row = []
        for reg_name, reg_fn in regions.items():
            hits = total = 0
            for f in frames:
                if len(f.raw) < 2:
                    continue
                try:
                    body = reg_fn(f)
                    calc = fn(body) & 0xFF
                except Exception:
                    continue
                total += 1
                if calc == f.raw[-1]:
                    hits += 1
            pct = (hits / total * 100) if total else 0.0
            row.append(f"{reg_name}:{pct:5.1f}%")
        print(f"  {algo_name:<24}  " + "  ".join(row))


# ---- Printing --------------------------------------------------------------


def _ascii_preview(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def _preview(data: bytes, width: int = 64) -> str:
    if len(data) <= width:
        return f"{data.hex()}  |{_ascii_preview(data)}|"
    return f"{data[:width].hex()}…  |{_ascii_preview(data[:width])}…|"


def _direction_label(src_ip: str, dst_ip: str, translator_ip: str) -> str:
    if src_ip == translator_ip:
        return "T->PC"
    if dst_ip == translator_ip:
        return "PC->T"
    return f"{src_ip}->{dst_ip}"


def _detect_byte_stuffing(frames: list[Frame]) -> tuple[int, int]:
    """Count how often 7E / 7F / 7D appear inside the body of each frame."""
    weird = 0
    for f in frames:
        body = f.raw[:-1]
        if FRAME_START in body or FRAME_END in body or 0x7D in body:
            weird += 1
    return weird, len(frames)


# ---- Main ------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--translator-ip", default="192.0.2.10")
    parser.add_argument("--limit", type=int, default=30,
                        help="frames per direction to print (default 30)")
    parser.add_argument("--show-long", action="store_true",
                        help="always print full hex for frames, no truncation")
    parser.add_argument("--dump-payloads", action="store_true",
                        help="write each Translator-reply body to /tmp/omnibus_sw_<i>.bin")
    args = parser.parse_args()

    if not args.pcap.exists():
        print(f"error: {args.pcap} not found", file=sys.stderr)
        return 2

    payloads = _parse_pcap(args.pcap)
    print(f"parsed {len(payloads)} TCP payloads from {args.pcap}")
    streams = _reassemble_streams(payloads)
    print(f"43690 streams (by direction): {len(streams)}")

    all_frames: list[Frame] = []
    per_direction: dict[str, list[Frame]] = {}

    for key, stream in streams.items():
        src_ip, src_port, dst_ip, dst_port = key
        frames = _split_frames(stream, src_ip, dst_ip)
        label = _direction_label(src_ip, dst_ip, args.translator_ip)
        per_direction.setdefault(label, []).extend(frames)
        all_frames.extend(frames)
        print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}  ({label})  "
              f"{sum(len(p) for _, p in stream)}B reassembled, {len(frames)} frames")

    print()
    print("=" * 78)
    print("Checksum candidate pass rates (body = frame.raw[:-1], trailer = frame.raw[-1])")
    print("=" * 78)
    print("  All frames:")
    for name, (hits, total) in _test_checksums(all_frames).items():
        pct = (hits / total * 100) if total else 0.0
        marker = "  <-- MATCH" if hits == total and total > 0 else ""
        print(f"    {name:<24} {hits:>4d} / {total:<4d}  ({pct:5.1f}%){marker}")
    for label, frames in per_direction.items():
        print(f"\n  {label} only:")
        for name, (hits, total) in _test_checksums(frames).items():
            pct = (hits / total * 100) if total else 0.0
            marker = "  <-- MATCH" if hits == total and total > 0 else ""
            print(f"    {name:<24} {hits:>4d} / {total:<4d}  ({pct:5.1f}%){marker}")

    _test_checksums_varied_regions(all_frames)

    # Two-stage CRC-8 brute force on the direction that didn't match.
    # Stage 1: narrow poly x init x xor_out candidates using the first 10 frames.
    # Stage 2: validate survivors across all frames.
    import sys as _sys  # local alias so output flushes as we go
    print()
    print("=" * 78)
    print("Brute-force CRC-8 search on PC->T frames")
    print("=" * 78)
    pc_frames = per_direction.get("PC->T", [])
    if not pc_frames:
        return 0

    sample = pc_frames[:5]
    survivors: list[tuple[int, int, int]] = []  # (poly, init, xor_out)
    # Full 256-init sweep with xor_out in {00, FF}
    for poly in range(256):
        for init in range(256):
            for xor_out in (0x00, 0xFF):
                ok = True
                for f in sample:
                    if _crc8(f.raw[:-1], poly, init=init, xor_out=xor_out) != f.raw[-1]:
                        ok = False
                        break
                if ok:
                    survivors.append((poly, init, xor_out))
    print(f"  stage 1 (first {len(sample)} frames): {len(survivors)} candidates")
    _sys.stdout.flush()

    if not survivors:
        print("  no CRC-8 match on raw[:-1] with init/xor in {00, FF}")

    print(f"  stage 2 (validate {len(survivors)} candidates on all {len(pc_frames)} frames):")
    for poly, init, xor_out in survivors[:20]:
        hits = sum(
            1
            for f in pc_frames
            if _crc8(f.raw[:-1], poly, init=init, xor_out=xor_out) == f.raw[-1]
        )
        pct = hits / len(pc_frames) * 100
        marker = "  <-- MATCH" if hits == len(pc_frames) else ""
        print(
            f"    poly=0x{poly:02X}  init=0x{init:02X}  xor_out=0x{xor_out:02X}  "
            f"{hits}/{len(pc_frames)} ({pct:.1f}%){marker}"
        )

    # Try two more hypotheses:
    #   (a) PC->T uses CRC-16 (2-byte trailer we treated as 1B), brute over polys
    #   (b) PC->T uses the MAXIM CRC but "self-check" — CRC over entire raw equals 0
    # Show the frames that don't match either init — they're likely mis-split
    # (embedded 0x7F mistaken for frame end).
    print()
    print("Frames that don't match crc8_8C with init=0x00 (T->PC) or init=0x05 (PC->T):")
    miss_count = 0
    for label, frames in per_direction.items():
        init = 0x00 if label == "T->PC" else 0x05
        for i, f in enumerate(frames):
            if len(f.raw) < 2:
                continue
            if _crc8(f.raw[:-1], 0x8C, init=init) != f.raw[-1]:
                if miss_count < 12:
                    print(f"    {label} [{i:3d}] len={len(f.raw)}  body={_preview(f.raw, 48)}")
                miss_count += 1
    print(f"  total misses: {miss_count}")

    print()
    print("Hypothesis (b): CRC-8/MAXIM over whole raw (incl. trailer) equals 0 for PC->T?")
    zeros = sum(1 for f in pc_frames if _crc8(f.raw, 0x8C) == 0)
    print(f"  {zeros}/{len(pc_frames)} frames self-check to zero with crc8_8C")

    print()
    print("Hypothesis (c): CRC-8/MAXIM computed over raw PLUS one extra constant byte")
    for extra in (0x00, 0x01, 0x7E, 0x7F, 0xAA, 0xFF):
        hits = sum(
            1
            for f in pc_frames
            if _crc8(f.raw[:-1] + bytes([extra]), 0x8C) == f.raw[-1]
        )
        pct = hits / len(pc_frames) * 100
        print(f"  extra=0x{extra:02X}: {hits}/{len(pc_frames)} ({pct:.1f}%)")

    print()
    print("Hypothesis (d): PC->T trailer is 2 bytes (CRC-16/A001), not 1")
    for name, fn in [
        ("crc16_A001 -> (lo,hi)", lambda d: crc16(d)),
        ("crc16_A001 -> (hi,lo)", lambda d: ((crc16(d) & 0xFF) << 8) | (crc16(d) >> 8)),
    ]:
        hits = 0
        for f in pc_frames:
            if len(f.raw) < 3:
                continue
            body = f.raw[:-2]
            observed = f.raw[-2] | (f.raw[-1] << 8)  # lo,hi
            if fn(body) == observed:
                hits += 1
        pct = hits / len(pc_frames) * 100
        print(f"  {name}: {hits}/{len(pc_frames)} ({pct:.1f}%)")

    weird, total = _detect_byte_stuffing(all_frames)
    print()
    print(f"Frames whose body contains 0x7E, 0x7F, or 0x7D: {weird} / {total}")

    # Frame length distribution and op-prefix histogram
    print()
    print("=" * 78)
    print("Frame length distribution (per direction)")
    print("=" * 78)
    for label, frames in per_direction.items():
        lengths: dict[int, int] = defaultdict(int)
        for f in frames:
            lengths[len(f.raw)] += 1
        print(f"  {label}: {len(frames)} frames")
        for length in sorted(lengths):
            print(f"    len={length:4d}  count={lengths[length]}")

    # Print the first N frames per direction, annotated
    print()
    print("=" * 78)
    print(f"First {args.limit} frames per direction")
    print("=" * 78)
    for label, frames in per_direction.items():
        print(f"\n--- {label} ---")
        for i, f in enumerate(frames[: args.limit]):
            body = f.raw[:-1] if f.raw else b""
            trailer = f.raw[-1] if f.raw else 0
            header_hex = body[:14].hex()
            if args.show_long or len(body) <= 64:
                print(f"  [{i:3d}] t={f.ts:.3f}  len={len(f.raw)}  cksum=0x{trailer:02X}")
                print(f"         header={header_hex}")
                print(f"         body  ={_preview(body)}")
            else:
                print(f"  [{i:3d}] t={f.ts:.3f}  len={len(f.raw):4d}  cksum=0x{trailer:02X}  "
                      f"header={header_hex}  body={_preview(body, 48)}")

    # If asked, dump Translator-reply bodies to /tmp so we can grep for names
    if args.dump_payloads:
        out_dir = Path("/tmp")
        out_dir.mkdir(exist_ok=True)
        for i, f in enumerate(per_direction.get("T->PC", [])):
            p = out_dir / f"omnibus_sw_{i:03d}.bin"
            p.write_bytes(f.raw[:-1])
        print(f"\nwrote {len(per_direction.get('T->PC', []))} Translator-reply bodies to /tmp/")

    # Pair PC->T read requests with their T->PC replies and analyze unit-name-bearing pages.
    # A "read" request is 24B with op prefix `0E 08 08`. Look for Translator replies
    # shortly after each such request.
    print()
    print("=" * 78)
    print("Paired reads: PC->T '0E 08 08' requests with following T->PC replies")
    print("=" * 78)
    pc_frames = per_direction.get("PC->T", [])
    t_frames = per_direction.get("T->PC", [])
    reads = []
    for f in pc_frames:
        if len(f.raw) >= 16 and f.raw[12:15] == b"\x0e\x08\x08":
            ot = f.raw[15]
            page = f.raw[18] if len(f.raw) > 18 else 0
            reads.append((f.ts, ot, page, f))
    print(f"  {len(reads)} read requests found")
    # Pair each read with the earliest T->PC frame whose timestamp is >= the
    # request and < next request (simple nearest-in-time pairing).
    # Concatenate each read's replies, stripping per-reply headers + CRC, so
    # we see the logical "page" payload as a contiguous bytestream.
    print(f"\n  Per-page summary (header-stripped, CRC-stripped, ASCII-bearing only):")
    ascii_pages: list[tuple[int, int, bytes]] = []
    for i, (ts, ot, page, f_req) in enumerate(reads):
        next_ts = reads[i + 1][0] if i + 1 < len(reads) else float("inf")
        replies = [tf for tf in t_frames if ts <= tf.ts < next_ts]
        payload = b""
        for r in replies:
            body = r.raw[:-1]  # drop CRC
            if len(body) >= 9:
                payload += body[9:]  # strip 9-byte header (00 + src + dst)
        # If payload has any meaningful ASCII run, surface it
        ascii_len = sum(1 for b in payload if 32 <= b < 127)
        if ascii_len >= 4:
            ascii_pages.append((ot, page, payload))

    print(f"  {len(ascii_pages)} pages have ASCII content; showing first 12:")
    for ot, page, payload in ascii_pages[:12]:
        print(f"\n  ot=0x{ot:02X} page=0x{page:02X}  ({len(payload)}B)")
        for off in range(0, min(len(payload), 384), 16):
            chunk = payload[off : off + 16]
            ascii_view = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"      {off:04X}  {chunk.hex():<32}  |{ascii_view}|")

    # Scan the full capture for "CBIT" or likely unit-name strings
    print()
    print("  All ASCII runs >=5 chars across all obj_type=0x02 pages:")
    import re
    seen = set()
    for ot, page, payload in ascii_pages:
        for m in re.finditer(rb"[\x20-\x7e]{5,}", payload):
            s = m.group().decode("ascii")
            if s not in seen:
                seen.add(s)
                print(f"    ot=0x{ot:02X} page=0x{page:02X} off={m.start():4d}  {s!r}")

    # Inspect WRITE frames (PC->T 0E 09 28) — OMNIBUS SW pushed 756 records back
    print()
    print("=" * 78)
    print("PC->T WRITE frames (0E 09 28 ...) — sample + ASCII scan")
    print("=" * 78)
    writes = [
        f for f in pc_frames
        if len(f.raw) >= 16 and f.raw[12:15] == b"\x0e\x09\x28"
    ]
    print(f"  {len(writes)} write frames found")
    # Print first 3 full, then scan all for ASCII
    for i, f in enumerate(writes[:3]):
        body = f.raw[:-1]  # drop CRC
        payload = body[12:]  # strip 12-byte PC header
        print(f"\n  write #{i}: payload ({len(payload)}B):")
        for off in range(0, len(payload), 16):
            chunk = payload[off : off + 16]
            ascii_view = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"      {off:04X}  {chunk.hex():<32}  |{ascii_view}|")

    # ASCII runs across all writes
    print("\n  All unique ASCII runs >=4 chars across all write frames:")
    seen = set()
    for i, f in enumerate(writes):
        body = f.raw[:-1]
        payload = body[12:]
        for m in re.finditer(rb"[\x20-\x7e]{4,}", payload):
            s = m.group().decode("ascii")
            if s not in seen and s not in ("`B.", "###"):
                seen.add(s)
                # Figure out this write's target (ot, page, rec)
                ot = payload[3] if len(payload) > 3 else 0
                page = payload[4] if len(payload) > 4 else 0
                rec = payload[6] if len(payload) > 6 else 0
                print(f"    ot=0x{ot:02X} page=0x{page:02X} rec=0x{rec:02X} off={m.start():4d}  {s!r}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
