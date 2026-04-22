"""Fake Translator — connects to a running omnibus-bridge and drives it.

Completes the real handshake, sends ENABLE_NOTIFICATIONS, polls for status
every 500 ms, and prints every inbound frame (including seq=0 0x3B pushes).
Useful for terminal-only smoke tests before pointing the real Translator
at the bridge.

Usage:
    python tools/fake_translator.py                          # localhost:4369
    python tools/fake_translator.py --host 192.168.1.40      # bridge on LAN
    python tools/fake_translator.py --switch-event 9:on      # fake wall-switch

Reads OMNILINK_KEY1/2 from .env (same file the bridge uses).
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from omnibus_bridge.config import load_private_key  # noqa: E402
from omnibus_bridge.crypto import (  # noqa: E402
    BLOCK_SIZE,
    SESSION_ID_LEN,
    decrypt,
    derive_session_key,
    encrypt,
)
from omnibus_bridge.protocol import (  # noqa: E402
    InnerType,
    OuterType,
    decode_inner,
    decode_outer,
    encode_inner,
    encode_outer,
)

log = logging.getLogger("fake-translator")


class FakeTranslator:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 private_key: bytes) -> None:
        self.reader = reader
        self.writer = writer
        self.private_key = private_key
        self.session_id: bytes | None = None
        self.session_key: bytes | None = None
        self.send_seq = 0

    async def handshake(self) -> None:
        # Type 1 — no body
        self.writer.write(encode_outer(1, OuterType.CLIENT_REQ_NEW_SESSION))
        await self.writer.drain()
        log.info("→ type 1 NEW_SESSION")

        header = await self.reader.readexactly(4)
        _seq, mtype, _ = decode_outer(header)
        if mtype != OuterType.CONTROLLER_ACK_NEW_SESSION:
            raise RuntimeError(f"expected type 2, got {mtype}")
        body = await self.reader.readexactly(7)
        self.session_id = body[2 : 2 + SESSION_ID_LEN]
        self.session_key = derive_session_key(self.private_key, self.session_id)
        log.info("← type 2 ACK  session_id=%s", self.session_id.hex().upper())

        plaintext = self.session_id + b"\x00" * (BLOCK_SIZE - SESSION_ID_LEN)
        ct = encrypt(plaintext, self.session_key, seq=2)
        self.writer.write(encode_outer(2, OuterType.CLIENT_REQ_SECURE, ct))
        await self.writer.drain()
        log.info("→ type 3 REQ_SECURE (16B ct)")

        header = await self.reader.readexactly(4)
        _seq, mtype, _ = decode_outer(header)
        if mtype != OuterType.CONTROLLER_ACK_SECURE:
            raise RuntimeError(f"expected type 4, got {mtype}")
        echoed = await self.reader.readexactly(BLOCK_SIZE)
        if echoed != ct:
            raise RuntimeError("type 4 ciphertext did not match type 3")
        log.info("← type 4 ACK_SECURE (matches) — handshake complete")
        self.send_seq = 2  # next app-data seq will be 3

    def _next_seq(self) -> int:
        self.send_seq = (self.send_seq % 0xFFFF) + 1
        return self.send_seq

    async def send_inner(self, msg_type: int, data: bytes = b"") -> None:
        assert self.session_key is not None
        frame = encode_inner(msg_type, data)
        seq = self._next_seq()
        ct = encrypt(frame, self.session_key, seq)
        self.writer.write(encode_outer(seq, OuterType.APP_DATA, ct))
        await self.writer.drain()

    async def poll_status(self, start: int = 1, end: int = 36) -> None:
        await self.send_inner(
            InnerType.REQ_OBJECT_STATUS, struct.pack(">BHH", 2, start, end)
        )

    async def send_switch_event(self, unit: int, on: bool) -> None:
        """Simulate a wall-switch press: Translator → Controller CONTROLLER_COMMAND."""
        cmd = 1 if on else 0
        data = struct.pack(">BBH", cmd, 0, unit)
        await self.send_inner(InnerType.CONTROLLER_COMMAND, data)
        log.info("→ CONTROLLER_COMMAND unit %d %s", unit, "ON" if on else "OFF")

    async def read_loop(self) -> None:
        """Background task: read frames off the wire and log them."""
        assert self.session_key is not None
        buf = bytearray()
        while True:
            try:
                data = await self.reader.read(4096)
            except ConnectionError:
                log.info("connection closed")
                return
            if not data:
                log.info("EOF")
                return
            buf.extend(data)
            while True:
                consumed = self._consume_one(buf)
                if consumed == 0:
                    break
                del buf[:consumed]

    def _consume_one(self, buf: bytearray) -> int:
        if len(buf) < 4:
            return 0
        seq, mtype, _ = decode_outer(bytes(buf[:4]))
        if mtype == OuterType.CONTROLLER_TERMINATED:
            log.info("← type 6 CONTROLLER_TERMINATED")
            return 4
        if mtype != OuterType.APP_DATA:
            log.info("← unexpected outer type %d seq=%d", mtype, seq)
            return 4
        if len(buf) < 4 + BLOCK_SIZE:
            return 0
        assert self.session_key is not None
        first_ct = bytes(buf[4 : 4 + BLOCK_SIZE])
        first_pt = decrypt(first_ct, self.session_key, seq)
        length_byte = first_pt[1]
        inner_total = 2 + length_byte + 2
        body_total = ((inner_total + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
        total = 4 + body_total
        if len(buf) < total:
            return 0
        body = bytes(buf[4:total])
        plain = decrypt(body, self.session_key, seq)
        msg_type, data = decode_inner(plain[:inner_total])
        try:
            name = InnerType(msg_type).name
        except ValueError:
            name = f"0x{msg_type:02X}"
        marker = " ★ PUSH" if seq == 0 else ""
        log.info("← %s seq=%d  data=%s%s", name, seq, data.hex().upper(), marker)
        if msg_type == InnerType.OBJECT_STATUS and len(data) > 1 and data[0] == 0x02:
            on_units = []
            for i in range(1, len(data), 5):
                if i + 5 > len(data):
                    break
                unit = (data[i] << 8) | data[i + 1]
                status = data[i + 2]
                if status != 0:
                    on_units.append(f"u{unit}={status}")
            log.info("   ON: %s", ", ".join(on_units) if on_units else "(none)")
        return total


async def run(args: argparse.Namespace) -> int:
    private_key = load_private_key(Path(args.env))
    reader, writer = await asyncio.open_connection(args.host, args.port)
    log.info("connected to %s:%d", args.host, args.port)
    trans = FakeTranslator(reader, writer, private_key)

    await trans.handshake()
    await trans.send_inner(InnerType.ENABLE_NOTIFICATIONS, b"\x01")
    log.info("→ ENABLE_NOTIFICATIONS")

    read_task = asyncio.create_task(trans.read_loop())

    # One-shot switch event if requested.
    if args.switch_event:
        unit_s, state_s = args.switch_event.split(":")
        await trans.send_switch_event(int(unit_s), state_s.lower() in ("on", "1", "true"))

    # Poll loop.
    try:
        while True:
            await trans.poll_status()
            await asyncio.sleep(args.poll_interval)
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        read_task.cancel()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Fake Translator for bridge smoke-testing.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4369)
    parser.add_argument("--env", default=".env")
    parser.add_argument("--poll-interval", type=float, default=0.5,
                        help="seconds between REQ_OBJECT_STATUS polls (default 0.5)")
    parser.add_argument("--switch-event",
                        help="simulate a wall-switch press, e.g. '9:on' or '4:off'")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(message)s",
        datefmt="%H:%M:%S",
    )
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
