"""Passive listener for the Bus Gateway ASCII protocol on port 43694.

Read-only. Opens a TCP connection, sends NOTHING, logs everything the
Translator pushes, framed on CR (0x0D). Default 30 seconds.

Usage:
    python tools/busgw_listen.py
    python tools/busgw_listen.py --seconds 120
    python tools/busgw_listen.py --host 192.0.2.10 --port 43694

Safety: this tool NEVER writes to the socket (writer is closed immediately
after connect via half-close where supported). If the Bus Gateway is push-
only on connect, we will see unsolicited messages stream in. If it's purely
request/response, we will see nothing and can make that a finding.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time

DEFAULT_HOST = "192.0.2.10"
DEFAULT_PORT = 43694


async def listen(host: str, port: int, seconds: float) -> None:
    print(f"Connecting to {host}:{port} ...")
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=5.0
    )
    print(f"Connected. Listening for {seconds}s without sending anything.")
    print("(If any canary device changes state during this window, note the timestamp.)")
    print("-" * 72)

    deadline = time.monotonic() + seconds
    buffer = bytearray()
    msg_count = 0

    try:
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(256), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if not chunk:
                print("[server closed connection]")
                break
            buffer.extend(chunk)
            # Frame on CR.
            while b"\r" in buffer:
                idx = buffer.index(b"\r")
                msg = bytes(buffer[:idx])
                del buffer[: idx + 1]
                msg_count += 1
                ts = time.strftime("%H:%M:%S")
                try:
                    text = msg.decode("ascii", errors="replace")
                except Exception:
                    text = repr(msg)
                print(f"[{ts}] #{msg_count:04d}  {text}")
    finally:
        print("-" * 72)
        leftover = bytes(buffer)
        if leftover:
            print(f"unframed tail ({len(leftover)}B): {leftover!r}")
        print(f"Total framed messages: {msg_count}")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        print("Connection closed.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Passive Bus Gateway listener (read-only).")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--seconds", type=float, default=30.0)
    args = parser.parse_args()
    try:
        asyncio.run(listen(args.host, args.port, args.seconds))
        return 0
    except KeyboardInterrupt:
        print("Interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
