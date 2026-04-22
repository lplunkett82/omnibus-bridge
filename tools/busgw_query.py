"""Single-shot query tool for the Bus Gateway ASCII protocol on port 43694.

Read-only by default: the command string is rejected if it contains `=`
(writes) unless --allow-writes is passed. Connects, sends `[<cmd>]\\r`,
reads until quiet for --read-seconds, then disconnects cleanly.

Usage:
    python tools/busgw_query.py "?"
    python tools/busgw_query.py "HELP"
    python tools/busgw_query.py "BS012"
    python tools/busgw_query.py "BS012=001" --allow-writes      # dangerous

The raw input and output are printed with both ASCII and hex so weird
characters are visible.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time

DEFAULT_HOST = "192.0.2.10"
DEFAULT_PORT = 43694


def _format_line(prefix: str, data: bytes) -> str:
    text = data.decode("ascii", errors="replace")
    return f"{prefix}  ascii={text!r}  hex={data.hex().upper()}"


async def query(
    host: str, port: int, command: str, read_seconds: float, raw: bool
) -> int:
    if raw:
        payload = command.encode("ascii", errors="strict")
    else:
        payload = f"[{command}]\r".encode("ascii")

    print(_format_line("-> ", payload))

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=5.0
        )
    except Exception as e:
        print(f"connect error: {type(e).__name__}: {e}")
        return 3

    try:
        writer.write(payload)
        await writer.drain()

        buf = bytearray()
        deadline = time.monotonic() + read_seconds
        last_rx = time.monotonic()

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            # Stop after 1.5s of quiet since last byte.
            quiet = time.monotonic() - last_rx
            timeout = min(remaining, max(0.1, 1.5 - quiet))
            try:
                chunk = await asyncio.wait_for(reader.read(256), timeout=timeout)
            except asyncio.TimeoutError:
                if buf and (time.monotonic() - last_rx) >= 1.5:
                    break
                continue
            if not chunk:
                break
            buf.extend(chunk)
            last_rx = time.monotonic()

        if not buf:
            print("<- (no response)")
            return 1

        # Split on CR for readability, but also print the raw buffer.
        print(_format_line("<- ", bytes(buf)))
        # Framed breakdown.
        parts = bytes(buf).split(b"\r")
        for i, part in enumerate(parts):
            if part or i < len(parts) - 1:
                print(f"   frame[{i}]: ascii={part.decode('ascii', errors='replace')!r}")
        return 0
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bus Gateway ASCII protocol query (read-only by default).",
    )
    parser.add_argument("command", help="ASCII command (will be wrapped in [..]\\r).")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--read-seconds", type=float, default=3.0,
                        help="Max seconds to keep reading after send.")
    parser.add_argument("--allow-writes", action="store_true",
                        help="Permit '=' in command (writes). Off by default.")
    parser.add_argument("--raw", action="store_true",
                        help="Send command bytes literally (no [..] or \\r wrapping).")
    args = parser.parse_args()

    if "=" in args.command and not args.allow_writes:
        print("refusing: command contains '=' (write); re-run with --allow-writes",
              file=sys.stderr)
        return 2

    try:
        return asyncio.run(query(args.host, args.port, args.command,
                                  args.read_seconds, args.raw))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
