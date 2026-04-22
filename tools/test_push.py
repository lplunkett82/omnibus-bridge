"""One-shot test: start bridge, wait for Translator, push one unit ON/OFF.

Usage:
    python tools/test_push.py --unit 9 --on-duration 5

Flow:
  1. Bridge starts listening.
  2. Wait for Translator to connect + handshake complete.
  3. Sleep `stabilize` seconds (let the first poll happen).
  4. Push unit N ON (seq=0 EXT_OBJECT_STATUS).
  5. Sleep `on_duration` seconds — USER WATCHES LIGHT.
  6. Push unit N OFF.
  7. Sleep `tail` seconds, then shut down cleanly.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from omnibus_bridge.config import load_private_key  # noqa: E402
from omnibus_bridge.main import Bridge  # noqa: E402
from omnibus_bridge.session import SessionState  # noqa: E402

log = logging.getLogger("test-push")


async def wait_for_handshake(bridge: Bridge, timeout: float = 60.0) -> None:
    """Wait until a Translator is connected + handshake has completed."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        c = bridge.server.current_client
        if c is not None and c.session.state is SessionState.ESTABLISHED:
            log.info("handshake confirmed with %s", c.peer)
            return
        await asyncio.sleep(0.2)
    raise TimeoutError(f"no Translator handshake within {timeout}s")


async def run(args: argparse.Namespace) -> int:
    key = load_private_key(Path(args.env))
    bridge = Bridge(key, host=args.host, port=args.port, unit_count=args.units)
    await bridge.start()
    log.info("bridge listening on %s:%d", args.host, bridge.server.port)

    try:
        await wait_for_handshake(bridge, timeout=args.handshake_timeout)
        log.info("stabilizing for %.1fs (letting first poll happen)", args.stabilize)
        await asyncio.sleep(args.stabilize)

        log.info("★ PUSH unit %d ON", args.unit)
        await bridge.set_unit(args.unit, 1)
        log.info("sleeping %.1fs — WATCH THE LIGHT", args.on_duration)
        await asyncio.sleep(args.on_duration)

        log.info("★ PUSH unit %d OFF", args.unit)
        await bridge.set_unit(args.unit, 0)
        await asyncio.sleep(args.tail)
    except TimeoutError as e:
        log.error("%s", e)
        return 2
    finally:
        log.info("shutting down")
        await bridge.stop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="One-shot light-toggle test against the real Translator.")
    parser.add_argument("--unit", type=int, required=True, help="unit number to toggle (1..36)")
    parser.add_argument("--on-duration", type=float, default=5.0, help="seconds to hold the light ON before OFF")
    parser.add_argument("--stabilize", type=float, default=3.0, help="seconds to wait after handshake before pushing")
    parser.add_argument("--tail", type=float, default=3.0, help="seconds to wait after OFF push before shutdown")
    parser.add_argument("--handshake-timeout", type=float, default=60.0)
    parser.add_argument("--env", default=str(REPO_ROOT / ".env"))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=4369)
    parser.add_argument("--units", type=int, default=36)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
