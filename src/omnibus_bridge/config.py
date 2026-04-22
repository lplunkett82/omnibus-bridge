"""Configuration loading.

Right now we only need the 16-byte private key (two 8-byte halves from
`.env`). YAML config + MQTT settings come in the MQTT phase.
"""
from __future__ import annotations

from pathlib import Path


def load_private_key(env_path: Path) -> bytes:
    """Read OMNILINK_KEY1 / OMNILINK_KEY2 from `.env` and return the 16-byte key.

    Both halves are hex strings (with or without separators like `-`, `:`, spaces).
    Raises `RuntimeError` with a human-readable message on missing or malformed keys.
    """
    if not env_path.exists():
        raise RuntimeError(f".env not found at {env_path}")
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
        raise RuntimeError("OMNILINK_KEY1 and OMNILINK_KEY2 must be set in .env")
    clean = lambda h: "".join(c for c in h if c not in "-: ")  # noqa: E731
    try:
        raw = bytes.fromhex(clean(key1)) + bytes.fromhex(clean(key2))
    except ValueError as e:
        raise RuntimeError(f"invalid hex in OMNILINK_KEY1/2: {e}") from e
    if len(raw) != 16:
        raise RuntimeError(f"combined private key must be 16 bytes, got {len(raw)}")
    return raw
