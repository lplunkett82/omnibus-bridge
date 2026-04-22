"""AES-128-ECB with per-block sequence-number XOR.

Per the Omni-Link II spec:

1. Plaintext is zero-padded on the right to a multiple of 16 bytes.
2. For each 16-byte block, byte[0] is XOR'd with seq_MSB and byte[1] with seq_LSB.
3. Each block is AES-128-ECB encrypted with the session key.

The same seq is applied to every block of a single message. Decryption reverses
the steps (AES decrypt each block, then XOR back).

The session key is derived from the 128-bit private key and the 40-bit
session_id returned by the controller:

    session_key[0..10]  = private_key[0..10]                      (88 bits)
    session_key[11..15] = private_key[11..15] XOR session_id      (40 bits)
"""
from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16
SESSION_ID_LEN = 5
PRIVATE_KEY_LEN = 16


def derive_session_key(private_key: bytes, session_id: bytes) -> bytes:
    """Derive the 16-byte session key from the private key and 5-byte session_id."""
    if len(private_key) != PRIVATE_KEY_LEN:
        raise ValueError(f"private_key must be {PRIVATE_KEY_LEN} bytes, got {len(private_key)}")
    if len(session_id) != SESSION_ID_LEN:
        raise ValueError(f"session_id must be {SESSION_ID_LEN} bytes, got {len(session_id)}")
    high = private_key[:11]
    # Lengths are validated above; no need for zip strict= (also: strict= is 3.10+).
    low = bytes(a ^ b for a, b in zip(private_key[11:], session_id))
    return high + low


def pad_block(data: bytes) -> bytes:
    """Right-pad *data* with zero bytes to the next 16-byte boundary."""
    remainder = len(data) % BLOCK_SIZE
    if remainder == 0:
        return data
    return data + bytes(BLOCK_SIZE - remainder)


def _xor_seq(block: bytes, seq: int) -> bytes:
    msb = (seq >> 8) & 0xFF
    lsb = seq & 0xFF
    return bytes([block[0] ^ msb, block[1] ^ lsb]) + block[2:]


def encrypt(plaintext: bytes, key: bytes, seq: int) -> bytes:
    """Encrypt *plaintext* using AES-128-ECB + sequence-XOR. Zero-pads as needed."""
    padded = pad_block(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    out = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        block = _xor_seq(padded[i : i + BLOCK_SIZE], seq)
        out.extend(cipher.update(block))
    out.extend(cipher.finalize())
    return bytes(out)


def decrypt(ciphertext: bytes, key: bytes, seq: int) -> bytes:
    """Decrypt *ciphertext* (AES-128-ECB), then reverse the sequence-XOR per block."""
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length {len(ciphertext)} not a multiple of {BLOCK_SIZE}")
    cipher = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    raw = cipher.update(ciphertext) + cipher.finalize()
    out = bytearray()
    for i in range(0, len(raw), BLOCK_SIZE):
        out.extend(_xor_seq(raw[i : i + BLOCK_SIZE], seq))
    return bytes(out)
