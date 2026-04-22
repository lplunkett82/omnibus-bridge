"""Tests for AES-128 + sequence-XOR layer."""
from __future__ import annotations

import pytest

from omnibus_bridge.crypto import (
    BLOCK_SIZE,
    decrypt,
    derive_session_key,
    encrypt,
    pad_block,
)


PRIVATE_KEY = bytes.fromhex("000102030405060708090A0B0C0D0E0F")


def test_derive_session_key_xors_last_five_bytes() -> None:
    session_id = bytes.fromhex("AABBCCDDEE")
    key = derive_session_key(PRIVATE_KEY, session_id)
    # High 88 bits come straight from the private key.
    assert key[:11] == PRIVATE_KEY[:11]
    # Low 40 bits are XOR of private_key[11..15] and session_id.
    assert key[11] == 0x0B ^ 0xAA
    assert key[12] == 0x0C ^ 0xBB
    assert key[13] == 0x0D ^ 0xCC
    assert key[14] == 0x0E ^ 0xDD
    assert key[15] == 0x0F ^ 0xEE


def test_derive_session_key_rejects_bad_lengths() -> None:
    with pytest.raises(ValueError):
        derive_session_key(b"\x00" * 15, b"\x00" * 5)
    with pytest.raises(ValueError):
        derive_session_key(b"\x00" * 16, b"\x00" * 4)


def test_pad_block_rounds_up_to_16() -> None:
    assert pad_block(b"") == b""
    assert pad_block(b"\x01") == b"\x01" + b"\x00" * 15
    assert pad_block(b"\x01" * 16) == b"\x01" * 16
    assert pad_block(b"\x01" * 17) == b"\x01" * 17 + b"\x00" * 15


def test_encrypt_decrypt_roundtrip_single_block() -> None:
    key = b"\x00" * 16
    plaintext = b"hello omni-link!"  # 16 bytes
    assert len(plaintext) == BLOCK_SIZE
    for seq in (0, 1, 2, 65535):
        ct = encrypt(plaintext, key, seq)
        assert len(ct) == BLOCK_SIZE
        assert decrypt(ct, key, seq) == plaintext


def test_encrypt_decrypt_roundtrip_multi_block() -> None:
    key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
    # Session_id encrypted during handshake is 5 bytes → zero-padded to 16.
    plaintext = bytes.fromhex("AABBCCDDEE") + b"\x00" * 11
    ct = encrypt(plaintext, key, seq=1)
    assert decrypt(ct, key, seq=1) == plaintext


def test_seq_xor_changes_ciphertext() -> None:
    # Same plaintext, different seq → different ciphertext (proves the XOR happens).
    key = b"\x01" * 16
    plaintext = b"\x00" * 16
    ct_seq1 = encrypt(plaintext, key, seq=1)
    ct_seq2 = encrypt(plaintext, key, seq=2)
    assert ct_seq1 != ct_seq2


def test_decrypt_rejects_unaligned_ciphertext() -> None:
    with pytest.raises(ValueError):
        decrypt(b"\x00" * 15, b"\x00" * 16, seq=1)
