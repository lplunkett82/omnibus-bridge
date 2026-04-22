"""Server-session state-machine tests.

The Translator's handshake behaviour is well-understood from captures:
  - It sends type 1 (no body) on a freshly opened TCP connection.
  - On receipt of type 2 (controller ACK with proto_ver + session_id), it
    derives the same session key we derive, encrypts (session_id + 11×0),
    and sends it as type 3.
  - It expects our type 4 to have the byte-identical ciphertext.
  - It then issues unsolicited type-32 pushes (the ~130ms poll loop).

These tests simulate that peer with a scripted byte generator so the
session logic is exercised independently of any network I/O.
"""
from __future__ import annotations

import struct

import pytest

from omnibus_bridge.crypto import BLOCK_SIZE, SESSION_ID_LEN, derive_session_key, encrypt
from omnibus_bridge.protocol import (
    InnerType,
    OuterType,
    decode_outer,
    encode_inner,
    encode_outer,
)
from omnibus_bridge.session import (
    HandshakeComplete,
    HandshakeFailed,
    InnerFrameReceived,
    PROTOCOL_VERSION,
    PeerTerminated,
    ServerSession,
    SessionState,
)

PRIVATE_KEY = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
FIXED_SESSION_ID = bytes.fromhex("AABBCCDDEE")


def _fixed_rng(data: bytes):
    """Return an RNG that yields exactly *data* on the first call."""

    def rng(n: int) -> bytes:
        assert n == len(data), f"RNG asked for {n} bytes, fixture has {len(data)}"
        return data

    return rng


def _complete_handshake(
    session: ServerSession,
    private_key: bytes = PRIVATE_KEY,
    session_id: bytes = FIXED_SESSION_ID,
) -> bytes:
    """Drive a ServerSession through a successful handshake.

    Returns the derived session key so tests can continue encrypting/
    decrypting app-data traffic against the same session.
    """
    # Client sends type 1 (no body).
    session.receive_bytes(encode_outer(seq=1, mtype=OuterType.CLIENT_REQ_NEW_SESSION))
    # Server should reply type 2 with proto_ver + session_id.
    out = session.bytes_to_send()
    seq, mtype, body = decode_outer(out)
    assert seq == 1
    assert mtype == OuterType.CONTROLLER_ACK_NEW_SESSION
    assert body[:2] == struct.pack(">H", PROTOCOL_VERSION)
    assert body[2 : 2 + SESSION_ID_LEN] == session_id

    # Client encrypts (session_id + 11×0) with derived key at seq=2.
    session_key = derive_session_key(private_key, session_id)
    plaintext = session_id + b"\x00" * (BLOCK_SIZE - SESSION_ID_LEN)
    ct = encrypt(plaintext, session_key, seq=2)
    session.receive_bytes(encode_outer(seq=2, mtype=OuterType.CLIENT_REQ_SECURE, body=ct))

    # Server should reply type 4 with byte-identical ciphertext.
    out = session.bytes_to_send()
    seq, mtype, body = decode_outer(out)
    assert seq == 2
    assert mtype == OuterType.CONTROLLER_ACK_SECURE
    assert body == ct

    # Event queue should contain HandshakeComplete.
    ev = session.next_event()
    assert isinstance(ev, HandshakeComplete)
    assert ev.session_id == session_id
    assert session.state is SessionState.ESTABLISHED
    return session_key


# ---------------------------------------------------------------------------
# Handshake happy path
# ---------------------------------------------------------------------------


def test_full_handshake_reaches_established() -> None:
    session = ServerSession(PRIVATE_KEY, rng=_fixed_rng(FIXED_SESSION_ID))
    _complete_handshake(session)
    assert session.session_id == FIXED_SESSION_ID


def test_handshake_generates_random_session_id() -> None:
    # Two back-to-back sessions with the default os.urandom RNG must get
    # different session_ids.
    s1 = ServerSession(PRIVATE_KEY)
    s1.receive_bytes(encode_outer(seq=1, mtype=OuterType.CLIENT_REQ_NEW_SESSION))
    s2 = ServerSession(PRIVATE_KEY)
    s2.receive_bytes(encode_outer(seq=1, mtype=OuterType.CLIENT_REQ_NEW_SESSION))
    assert s1.session_id != s2.session_id


# ---------------------------------------------------------------------------
# Handshake failure paths
# ---------------------------------------------------------------------------


def test_app_data_before_handshake_rejects_with_type6() -> None:
    # Real-world trigger: Translator reuses a stale session on a fresh TCP
    # after we dropped. OmniPro replies with type 6 (TERMINATED) and the
    # Translator reconnects in ~2s; type 7 (CANNOT_START) causes a ~14s
    # backoff. Bridge must match OmniPro's behavior.
    session = ServerSession(PRIVATE_KEY)
    session.receive_bytes(encode_outer(seq=1, mtype=OuterType.APP_DATA, body=b""))
    ev = session.next_event()
    assert isinstance(ev, HandshakeFailed)
    _seq, mtype, _body = decode_outer(session.bytes_to_send())
    assert mtype == OuterType.CONTROLLER_TERMINATED
    assert session.state is SessionState.CLOSED


def test_bad_type3_ciphertext_rejects() -> None:
    session = ServerSession(PRIVATE_KEY, rng=_fixed_rng(FIXED_SESSION_ID))
    session.receive_bytes(encode_outer(seq=1, mtype=OuterType.CLIENT_REQ_NEW_SESSION))
    session.bytes_to_send()  # discard type 2
    session.next_event()  # discard nothing (HandshakeComplete hasn't fired yet)
    # Encrypt with the WRONG key — server should reject.
    wrong_key = derive_session_key(b"\xFF" * 16, FIXED_SESSION_ID)
    plaintext = FIXED_SESSION_ID + b"\x00" * 11
    ct = encrypt(plaintext, wrong_key, seq=2)
    session.receive_bytes(encode_outer(seq=2, mtype=OuterType.CLIENT_REQ_SECURE, body=ct))
    ev = session.next_event()
    assert isinstance(ev, HandshakeFailed)
    assert "plaintext mismatch" in ev.reason
    _, mtype, _ = decode_outer(session.bytes_to_send())
    assert mtype == OuterType.CONTROLLER_CANNOT_START
    assert session.state is SessionState.CLOSED


# ---------------------------------------------------------------------------
# Post-handshake application data
# ---------------------------------------------------------------------------


def _encrypt_app_packet(session_key: bytes, inner_frame: bytes, seq: int) -> bytes:
    """Wrap an inner frame in an encrypted type-32 outer packet."""
    body = encrypt(inner_frame, session_key, seq)
    return encode_outer(seq, OuterType.APP_DATA, body)


def test_app_data_delivers_inner_frame_event() -> None:
    session = ServerSession(PRIVATE_KEY, rng=_fixed_rng(FIXED_SESSION_ID))
    session_key = _complete_handshake(session)
    # Client sends REQ_OBJECT_STATUS for Units 1..36.
    req_data = struct.pack(">BHH", 2, 1, 36)
    inner = encode_inner(InnerType.REQ_OBJECT_STATUS, req_data)
    session.receive_bytes(_encrypt_app_packet(session_key, inner, seq=3))

    ev = session.next_event()
    assert isinstance(ev, InnerFrameReceived)
    assert ev.msg_type == InnerType.REQ_OBJECT_STATUS
    assert ev.data == req_data
    assert ev.outer_seq == 3


def test_send_inner_produces_decryptable_packet() -> None:
    session = ServerSession(PRIVATE_KEY, rng=_fixed_rng(FIXED_SESSION_ID))
    session_key = _complete_handshake(session)
    # Server sends a sequenced OBJECT_STATUS (small variant, 1 unit record).
    data = bytes([0x02]) + struct.pack(">HBH", 4, 1, 0)  # obj_type=2, unit 4 ON
    session.send_inner(InnerType.OBJECT_STATUS, data)
    out = session.bytes_to_send()
    seq, mtype, body = decode_outer(out)
    assert mtype == OuterType.APP_DATA
    assert seq == 1  # first outbound sequenced reply after handshake
    # Client decrypts with the same key/seq.
    from omnibus_bridge.crypto import decrypt
    plain = decrypt(body, session_key, seq)
    # plain[:5+2] is the inner frame — first few bytes
    assert plain[0] == 0x21
    assert plain[2] == InnerType.OBJECT_STATUS


def test_send_inner_seq_zero_push() -> None:
    session = ServerSession(PRIVATE_KEY, rng=_fixed_rng(FIXED_SESSION_ID))
    session_key = _complete_handshake(session)
    # seq=0 push — this is the HA→light write path.
    ext_data = struct.pack(">BBHB4x", 0x02, 0x07, 4, 1)  # unit 4 ON
    session.send_inner(InnerType.EXT_OBJECT_STATUS, ext_data, use_seq_zero=True)
    out = session.bytes_to_send()
    seq, mtype, _body = decode_outer(out)
    assert seq == 0
    assert mtype == OuterType.APP_DATA


def test_send_inner_seq_increments_across_calls() -> None:
    session = ServerSession(PRIVATE_KEY, rng=_fixed_rng(FIXED_SESSION_ID))
    _complete_handshake(session)
    seqs = []
    for _ in range(3):
        session.send_inner(InnerType.ACK)
        seqs.append(decode_outer(session.bytes_to_send())[0])
    assert seqs == [1, 2, 3]


def test_send_inner_rejected_before_handshake() -> None:
    session = ServerSession(PRIVATE_KEY)
    with pytest.raises(RuntimeError, match="session not established"):
        session.send_inner(InnerType.ACK)


# ---------------------------------------------------------------------------
# Termination
# ---------------------------------------------------------------------------


def test_client_terminated_closes_session() -> None:
    session = ServerSession(PRIVATE_KEY, rng=_fixed_rng(FIXED_SESSION_ID))
    _complete_handshake(session)
    session.receive_bytes(encode_outer(seq=0, mtype=OuterType.CLIENT_TERMINATED))
    ev = session.next_event()
    assert isinstance(ev, PeerTerminated)
    # Server should reply type 6.
    _, mtype, _ = decode_outer(session.bytes_to_send())
    assert mtype == OuterType.CONTROLLER_TERMINATED
    assert session.state is SessionState.CLOSED


def test_controller_terminate_closes() -> None:
    session = ServerSession(PRIVATE_KEY, rng=_fixed_rng(FIXED_SESSION_ID))
    _complete_handshake(session)
    session.terminate()
    _, mtype, _ = decode_outer(session.bytes_to_send())
    assert mtype == OuterType.CONTROLLER_TERMINATED
    assert session.state is SessionState.CLOSED


# ---------------------------------------------------------------------------
# Buffer splitting (fragmented TCP arrivals)
# ---------------------------------------------------------------------------


def test_handshake_survives_byte_at_a_time_delivery() -> None:
    """TCP can fragment packets arbitrarily — session must buffer correctly."""
    session = ServerSession(PRIVATE_KEY, rng=_fixed_rng(FIXED_SESSION_ID))
    type1 = encode_outer(seq=1, mtype=OuterType.CLIENT_REQ_NEW_SESSION)
    # Feed byte-by-byte.
    for b in type1:
        session.receive_bytes(bytes([b]))
    # At this point the server should have sent type 2.
    assert session.state is SessionState.AWAITING_SECURE

    session_key = derive_session_key(PRIVATE_KEY, FIXED_SESSION_ID)
    plaintext = FIXED_SESSION_ID + b"\x00" * 11
    ct = encrypt(plaintext, session_key, seq=2)
    type3 = encode_outer(seq=2, mtype=OuterType.CLIENT_REQ_SECURE, body=ct)
    for b in type3:
        session.receive_bytes(bytes([b]))
    assert session.state is SessionState.ESTABLISHED


def test_multiple_app_packets_in_one_buffer() -> None:
    """Two back-to-back encrypted packets delivered in a single receive_bytes call."""
    session = ServerSession(PRIVATE_KEY, rng=_fixed_rng(FIXED_SESSION_ID))
    session_key = _complete_handshake(session)

    ack = encode_inner(InnerType.ACK)
    pkt_a = _encrypt_app_packet(session_key, ack, seq=3)
    pkt_b = _encrypt_app_packet(session_key, ack, seq=4)
    session.receive_bytes(pkt_a + pkt_b)

    e1 = session.next_event()
    e2 = session.next_event()
    assert isinstance(e1, InnerFrameReceived) and e1.outer_seq == 3
    assert isinstance(e2, InnerFrameReceived) and e2.outer_seq == 4
    assert session.next_event() is None
