"""Server-side Omni-Link II session state machine (sans-IO).

The bridge acts as the Omni-Link II **controller** — the Translator connects
to us outbound on TCP :4369, we complete the handshake, then exchange
AES-encrypted type-32 application data messages over a long-lived session.

This module owns the protocol state machine but does no I/O. Feed incoming
bytes in, pull outgoing bytes + parsed events out. The transport layer
(`transport.py`) is a thin asyncio wrapper.

Handshake (we are the controller):

    client (Translator)                 server (us, this module)
        │                                      │
        │── type 1 (no body) ────────────────▶ │
        │                                      │  generate 5B session_id
        │                                      │  derive 16B session key
        │◀──── type 2: proto_ver + session_id ─┤
        │                                      │
        │── type 3: AES(session_id + 0×11) ──▶ │
        │                                      │  decrypt with session key
        │                                      │  verify plaintext matches
        │◀──── type 4: AES(session_id + 0×11) ─┤  (same ciphertext echoed)
        │                                      │
        │── type 32: AES(inner frame) ───────▶ │
        │◀──── type 32: AES(inner frame) ──────┤
        │                                      │
        │── type 5 (terminated) ─────────────▶ │
        │◀──── type 6 (terminated) ────────────┤

Outer packet body sizes (used by the buffer splitter since there's no
explicit length field):

    type     body size
    ────     ─────────
    0,1,5,   0 (header-only)
    6,7
    2        7  (proto_ver:2 + session_id:5)
    3, 4     16 (one AES block: encrypted session_id + 11×0)
    32       N × 16, where N comes from the first decrypted block's
             inner-frame length byte (total inner bytes = 2+length+2,
             rounded up to 16)
"""
from __future__ import annotations

import os
import struct
from collections import deque
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Union

from .crypto import BLOCK_SIZE, SESSION_ID_LEN, decrypt, derive_session_key, encrypt
from .protocol import (
    OUTER_HEADER_LEN,
    InvalidFrame,
    OuterType,
    decode_inner,
    decode_outer,
    encode_inner,
    encode_outer,
)

PROTOCOL_VERSION = 0x0001


class SessionState(Enum):
    AWAITING_NEW_SESSION = auto()  # expecting type 1
    AWAITING_SECURE = auto()  # sent type 2, expecting type 3
    ESTABLISHED = auto()  # handshake done, type 32 traffic flows
    CLOSED = auto()


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HandshakeComplete:
    session_id: bytes


@dataclass(frozen=True)
class InnerFrameReceived:
    """An application-data inner frame decrypted off the wire."""

    msg_type: int
    data: bytes
    outer_seq: int  # seq of the outer packet that carried this (0 = unsolicited push)


@dataclass(frozen=True)
class PeerTerminated:
    """The client sent type 5 (CLIENT_TERMINATED)."""


@dataclass(frozen=True)
class HandshakeFailed:
    """Handshake aborted. Reason is a short human-readable string."""

    reason: str


Event = Union[HandshakeComplete, InnerFrameReceived, PeerTerminated, HandshakeFailed]


# ---------------------------------------------------------------------------
# Server session
# ---------------------------------------------------------------------------


class ServerSession:
    """Sans-IO Omni-Link II controller-side session.

    Typical loop in the transport layer:

        session = ServerSession(private_key)
        while data := await reader.read(4096):
            session.receive_bytes(data)
            if out := session.bytes_to_send():
                writer.write(out); await writer.drain()
            while event := session.next_event():
                await handle(event)

    Call `send_inner(msg_type, data)` from the application to push an
    outbound inner frame; bytes appear in `bytes_to_send()` on the next
    drain cycle.
    """

    def __init__(
        self,
        private_key: bytes,
        *,
        rng: Callable[[int], bytes] = os.urandom,
    ) -> None:
        if len(private_key) != 16:
            raise ValueError(f"private_key must be 16 bytes, got {len(private_key)}")
        self._private_key = private_key
        self._rng = rng
        self._state = SessionState.AWAITING_NEW_SESSION
        self._inbound = bytearray()
        self._outbound = bytearray()
        self._events: deque[Event] = deque()
        self._session_id: bytes | None = None
        self._session_key: bytes | None = None
        # Our outbound seq for replies and pushes. Starts at 0; `_next_send_seq`
        # increments to 1 first. seq=0 is reserved for unsolicited "no tracking"
        # pushes (e.g. 0x3B state changes).
        self._send_seq: int = 0

    # ---- Public API --------------------------------------------------------

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def session_id(self) -> bytes | None:
        return self._session_id

    def receive_bytes(self, data: bytes) -> None:
        """Append wire bytes from the peer. Drives the state machine."""
        if self._state is SessionState.CLOSED:
            return
        self._inbound.extend(data)
        self._drain_inbound()

    def bytes_to_send(self) -> bytes:
        """Pop and return all queued outbound bytes."""
        out = bytes(self._outbound)
        self._outbound.clear()
        return out

    def next_event(self) -> Event | None:
        """Pop and return the next parsed event, or None if queue is empty."""
        if self._events:
            return self._events.popleft()
        return None

    def send_inner(
        self,
        msg_type: int,
        data: bytes = b"",
        *,
        use_seq_zero: bool = False,
        reply_seq: int | None = None,
    ) -> None:
        """Queue an outbound inner frame.

        Seq selection (priority order):
          - `use_seq_zero=True`  → seq=0 ("tracking disabled", used for
            unsolicited 0x3B state pushes; matches OmniPro's behavior).
          - `reply_seq=<n>`      → echo the inbound packet's seq. Use this
            for any response to a Translator poll or query. OmniPro replies
            this way on every response in captures; treating replies with
            our own counter makes the Translator classify us as "flaky"
            and results in slow 2 s polls + 16 s session drops.
          - neither              → our own monotonic counter (last-resort
            fallback for bridge-initiated queries; none exist today).
        """
        if self._state is not SessionState.ESTABLISHED:
            raise RuntimeError(
                f"cannot send_inner in state {self._state.name}; session not established"
            )
        assert self._session_key is not None  # for type-checker; guaranteed by state
        frame = encode_inner(msg_type, data)
        if use_seq_zero:
            seq = 0
        elif reply_seq is not None:
            seq = reply_seq
        else:
            seq = self._next_send_seq()
        body = encrypt(frame, self._session_key, seq)
        self._outbound.extend(encode_outer(seq, OuterType.APP_DATA, body))

    def terminate(self) -> None:
        """Send CONTROLLER_TERMINATED (type 6) and move to CLOSED."""
        if self._state is SessionState.CLOSED:
            return
        self._outbound.extend(encode_outer(0, OuterType.CONTROLLER_TERMINATED))
        self._state = SessionState.CLOSED

    # ---- Inbound parsing ---------------------------------------------------

    def _drain_inbound(self) -> None:
        """Repeatedly peel complete outer packets off the inbound buffer."""
        while True:
            consumed = self._try_parse_one_packet()
            if consumed == 0:
                return
            del self._inbound[:consumed]

    def _try_parse_one_packet(self) -> int:
        """Try to parse one outer packet from the head of `_inbound`.

        Returns bytes consumed (0 if not enough data to decide). State
        transitions happen here as a side effect.
        """
        if len(self._inbound) < OUTER_HEADER_LEN:
            return 0
        seq, mtype, _rest = decode_outer(bytes(self._inbound[:OUTER_HEADER_LEN]))
        body_len = self._expected_body_len(mtype)
        if body_len is None:
            # Type 32 — need at least one decrypted block to learn the full size.
            return self._try_parse_app_data(seq)
        total = OUTER_HEADER_LEN + body_len
        if len(self._inbound) < total:
            return 0
        body = bytes(self._inbound[OUTER_HEADER_LEN:total])
        self._handle_outer(seq, mtype, body)
        return total

    @staticmethod
    def _expected_body_len(mtype: int) -> int | None:
        """Return the fixed body length for `mtype`, or None for type 32."""
        if mtype in (
            OuterType.NO_MSG,
            OuterType.CLIENT_REQ_NEW_SESSION,
            OuterType.CLIENT_TERMINATED,
            OuterType.CONTROLLER_TERMINATED,
            OuterType.CONTROLLER_CANNOT_START,
        ):
            return 0
        if mtype == OuterType.CONTROLLER_ACK_NEW_SESSION:
            return 7
        if mtype in (OuterType.CLIENT_REQ_SECURE, OuterType.CONTROLLER_ACK_SECURE):
            return BLOCK_SIZE  # 16
        if mtype == OuterType.APP_DATA:
            return None
        # Unknown type — treat as header-only, we'll reject in _handle_outer.
        return 0

    def _try_parse_app_data(self, seq: int) -> int:
        """Parse a type-32 packet. Body size is learned by decrypting block 1."""
        if self._state is not SessionState.ESTABLISHED or self._session_key is None:
            # APP_DATA before handshake = Translator reusing a stale session
            # on a fresh TCP (happens once per bridge restart). Reply with
            # type 6 (TERMINATED) echoing the inbound seq; then close. The
            # Translator always imposes ~14 s backoff before its fresh type-1
            # handshake regardless of reply seq or type — confirmed empirical
            # (2026-04-22), not a fixable protocol nuance.
            self._terminate_stale_session(
                "APP_DATA before handshake complete", reply_seq=seq
            )
            return len(self._inbound)  # flush rest
        start = OUTER_HEADER_LEN
        if len(self._inbound) < start + BLOCK_SIZE:
            return 0
        first_ct = bytes(self._inbound[start : start + BLOCK_SIZE])
        first_pt = decrypt(first_ct, self._session_key, seq)
        if first_pt[0] != 0x21:
            self._events.append(
                HandshakeFailed(
                    f"APP_DATA first block not an inner frame (start=0x{first_pt[0]:02X})"
                )
            )
            # Skip just this block; keep the session open so a resync is possible.
            return start + BLOCK_SIZE
        length_byte = first_pt[1]
        inner_total = 2 + length_byte + 2  # start + length + (type+data) + CRC
        body_total = ((inner_total + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
        total = OUTER_HEADER_LEN + body_total
        if len(self._inbound) < total:
            return 0
        body = bytes(self._inbound[OUTER_HEADER_LEN:total])
        plain = decrypt(body, self._session_key, seq)
        try:
            msg_type, data = decode_inner(plain[:inner_total])
        except InvalidFrame as e:
            self._events.append(HandshakeFailed(f"bad inner frame: {e}"))
            return total
        self._events.append(InnerFrameReceived(msg_type, data, seq))
        return total

    def _handle_outer(self, seq: int, mtype: int, body: bytes) -> None:
        """Dispatch a complete outer packet to the right state handler."""
        if mtype == OuterType.CLIENT_TERMINATED:
            self._events.append(PeerTerminated())
            self._outbound.extend(encode_outer(0, OuterType.CONTROLLER_TERMINATED))
            self._state = SessionState.CLOSED
            return

        if self._state is SessionState.AWAITING_NEW_SESSION:
            if mtype != OuterType.CLIENT_REQ_NEW_SESSION:
                self._fail_handshake(
                    f"expected type 1 (NEW_SESSION), got type {mtype}"
                )
                return
            self._send_new_session_ack(seq)
            self._state = SessionState.AWAITING_SECURE
            return

        if self._state is SessionState.AWAITING_SECURE:
            if mtype != OuterType.CLIENT_REQ_SECURE:
                self._fail_handshake(
                    f"expected type 3 (REQ_SECURE), got type {mtype}"
                )
                return
            self._verify_secure_and_ack(seq, body)
            return

        # In ESTABLISHED, only type 32 (handled in _try_parse_app_data) and
        # type 5 (handled above) are expected.
        self._events.append(
            HandshakeFailed(f"unexpected type {mtype} in state {self._state.name}")
        )

    # ---- Handshake internals ----------------------------------------------

    def _send_new_session_ack(self, client_seq: int) -> None:
        """Generate session_id, derive key, send type 2 echoing the client's seq.

        Per observed OmniPro behaviour (and the spec's implicit convention),
        the controller's type-2 reply carries the same seq as the type-1
        request. Hard-coding seq=1 here causes the Translator to reject the
        reply and retry.
        """
        self._session_id = self._rng(SESSION_ID_LEN)
        self._session_key = derive_session_key(self._private_key, self._session_id)
        body = struct.pack(">H", PROTOCOL_VERSION) + self._session_id
        self._outbound.extend(
            encode_outer(client_seq, OuterType.CONTROLLER_ACK_NEW_SESSION, body)
        )

    def _verify_secure_and_ack(self, seq: int, body: bytes) -> None:
        """Decrypt type 3, verify plaintext, echo as type 4."""
        assert self._session_key is not None
        assert self._session_id is not None
        try:
            plain = decrypt(body, self._session_key, seq)
        except Exception as e:
            self._fail_handshake(f"type 3 decrypt failed: {e}")
            return
        expected = self._session_id + b"\x00" * (BLOCK_SIZE - SESSION_ID_LEN)
        if plain != expected:
            self._fail_handshake(
                f"type 3 plaintext mismatch: got {plain.hex().upper()}, "
                f"expected {expected.hex().upper()}"
            )
            return
        # Echo the SAME ciphertext back as type 4. Per spec + confirmed on the
        # wire: OmniPro's type 4 body is byte-identical to its type 3 body.
        self._outbound.extend(encode_outer(seq, OuterType.CONTROLLER_ACK_SECURE, body))
        self._state = SessionState.ESTABLISHED
        self._events.append(HandshakeComplete(self._session_id))

    def _fail_handshake(self, reason: str) -> None:
        """Reject a session for a protocol/auth error.

        Emits CONTROLLER_CANNOT_START (type 7) — the spec's "I refuse to start
        a new session" message. Use for genuine errors: wrong message order,
        bad type-3 ciphertext, etc. For the "Translator reusing stale session
        on fresh TCP" case, use `_terminate_stale_session` instead.
        """
        self._events.append(HandshakeFailed(reason))
        self._outbound.extend(encode_outer(0, OuterType.CONTROLLER_CANNOT_START))
        self._state = SessionState.CLOSED

    def _terminate_stale_session(self, reason: str, *, reply_seq: int = 0) -> None:
        """Reject APP_DATA that arrives without a fresh handshake.

        Emits CONTROLLER_TERMINATED (type 6). Semantically: "you don't have
        a session with me; start a new one." Echo the inbound seq so the
        Translator's response-matching logic sees this as an in-session
        reply rather than an unsolicited frame.
        """
        self._events.append(HandshakeFailed(reason))
        self._outbound.extend(encode_outer(reply_seq, OuterType.CONTROLLER_TERMINATED))
        self._state = SessionState.CLOSED

    def _next_send_seq(self) -> int:
        """Next non-zero outbound seq (wraps 65535 → 1, skipping 0)."""
        self._send_seq = (self._send_seq % 0xFFFF) + 1
        return self._send_seq
