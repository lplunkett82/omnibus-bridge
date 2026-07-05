"""Asyncio server tests — scripted Translator driving OmniLinkServer over loopback.

These are the first tests where real TCP sockets are involved. The server
binds to an ephemeral port (host=127.0.0.1, port=0), a scripted "Translator"
client connects, performs the handshake, exchanges app data, and closes.
No network, no Translator — all loopback.
"""
from __future__ import annotations

import asyncio
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
    InnerFrameReceived,
    PROTOCOL_VERSION,
    PeerTerminated,
)
from omnibus_bridge.transport import OmniLinkServer

PRIVATE_KEY = bytes.fromhex("000102030405060708090A0B0C0D0E0F")


class ScriptedTranslator:
    """Minimal client that speaks the Translator side of the handshake.

    Buffers bytes off the socket and peels outer packets by expected body
    size (same logic as the server, but simpler since we only receive
    types 2, 4, 6, 7 and type-32 app data).
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.session_id: bytes | None = None
        self.session_key: bytes | None = None

    async def send_type1(self) -> None:
        self.writer.write(encode_outer(seq=1, mtype=OuterType.CLIENT_REQ_NEW_SESSION))
        await self.writer.drain()

    async def recv_type2(self) -> None:
        header = await self.reader.readexactly(4)
        seq, mtype, _ = decode_outer(header)
        assert mtype == OuterType.CONTROLLER_ACK_NEW_SESSION, f"expected type 2, got {mtype}"
        body = await self.reader.readexactly(7)
        assert body[:2] == struct.pack(">H", PROTOCOL_VERSION)
        self.session_id = body[2 : 2 + SESSION_ID_LEN]
        self.session_key = derive_session_key(PRIVATE_KEY, self.session_id)

    async def send_type3(self) -> None:
        assert self.session_id is not None and self.session_key is not None
        plaintext = self.session_id + b"\x00" * (BLOCK_SIZE - SESSION_ID_LEN)
        ct = encrypt(plaintext, self.session_key, seq=2)
        self.writer.write(encode_outer(seq=2, mtype=OuterType.CLIENT_REQ_SECURE, body=ct))
        await self.writer.drain()

    async def recv_type4(self) -> bytes:
        header = await self.reader.readexactly(4)
        seq, mtype, _ = decode_outer(header)
        assert mtype == OuterType.CONTROLLER_ACK_SECURE, f"expected type 4, got {mtype}"
        return await self.reader.readexactly(BLOCK_SIZE)

    async def full_handshake(self) -> None:
        await self.send_type1()
        await self.recv_type2()
        await self.send_type3()
        await self.recv_type4()

    async def send_app(self, inner_frame: bytes, seq: int) -> None:
        assert self.session_key is not None
        body = encrypt(inner_frame, self.session_key, seq)
        self.writer.write(encode_outer(seq, OuterType.APP_DATA, body))
        await self.writer.drain()

    async def recv_app(self) -> tuple[int, bytes]:
        """Receive one type-32 packet and return (outer_seq, decrypted_plaintext)."""
        assert self.session_key is not None
        header = await self.reader.readexactly(4)
        seq, mtype, _ = decode_outer(header)
        assert mtype == OuterType.APP_DATA, f"expected app data, got {mtype}"
        # First block to learn size.
        first_ct = await self.reader.readexactly(BLOCK_SIZE)
        from omnibus_bridge.crypto import decrypt
        first_pt = decrypt(first_ct, self.session_key, seq)
        length_byte = first_pt[1]
        inner_total = 2 + length_byte + 2
        body_total = ((inner_total + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
        remainder = await self.reader.readexactly(body_total - BLOCK_SIZE) if body_total > BLOCK_SIZE else b""
        plain = decrypt(first_ct + remainder, self.session_key, seq)
        return seq, plain

    def close(self) -> None:
        self.writer.close()


class CollectingHandler:
    """Event handler that records everything it sees, plus optional auto-reply."""

    def __init__(self) -> None:
        self.events: list = []
        self.client = None

    async def __call__(self, event, client) -> None:
        self.events.append(event)
        self.client = client


async def _start_server(handler):
    server = OmniLinkServer(PRIVATE_KEY, handler, host="127.0.0.1", port=0)
    await server.start()
    return server


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_server_completes_handshake_over_loopback() -> None:
    handler = CollectingHandler()
    server = await _start_server(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        trans = ScriptedTranslator(reader, writer)
        await trans.full_handshake()

        # Give the server a chance to process the last byte.
        await asyncio.sleep(0.05)
        assert any(isinstance(e, HandshakeComplete) for e in handler.events)
        assert handler.client is not None
        assert handler.client.session.session_id == trans.session_id
        trans.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_server_delivers_app_data_events() -> None:
    handler = CollectingHandler()
    server = await _start_server(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        trans = ScriptedTranslator(reader, writer)
        await trans.full_handshake()

        # Client sends REQ_OBJECT_STATUS.
        req_data = struct.pack(">BHH", 2, 1, 36)
        await trans.send_app(encode_inner(InnerType.REQ_OBJECT_STATUS, req_data), seq=3)
        await asyncio.sleep(0.05)
        frames = [e for e in handler.events if isinstance(e, InnerFrameReceived)]
        assert len(frames) == 1
        assert frames[0].msg_type == InnerType.REQ_OBJECT_STATUS
        assert frames[0].data == req_data
        trans.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_server_sends_inner_frame_to_client() -> None:
    handler = CollectingHandler()
    server = await _start_server(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        trans = ScriptedTranslator(reader, writer)
        await trans.full_handshake()
        await asyncio.sleep(0.05)

        # Server pushes a seq=0 EXT_OBJECT_STATUS (unit 4 ON).
        ext_data = struct.pack(">BBHB4x", 0x02, 0x07, 4, 1)
        assert handler.client is not None
        await handler.client.send_inner(
            InnerType.EXT_OBJECT_STATUS, ext_data, use_seq_zero=True
        )

        seq, plain = await trans.recv_app()
        assert seq == 0
        assert plain[0] == 0x21  # inner frame start
        assert plain[2] == InnerType.EXT_OBJECT_STATUS
        trans.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_new_connection_evicts_stale_client() -> None:
    """After a silent drop the Translator redials from a new port while the
    old socket still looks alive. The newest connection must win: the stale
    client is aborted and the new one can handshake normally."""
    handler = CollectingHandler()
    server = await _start_server(handler)
    try:
        # First client connects and completes handshake.
        r1, w1 = await asyncio.open_connection("127.0.0.1", server.port)
        trans1 = ScriptedTranslator(r1, w1)
        await trans1.full_handshake()
        await asyncio.sleep(0.05)
        first = server.current_client
        assert first is not None

        # Second client connects — evicts the first and handshakes fine.
        r2, w2 = await asyncio.open_connection("127.0.0.1", server.port)
        trans2 = ScriptedTranslator(r2, w2)
        await trans2.full_handshake()
        await asyncio.sleep(0.05)
        assert server.current_client is not None
        assert server.current_client is not first
        assert server.current_client.session.session_id == trans2.session_id

        # First client's socket is dead (RST or EOF).
        try:
            data = await asyncio.wait_for(r1.read(10), timeout=1.0)
            assert data == b""
        except ConnectionError:
            pass
        w1.close()
        trans2.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_connection_from_unlisted_peer_is_rejected() -> None:
    handler = CollectingHandler()
    server = OmniLinkServer(
        PRIVATE_KEY, handler, host="127.0.0.1", port=0,
        allowed_peer="203.0.113.9",
    )
    await server.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        eof = await asyncio.wait_for(reader.read(10), timeout=1.0)
        assert eof == b""
        assert server.current_client is None
        writer.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_handshake_timeout_aborts_idle_connection() -> None:
    """A client that connects but never handshakes must not hold the single
    client slot forever — the watchdog aborts it."""
    handler = CollectingHandler()
    server = OmniLinkServer(
        PRIVATE_KEY, handler, host="127.0.0.1", port=0,
        handshake_timeout=0.2,
    )
    await server.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        await asyncio.sleep(0.05)
        assert server.current_client is not None

        # Send nothing. Within the timeout window the server aborts us.
        try:
            data = await asyncio.wait_for(reader.read(10), timeout=1.0)
            assert data == b""
        except ConnectionError:
            pass
        await asyncio.sleep(0.05)
        assert server.current_client is None
        writer.close()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_client_disconnect_clears_current_client() -> None:
    handler = CollectingHandler()
    server = await _start_server(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        trans = ScriptedTranslator(reader, writer)
        await trans.full_handshake()
        await asyncio.sleep(0.05)
        assert server.current_client is not None

        # Client sends type 5 (terminated) then closes.
        writer.write(encode_outer(seq=0, mtype=OuterType.CLIENT_TERMINATED))
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        # Give server time to process.
        await asyncio.sleep(0.1)

        assert any(isinstance(e, PeerTerminated) for e in handler.events)
        assert server.current_client is None
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_server_stop_closes_active_client() -> None:
    handler = CollectingHandler()
    server = await _start_server(handler)
    reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
    trans = ScriptedTranslator(reader, writer)
    await trans.full_handshake()
    await asyncio.sleep(0.05)
    assert server.current_client is not None

    await server.stop()
    # After stop, the active client should be gone and the socket EOFed.
    assert server.current_client is None
    eof = await asyncio.wait_for(reader.read(100), timeout=1.0)
    # Graceful terminate from server means we may get a type-6 packet before EOF.
    if eof:
        seq, mtype, _ = decode_outer(eof[:4])
        assert mtype == OuterType.CONTROLLER_TERMINATED
