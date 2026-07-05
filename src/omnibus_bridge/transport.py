"""Asyncio TCP server that wires a ServerSession onto a network socket.

Thin adapter between `asyncio.start_server` and the sans-IO `ServerSession`.
The Translator makes exactly one long-lived connection to us on TCP :4369;
we accept at most one client at a time. A new connection arriving while one
is active *replaces* it: after a silent drop the Translator redials from a
new ephemeral port while the old socket can look alive for up to ~8 s
(keepalive window), so the newest connection is always the real one. The
stale socket is aborted (RST) rather than gracefully closed — its peer is
gone by definition.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import Awaitable, Callable

from .session import Event, ServerSession, SessionState

log = logging.getLogger(__name__)

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 4369
READ_CHUNK = 4096

# TCP keepalive timings tuned for fast dead-peer detection. The Translator
# currently drops its session around 15 s; if the drop is silent (no FIN),
# keepalives let us notice within ~8 s (5 s idle + 3 × 1 s probes) instead
# of the OS default of ~2 hours.
_KEEPALIVE_IDLE_S = 5
_KEEPALIVE_INTVL_S = 1
_KEEPALIVE_PROBES = 3

# A connection that hasn't completed the handshake within this window is
# aborted. Keepalive only catches *dead* peers — without this, any TCP
# client that connects and goes idle would hold the single client slot
# forever, locking the real Translator out.
DEFAULT_HANDSHAKE_TIMEOUT_S = 30.0

# Shrink our advertised TCP window to match OmniPro's embedded-stack
# signature. OmniPro advertises win=255, we default to ~65 KB. Tested
# against live Translator: SO_RCVBUF does change our SYN-ACK window,
# but does NOT change the Translator's ~2 s poll cadence or 16 s session
# drop — so the Translator's differential treatment of OmniPro is not
# tied to advertised window size. Kept anyway; harmless and moves us
# closer to OmniPro's fingerprint should the Translator's logic ever
# combine multiple signals. OS floors typically clamp this to a higher
# value (Windows 4 KB, Linux ~2 KB).
_RCVBUF_BYTES = 512


class ConnectedClient:
    """Handle to an active Translator connection.

    Exposed to the event handler so the application can push outbound frames
    without reaching into the transport's internals.
    """

    def __init__(
        self,
        session: ServerSession,
        writer: asyncio.StreamWriter,
        peer: str,
    ) -> None:
        self._session = session
        self._writer = writer
        self._peer = peer
        self._send_lock = asyncio.Lock()

    @property
    def session(self) -> ServerSession:
        return self._session

    @property
    def peer(self) -> str:
        return self._peer

    async def send_inner(
        self,
        msg_type: int,
        data: bytes = b"",
        *,
        use_seq_zero: bool = False,
        reply_seq: int | None = None,
    ) -> None:
        """Queue an inner frame and flush it to the socket."""
        async with self._send_lock:
            self._session.send_inner(
                msg_type, data, use_seq_zero=use_seq_zero, reply_seq=reply_seq
            )
            await self._flush_locked()

    async def _flush_locked(self) -> None:
        """Write any pending session bytes to the socket. Caller holds the lock."""
        out = self._session.bytes_to_send()
        if out:
            self._writer.write(out)
            await self._writer.drain()

    async def flush(self) -> None:
        """Flush any bytes the session has queued (e.g. after a receive)."""
        async with self._send_lock:
            await self._flush_locked()

    async def close(self) -> None:
        """Graceful close: send type 6 + close socket."""
        async with self._send_lock:
            if self._session.state is not SessionState.CLOSED:
                self._session.terminate()
            await self._flush_locked()
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except Exception:  # noqa: BLE001 — socket already torn down
            pass

    def abort(self) -> None:
        """Hard-close the socket immediately (RST), no flush.

        Used to evict a stale/zombie connection: a graceful close would try
        to drain to a peer that is gone, blocking for up to the keepalive
        timeout. Aborting also unblocks the connection's read loop at once.
        """
        transport = self._writer.transport
        if transport is not None:
            transport.abort()


EventHandler = Callable[[Event, ConnectedClient], Awaitable[None]]


class OmniLinkServer:
    """Single-client asyncio server for Omni-Link II controller-side sessions.

    Usage:

        async def on_event(event, client):
            if isinstance(event, InnerFrameReceived):
                ...

        server = OmniLinkServer(private_key, on_event, port=4369)
        await server.start()
        # ... do work ...
        await server.stop()
    """

    def __init__(
        self,
        private_key: bytes,
        handler: EventHandler,
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        allowed_peer: str | None = None,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT_S,
    ) -> None:
        self._private_key = private_key
        self._handler = handler
        self._host = host
        self._port = port
        self._allowed_peer = allowed_peer
        self._handshake_timeout = handshake_timeout
        self._server: asyncio.base_events.Server | None = None
        self._current: ConnectedClient | None = None

    @property
    def current_client(self) -> ConnectedClient | None:
        """The active Translator connection, if any."""
        return self._current

    @property
    def port(self) -> int:
        """The bound port. Useful when host port was 0 (ephemeral)."""
        if self._server is None:
            return self._port
        sockets = self._server.sockets or ()
        if sockets:
            return sockets[0].getsockname()[1]
        return self._port

    async def start(self) -> None:
        """Start listening. Returns once the server is bound."""
        if self._server is not None:
            raise RuntimeError("server already started")
        self._server = await asyncio.start_server(
            self._on_connect, host=self._host, port=self._port
        )
        # Set SO_RCVBUF on the listening socket so the kernel-advertised
        # window on the SYN-ACK matches OmniPro's embedded stack (~255 B).
        # Accepted sockets inherit the buffer size.
        for s in self._server.sockets or ():
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_BYTES)
            except OSError as e:
                log.debug("listen SO_RCVBUF failed: %s", e)
        log.info("omni-link server listening on %s:%d", self._host, self.port)

    async def serve_forever(self) -> None:
        """Start (if needed) and block until cancelled."""
        if self._server is None:
            await self.start()
        assert self._server is not None
        try:
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        """Close the listening socket and the active client, if any."""
        if self._current is not None:
            await self._current.close()
            self._current = None
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    # ---- Per-connection handler -------------------------------------------

    async def _on_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = _peer_name(writer)
        if self._allowed_peer is not None and _peer_host(writer) != self._allowed_peer:
            log.warning(
                "rejecting connection from %s: not the configured Translator (%s)",
                peer,
                self._allowed_peer,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            return

        if self._current is not None:
            # Newest connection wins: after a silent drop the Translator
            # redials from a new port before keepalive declares the old
            # socket dead. Abort the stale one so its read loop exits now.
            log.warning(
                "new connection from %s; evicting stale client %s",
                peer,
                self._current.peer,
            )
            self._current.abort()

        log.info("translator connected: %s", peer)
        _tune_socket(writer)
        session = ServerSession(self._private_key)
        client = ConnectedClient(session, writer, peer)
        self._current = client
        watchdog = asyncio.get_running_loop().create_task(
            self._handshake_watchdog(client)
        )
        try:
            await self._run_read_loop(reader, client)
        except Exception:
            log.exception("unhandled error in session with %s", peer)
        finally:
            watchdog.cancel()
            # Only clear the slot if it's still ours — an evicting new
            # connection may already have replaced us.
            if self._current is client:
                self._current = None
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            log.info("translator disconnected: %s", peer)

    async def _handshake_watchdog(self, client: ConnectedClient) -> None:
        """Abort the connection if the handshake hasn't completed in time."""
        await asyncio.sleep(self._handshake_timeout)
        if client.session.state in (
            SessionState.AWAITING_NEW_SESSION,
            SessionState.AWAITING_SECURE,
        ):
            log.warning(
                "handshake not completed within %.0f s by %s; aborting connection",
                self._handshake_timeout,
                client.peer,
            )
            client.abort()

    async def _run_read_loop(
        self,
        reader: asyncio.StreamReader,
        client: ConnectedClient,
    ) -> None:
        session = client.session
        while True:
            try:
                data = await reader.read(READ_CHUNK)
            except (ConnectionError, TimeoutError):
                # TimeoutError is the kernel's ETIMEDOUT after SO_KEEPALIVE
                # probes fail — a normal "peer went away silently" outcome,
                # not an application bug. Treat like any other disconnect.
                return
            if not data:  # EOF
                return
            session.receive_bytes(data)
            # Push any outbound bytes produced synchronously by the state machine.
            await client.flush()
            # Drain the event queue; invoke the application handler.
            while (event := session.next_event()) is not None:
                try:
                    await self._handler(event, client)
                except Exception:
                    log.exception("handler raised on event %r", event)
            if session.state is SessionState.CLOSED:
                return


def _peer_name(writer: asyncio.StreamWriter) -> str:
    try:
        host, port, *_ = writer.get_extra_info("peername") or ("?", 0)
        return f"{host}:{port}"
    except Exception:  # noqa: BLE001
        return "?"


def _peer_host(writer: asyncio.StreamWriter) -> str:
    try:
        host, *_ = writer.get_extra_info("peername") or ("?",)
        return str(host)
    except Exception:  # noqa: BLE001
        return "?"


def _tune_socket(writer: asyncio.StreamWriter) -> None:
    """Apply TCP_NODELAY + keepalive + small SO_RCVBUF to the accepted socket.

    TCP_NODELAY: disables Nagle so 16-byte push frames hit the wire
    immediately instead of waiting for an ACK or ~200 ms coalescing window.

    SO_KEEPALIVE + short timers: detects dead peers in ~8 s instead of the
    2-hour default. Without this, if the Translator's NIC disappears mid-
    session we'd hold a zombie connection indefinitely and drop pushes.
    Platform-specific APIs for the timers: POSIX uses TCP_KEEPIDLE/INTVL/CNT;
    Windows uses SIO_KEEPALIVE_VALS via ioctl.

    SO_RCVBUF: shrinks our advertised receive window to mimic OmniPro's
    embedded stack. The Translator appears to pace polls by peer window:
    OmniPro's 255-byte window gets 350 ms poll intervals; our default 65 KB
    window gets 2 s intervals and 16 s session drops. Setting a tiny RCVBUF
    reduces the window the kernel advertises. OS typically clamps to a
    higher floor (Windows ~4 KB, Linux 2×SO_RCVBUF with a minimum around
    2 KB) — any reduction is a win.
    """
    sock: socket.socket | None = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError as e:
        log.debug("TCP_NODELAY failed: %s", e)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_BYTES)
        actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        log.info("SO_RCVBUF requested=%d actual=%d", _RCVBUF_BYTES, actual)
    except OSError as e:
        log.debug("SO_RCVBUF failed: %s", e)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError as e:
        log.debug("SO_KEEPALIVE failed: %s", e)
        return
    if hasattr(socket, "TCP_KEEPIDLE"):
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, _KEEPALIVE_IDLE_S)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, _KEEPALIVE_INTVL_S)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, _KEEPALIVE_PROBES)
        except OSError as e:
            log.debug("TCP_KEEP* tuning failed: %s", e)
    elif hasattr(socket, "SIO_KEEPALIVE_VALS"):
        try:
            sock.ioctl(
                socket.SIO_KEEPALIVE_VALS,
                (1, _KEEPALIVE_IDLE_S * 1000, _KEEPALIVE_INTVL_S * 1000),
            )
        except OSError as e:
            log.debug("SIO_KEEPALIVE_VALS failed: %s", e)
