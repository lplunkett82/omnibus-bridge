"""Bridge composition root + entrypoint.

Wires the UnitStateTable, OmniLinkServer, and (eventually) MQTT together.
The `Bridge` class is what tests exercise end-to-end; `main()` is the
CLI shim that reads config, starts the bridge, and blocks.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import load_private_key
from .mqtt import (
    MqttClient,
    MqttConfig,
    brightness_state_topic,
    build_discovery_payloads,
    build_object_id,
    level_topic,
    set_topic,
    state_topic,
)
from .protocol import (
    ControllerCommand,
    InnerType,
    ReqObjectStatus,
    UnitStatusRecord,
    encode_ext_object_status_push,
    encode_object_status_units,
)
from .scanner import DIMMER, FAN, LOCK, Device, RELAY, TRANSLATOR, WALLSWITCH_BUTTON
from .session import (
    Event,
    HandshakeComplete,
    HandshakeFailed,
    InnerFrameReceived,
    PeerTerminated,
)
from .state import UnitStateTable
from .transport import ConnectedClient, OmniLinkServer

log = logging.getLogger(__name__)

# PC Access `PrincessSt_April_2026.pca` shows 36 configured units on the
# Omni-Bus. The Translator's poll loop always asks for indices 1..36.
DEFAULT_UNIT_COUNT = 36

# Gap between consecutive cmd=9 UNIT_LEVEL_PCT events that marks the end
# of a long-press dim stream. Observed ~250 ms between stream updates, so
# anything >= 1 s is a fresh press.
_DIM_STREAM_GAP_S = 1.0

# Pushes queued while the Translator is offline are dropped if they're older
# than this when the next session comes up. Flushing an arbitrarily old
# command on reconnect would actuate a relay long after the user's intent
# (and after physical wall-switch changes we never saw) — a phantom-on by
# our own hand.
PENDING_PUSH_TTL_S = 60.0


@dataclass
class _ButtonDimState:
    """Per-button state for alternating long-press dim direction.

    The Translator always sends a decreasing UNIT_LEVEL_PCT stream during
    long-press (100 → low). Rocker-dimmer UX expects direction to flip
    between successive holds (hold 1 = down, hold 2 = up, hold 3 = down, …).
    We apply the Translator's delta to a virtual level, flipping sign on
    each new stream, and publish *that* to the level sensor. HA automations
    built on the level sensor then see natural rocker behavior.
    """

    direction: str = "up"           # flips to "down" on the first new stream
    virtual_level: int = 100        # current published value (0..100 %)
    last_trans_pct: int | None = None
    last_event_time: float | None = None



class Bridge:
    """The composition root.

    Owns the state table, wires its change callback to push outbound
    0x3B frames to the Translator, and — optionally — publishes state and
    press events to MQTT for Home Assistant.
    """

    def __init__(
        self,
        private_key: bytes,
        *,
        unit_count: int = DEFAULT_UNIT_COUNT,
        host: str = "0.0.0.0",
        port: int = 4369,
        devices: list[Device] | None = None,
        mqtt: MqttClient | None = None,
        state_file: Path | None = None,
        allowed_peer: str | None = None,
    ) -> None:
        self.state = UnitStateTable(unit_count)
        self._state_file = state_file
        if state_file is not None:
            n = self.state.load(state_file)
            if n:
                log.info("restored %d unit states from %s", n, state_file)
            # Save on every change so a bridge restart preserves current
            # physical-device state (otherwise the Translator syncs all
            # lights OFF from our fresh table on session startup).
            self.state.on_change(self._on_state_persist)
        self.server = OmniLinkServer(
            private_key, self._on_event, host=host, port=port,
            allowed_peer=allowed_peer,
        )
        self._mqtt = mqtt
        self._devices_by_unit: dict[int, Device] = {
            d.unit_number: d for d in (devices or []) if d.unit_number > 0
        }
        self._translator_device: Device | None = next(
            (d for d in (devices or []) if d.device_type == TRANSLATOR), None
        )
        # Pushes that couldn't be sent because the Translator was offline mid-
        # reconnect. Keyed by unit — last-write-wins, which is what we want
        # (no point sending stale intermediate states). Values are
        # (status, queued_at_monotonic); entries older than PENDING_PUSH_TTL_S
        # are discarded at flush time instead of actuating stale intent.
        self._pending_pushes: dict[int, tuple[int, float]] = {}
        # Per-wall-button direction-alternation state for the level sensor.
        self._button_dim: dict[int, _ButtonDimState] = {}
        if mqtt is not None:
            self.state.on_change(self._on_state_change)

    def _on_state_persist(self, _unit: int, _old: int, _new: int) -> None:
        if self._state_file is None:
            return
        try:
            self.state.save(self._state_file)
        except OSError as e:
            log.warning("state save to %s failed: %s", self._state_file, e)

    # ---- Lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        await self.server.start()
        if self._mqtt is not None:
            await self._mqtt.start()
            self._publish_discovery()
            self._subscribe_commands()
            self._publish_initial_state()

    async def stop(self) -> None:
        await self.server.stop()
        if self._mqtt is not None:
            await self._mqtt.stop()

    async def serve_forever(self) -> None:
        await self.server.serve_forever()

    # ---- Public API used by MQTT / HA glue --------------------------------

    async def set_unit(self, unit: int, status: int) -> None:
        """Apply an HA-originated state change. Updates state + pushes to Translator.

        This is the one supported write path from the MQTT / application side.
        Physical events arriving as CONTROLLER_COMMAND update state without
        calling this method, so there's no echo back to the Translator for
        changes it already knows about.
        """
        self.state.set_status(unit, status)
        await self._push_unit(unit, status)

    async def handle_mqtt_command(self, unit: int, kind: str, payload: str) -> None:
        """Inbound MQTT dispatch from MqttClient callbacks.

        `kind` is "set" (ON/OFF) or "brightness" (0..100). For relay units a
        brightness command is ignored. For dimmer units both kinds are honored.
        """
        dev = self._devices_by_unit.get(unit)
        if dev is None:
            log.warning("MQTT command for unknown unit %d (payload=%r)", unit, payload)
            return

        if kind == "set":
            # Lock entities send LOCK/UNLOCK instead of ON/OFF.
            if dev.device_type == LOCK:
                new_status = _parse_lock_command(payload)
                if new_status is None:
                    log.warning("MQTT unit %d lock: unparseable payload %r", unit, payload)
                    return
                await self.set_unit(unit, new_status)
                return
            new_status = _parse_on_off(payload)
            if new_status is None:
                log.warning("MQTT unit %d set: unparseable payload %r", unit, payload)
                return
            # Wall-switch buttons are physical inputs — HA commands update the
            # virtual state only, never push to the Translator. (Users toggling
            # the HA tile just flip a local indicator.)
            if dev.device_type == WALLSWITCH_BUTTON:
                self.state.set_status(unit, new_status)
                return
            # For a dimmer, ON without a brightness command implies "last level
            # or 100 %" per HA conventions. We use 100 % (status=200) on plain ON.
            if dev.device_type == DIMMER and new_status == 1:
                new_status = 200
            await self.set_unit(unit, new_status)
            return

        if kind == "brightness":
            if dev.device_type != DIMMER:
                log.debug("MQTT brightness for non-dimmer unit %d, ignoring", unit)
                return
            try:
                level = max(0, min(100, int(payload)))
            except ValueError:
                log.warning("MQTT unit %d brightness: non-integer payload %r", unit, payload)
                return
            status = 0 if level == 0 else 100 + level  # ALC-style dimmer encoding
            await self.set_unit(unit, status)
            return

        log.debug("MQTT unit %d unknown kind %r", unit, kind)

    # ---- Event handler ----------------------------------------------------

    async def _on_event(self, event: Event, client: ConnectedClient) -> None:
        if isinstance(event, InnerFrameReceived):
            await self._handle_inner(event, client)
        elif isinstance(event, HandshakeComplete):
            log.info(
                "handshake complete with %s (session_id=%s)",
                client.peer,
                event.session_id.hex().upper(),
            )
            # Flush any pushes queued during the reconnect gap — the
            # Translator is ready to receive them immediately post-handshake
            # (matches Phase 3 live-test behavior that actuated lights).
            await self._flush_pending_pushes(client)
        elif isinstance(event, HandshakeFailed):
            log.warning("handshake failed with %s: %s", client.peer, event.reason)
        elif isinstance(event, PeerTerminated):
            log.info("%s terminated the session", client.peer)

    async def _handle_inner(
        self, event: InnerFrameReceived, client: ConnectedClient
    ) -> None:
        msg_type = event.msg_type
        data = event.data

        try:
            _name = InnerType(msg_type).name
        except ValueError:
            _name = f"0x{msg_type:02X}"
        log.debug(
            "← inner %s (outer_seq=%d, %dB data)", _name, event.outer_seq, len(data)
        )

        # All responses below MUST echo the inbound packet's seq. OmniPro
        # does this on every reply (verified in live captures); when we
        # used our own counter the Translator treated replies as drops
        # and fell into slow-poll + short-session mode.
        reply_seq = event.outer_seq

        if msg_type == InnerType.REQ_OBJECT_STATUS:
            req = ReqObjectStatus.decode(data)
            if req.obj_type != 0x02:
                log.debug(
                    "REQ_OBJECT_STATUS for obj_type=%d (not Unit) — replying empty",
                    req.obj_type,
                )
                await client.send_inner(
                    InnerType.OBJECT_STATUS, bytes([req.obj_type]), reply_seq=reply_seq
                )
                return
            records = [
                UnitStatusRecord(
                    unit=snap.unit, status=snap.status, time_remaining=snap.time_remaining
                )
                for snap in self.state.snapshot_range(req.start_index, req.end_index)
            ]
            await client.send_inner(
                InnerType.OBJECT_STATUS,
                encode_object_status_units(records),
                reply_seq=reply_seq,
            )
            return

        if msg_type == InnerType.REQ_EXT_OBJECT_STATUS:
            # Same parameter shape as 0x22. Reply with one 9-byte EXT record
            # per requested unit. Observed 3x at handshake-time only, so this
            # path is not hot.
            req = ReqObjectStatus.decode(data)
            payload = b""
            for snap in self.state.snapshot_range(req.start_index, req.end_index):
                payload += encode_ext_object_status_push(snap.unit, snap.status)
            await client.send_inner(
                InnerType.EXT_OBJECT_STATUS, payload, reply_seq=reply_seq
            )
            return

        if msg_type == InnerType.ENABLE_NOTIFICATIONS:
            await client.send_inner(InnerType.ACK, reply_seq=reply_seq)
            # Also flush here in case pushes were enqueued between handshake
            # and this moment (not strictly required, but cheap belt-and-
            # -suspenders for session start-up races).
            await self._flush_pending_pushes(client)
            return

        if msg_type == InnerType.CONTROLLER_COMMAND:
            cmd = ControllerCommand.decode(data)
            log.info(
                "physical event: CONTROLLER_COMMAND cmd=%d p1=%d p2=%d (unit=%d)",
                cmd.cmd, cmd.p1, cmd.p2, cmd.p2,
            )
            # OmniPro ACKs every CONTROLLER_COMMAND with echoed seq before
            # updating its own state — we must match that so the Translator
            # sees the command as acknowledged.
            await client.send_inner(InnerType.ACK, reply_seq=reply_seq)
            # Translator forwards physical events up to us:
            #   cmd=0 UNIT_OFF        — short press OFF / hard off
            #   cmd=1 UNIT_ON         — short press ON / hard on
            #   cmd=9 UNIT_LEVEL_PCT  — stream during long-press dim at
            #                            ~4 Hz. p1 = brightness 0..100.
            #                            Both the button unit and its
            #                            linked dimmer fire in parallel;
            #                            updating state for both makes the
            #                            dimmer's HA brightness tile track
            #                            the wall-switch hold in real time.
            # p2 = unit number.
            if cmd.cmd == 0:
                new_status = 0
            elif cmd.cmd == 1:
                new_status = 1
            elif cmd.cmd == 9:
                pct = max(0, min(100, cmd.p1))
                # ALC-style encoding: 0 = off; 101..200 = 1%..100%.
                new_status = 0 if pct == 0 else 100 + pct
            else:
                log.debug(
                    "CONTROLLER_COMMAND with cmd=%d p1=%d p2=%d — ignoring (unhandled)",
                    cmd.cmd, cmd.p1, cmd.p2,
                )
                return
            unit = cmd.p2
            if 1 <= unit <= self.state.count:
                # Physical event — update state without pushing back. The
                # Translator is the source of truth for this change.
                self.state.set_status(unit, new_status)
            return

        log.debug("unhandled inner frame type 0x%02X data=%s", msg_type, data.hex())

    # ---- Outbound push ----------------------------------------------------

    async def _push_unit(self, unit: int, status: int) -> None:
        client = self.server.current_client
        if client is None:
            self._pending_pushes[unit] = (status, time.monotonic())
            log.info("queued push unit=%d status=%d (Translator offline)", unit, status)
            return
        await self._send_push(client, unit, status)

    async def _send_push(self, client: ConnectedClient, unit: int, status: int) -> None:
        try:
            await client.send_inner(
                InnerType.EXT_OBJECT_STATUS,
                encode_ext_object_status_push(unit, status),
                use_seq_zero=True,
            )
            log.info("pushed unit=%d status=%d to Translator", unit, status)
        except (RuntimeError, OSError) as e:
            # RuntimeError: session transitioned between check and send
            # (reconnect race). OSError/ConnectionError: socket died mid-
            # write. Either way, re-queue and let the next HandshakeComplete
            # flush it (subject to the TTL).
            self._pending_pushes[unit] = (status, time.monotonic())
            log.info("push failed; requeued unit=%d status=%d (%s)", unit, status, e)
        except Exception:  # noqa: BLE001
            log.exception("failed to push unit %d status=%d", unit, status)

    async def _flush_pending_pushes(self, client: ConnectedClient) -> None:
        """Send pushes queued while the Translator was offline; drop stale ones.

        A push older than PENDING_PUSH_TTL_S no longer reflects anyone's
        current intent — actuating it after a long outage is a phantom
        activation, so it's discarded loudly instead.
        """
        if not self._pending_pushes:
            return
        pending = dict(self._pending_pushes)
        self._pending_pushes.clear()
        now = time.monotonic()
        fresh = {u: s for u, (s, t) in pending.items() if now - t <= PENDING_PUSH_TTL_S}
        stale = {u: s for u, (s, t) in pending.items() if u not in fresh}
        if stale:
            log.warning(
                "discarding %d stale queued push(es) older than %.0f s: %s",
                len(stale), PENDING_PUSH_TTL_S,
                ", ".join(f"unit={u} status={s}" for u, s in stale.items()),
            )
        if fresh:
            log.info("flushing %d queued push(es) after handshake", len(fresh))
        for unit, status in fresh.items():
            await self._send_push(client, unit, status)

    # ---- MQTT glue --------------------------------------------------------

    def _publish_discovery(self) -> None:
        """Publish HA auto-discovery configs for every known device.

        Also clears legacy `event` discovery topics for wall-switch buttons —
        those entities were replaced with `switch` entities. Publishing an
        empty retained payload tells HA to forget the old entity.
        """
        assert self._mqtt is not None
        # Migration: retire legacy `event` entities for wall-switch buttons
        # (they now publish as `switch` entities). Publishing an empty
        # retained payload on the old config topic tells HA to forget the
        # entity cleanly. The object_id is computed with build_object_id
        # to match exactly what the old build_discovery_payloads emitted.
        cfg = self._mqtt.cfg
        for d in self._devices_by_unit.values():
            if d.device_type != WALLSWITCH_BUTTON:
                continue
            name = d.name or f"Button {d.unit_number}"
            old_obj_id = build_object_id("button", d.unit_number, name)
            old_topic = f"{cfg.discovery_prefix}/event/{cfg.node_id}/{old_obj_id}/config"
            self._mqtt.publish(old_topic, "", retain=True)
        # Migration: retire stale `light` discovery for units that changed
        # domain to `fan` or `lock`. Without this, HA sees both the old
        # light and the new fan/lock for the same unique_id and ignores the
        # new one.
        for d in self._devices_by_unit.values():
            if d.device_type in (FAN, LOCK):
                obj_id = build_object_id("unit", d.unit_number, d.name)
                old_topic = f"{cfg.discovery_prefix}/light/{cfg.node_id}/{obj_id}/config"
                self._mqtt.publish(old_topic, "", retain=True)
        payloads = build_discovery_payloads(
            cfg,
            list(self._devices_by_unit.values()),
            translator=self._translator_device,
        )
        for topic, payload in payloads:
            self._mqtt.publish_json(topic, payload, retain=True)
        log.info("published %d HA discovery configs", len(payloads))

    def _subscribe_commands(self) -> None:
        """Subscribe to every addressable unit's set topic (and brightness set
        topic for dimmers). Wall-switch buttons subscribe too so the HA-side
        switch tile can toggle state virtually (no Translator push — they're
        physical inputs)."""
        assert self._mqtt is not None
        for d in self._devices_by_unit.values():
            if d.device_type in (RELAY, DIMMER, FAN, LOCK, WALLSWITCH_BUTTON):
                self._mqtt.subscribe(set_topic(self._mqtt.cfg, d.unit_number))
            if d.device_type == DIMMER:
                self._mqtt.subscribe(
                    f"{self._mqtt.cfg.base_topic}/unit/{d.unit_number}/brightness/set"
                )

    def _publish_initial_state(self) -> None:
        """Publish current state table to MQTT so HA sees whatever we know at
        boot. Applies to lights and wall-switches alike (buttons default to
        OFF until we see the first press)."""
        assert self._mqtt is not None
        for d in self._devices_by_unit.values():
            if d.device_type in (RELAY, DIMMER):
                snap = self.state.get(d.unit_number) if 1 <= d.unit_number <= self.state.count else None
                status = snap.status if snap is not None else 0
                self._publish_light_state(d, status)
            elif d.device_type == FAN:
                snap = self.state.get(d.unit_number) if 1 <= d.unit_number <= self.state.count else None
                status = snap.status if snap is not None else 0
                self._publish_fan_state(d, status)
            elif d.device_type == LOCK:
                snap = self.state.get(d.unit_number) if 1 <= d.unit_number <= self.state.count else None
                status = snap.status if snap is not None else 0
                self._publish_lock_state(d, status)
            elif d.device_type == WALLSWITCH_BUTTON:
                self._publish_button_state(d, 0)

    def _on_state_change(self, unit: int, _old: int, new: int) -> None:
        """Fires on every state table change — physical events AND HA-originated
        writes flow through here. Dispatches to the right MQTT topic by device type."""
        assert self._mqtt is not None
        dev = self._devices_by_unit.get(unit)
        if dev is None:
            return
        if dev.device_type in (RELAY, DIMMER):
            self._publish_light_state(dev, new)
        elif dev.device_type == FAN:
            self._publish_fan_state(dev, new)
        elif dev.device_type == LOCK:
            self._publish_lock_state(dev, new)
        elif dev.device_type == WALLSWITCH_BUTTON:
            self._publish_button_state(dev, new)

    def _publish_button_state(self, dev: Device, status: int) -> None:
        """Publish wall-switch button state: ON/OFF for the switch entity
        plus 0..100 % for the companion level sensor. Long-press dimming
        (UNIT_LEVEL_PCT stream) streams to the level topic at ~4 Hz; each
        new hold flips direction (down/up/down/…) so HA automations see
        natural rocker-dimmer behavior."""
        assert self._mqtt is not None
        self._mqtt.publish(
            state_topic(self._mqtt.cfg, dev.unit_number),
            "ON" if status != 0 else "OFF",
            retain=True,
        )
        level = self._compute_button_level(dev.unit_number, status)
        self._mqtt.publish(
            level_topic(self._mqtt.cfg, dev.unit_number),
            str(level),
            retain=True,
        )

    def _compute_button_level(self, unit: int, status: int) -> int:
        """Translate raw button status into an alternating-direction level.

        - status 0 (UNIT_OFF / idle)  → level 0, resets dim state to 0.
        - status 1 (short-press ON)   → level 100, resets dim state to 100.
        - status 101..200 (dim pct)   → within a stream: apply the
            Translator's delta to the virtual level, with sign flipped on
            each new stream (first new-stream flip takes direction to DOWN,
            the next to UP, etc). The Translator always sends a decreasing
            stream; with alternation the published level alternates
            direction between holds."""
        if status == 0:
            ds = self._button_dim.get(unit)
            if ds is not None:
                ds.virtual_level = 0
                ds.last_trans_pct = None
                ds.last_event_time = None
            return 0
        if status == 1:
            ds = self._button_dim.get(unit)
            if ds is not None:
                ds.virtual_level = 100
                ds.last_trans_pct = None
                ds.last_event_time = None
            return 100
        if not (100 <= status <= 200):
            return 100  # unknown encoding — treat as fully on

        trans_pct = status - 100  # 0..100
        now = time.monotonic()
        ds = self._button_dim.setdefault(unit, _ButtonDimState())
        is_new_stream = (
            ds.last_event_time is None
            or (now - ds.last_event_time) > _DIM_STREAM_GAP_S
        )
        if is_new_stream:
            # Flip direction for the upcoming hold.
            ds.direction = "down" if ds.direction == "up" else "up"
            # First event establishes the baseline; level stays where we
            # left it last hold (so up-hold continues from where down-hold
            # ended).
            ds.last_trans_pct = trans_pct
        else:
            assert ds.last_trans_pct is not None
            trans_delta = trans_pct - ds.last_trans_pct
            # Translator sends decreasing values (trans_delta ≤ 0).
            # direction="down" → virtual_level follows (decreases).
            # direction="up"   → virtual_level inverted (increases).
            output_delta = trans_delta if ds.direction == "down" else -trans_delta
            ds.virtual_level = max(0, min(100, ds.virtual_level + output_delta))
            ds.last_trans_pct = trans_pct
        ds.last_event_time = now
        return ds.virtual_level

    def _publish_light_state(self, dev: Device, status: int) -> None:
        assert self._mqtt is not None
        is_on = status != 0
        self._mqtt.publish(
            state_topic(self._mqtt.cfg, dev.unit_number),
            "ON" if is_on else "OFF",
            retain=True,
        )
        if dev.device_type == DIMMER:
            # ALC-style: status 100..200 = level 0..100 %. 1 (plain ON) → 100 %.
            if status == 0:
                level = 0
            elif 100 <= status <= 200:
                level = status - 100
            else:
                level = 100
            self._mqtt.publish(
                brightness_state_topic(self._mqtt.cfg, dev.unit_number),
                str(level),
                retain=True,
            )


    def _publish_fan_state(self, dev: Device, status: int) -> None:
        assert self._mqtt is not None
        self._mqtt.publish(
            state_topic(self._mqtt.cfg, dev.unit_number),
            "ON" if status != 0 else "OFF",
            retain=True,
        )

    def _publish_lock_state(self, dev: Device, status: int) -> None:
        """Publish lock state. ON (relay energized) = UNLOCKED, OFF = LOCKED."""
        assert self._mqtt is not None
        self._mqtt.publish(
            state_topic(self._mqtt.cfg, dev.unit_number),
            "UNLOCKED" if status != 0 else "LOCKED",
            retain=True,
        )


def _parse_on_off(payload: str) -> int | None:
    s = payload.strip().upper()
    if s in ("ON", "1", "TRUE"):
        return 1
    if s in ("OFF", "0", "FALSE"):
        return 0
    return None


def _parse_lock_command(payload: str) -> int | None:
    """Parse an HA MQTT lock command. UNLOCK → ON (1), LOCK → OFF (0)."""
    s = payload.strip().upper()
    if s == "UNLOCK":
        return 1
    if s == "LOCK":
        return 0
    return None


def _load_devices_yaml(path: Path) -> list[Device]:
    """Load a device list from the YAML file tools/scan.py writes.

    We only need flat scalars under a `translator:` block and a `devices:`
    list of dicts; yaml.safe_load handles both.
    """
    import yaml  # deferred import; pyyaml is already in the deps
    data = yaml.safe_load(path.read_text()) or {}
    out: list[Device] = []
    t = data.get("translator") or {}
    if t:
        out.append(Device(
            unit_number=0,
            name="Translator",
            device_type=TRANSLATOR,
            raw_frame=b"",
            device_id=t.get("device_id"),
            ip=t.get("ip"),
            netmask=t.get("netmask"),
            gateway=t.get("gateway"),
            port=t.get("port"),
        ))
    for entry in data.get("devices", []) or []:
        out.append(Device(
            unit_number=int(entry["unit"]),
            name=str(entry.get("name", "")),
            device_type=str(entry["type"]),
            raw_frame=b"",
        ))
    return out


async def _run(args: argparse.Namespace) -> int:
    private_key = load_private_key(Path(args.env))

    devices: list[Device] = []
    if args.devices_yaml:
        devices = _load_devices_yaml(Path(args.devices_yaml))
        log.info("loaded %d devices from %s", len(devices), args.devices_yaml)
    elif args.scan:
        from .scanner import scan  # local import; scan only needed at startup
        log.info("scanning Translator at %s:%d for devices", args.translator, args.scan_port)
        devices = await scan(args.translator, port=args.scan_port)
        log.info("scanner found %d devices", len(devices))

    mqtt_client: MqttClient | None = None
    if args.mqtt_host:
        cfg = MqttConfig(
            host=args.mqtt_host,
            port=args.mqtt_port,
            username=args.mqtt_user,
            password=args.mqtt_password,
            client_id=args.mqtt_client_id,
            base_topic=args.mqtt_base_topic,
            discovery_prefix=args.mqtt_discovery_prefix,
        )
        # Forward declare so MqttClient can call into the bridge; patched below.
        _pending: list[Bridge] = []

        async def _dispatch(unit: int, kind: str, payload: str) -> None:
            if _pending:
                await _pending[0].handle_mqtt_command(unit, kind, payload)

        mqtt_client = MqttClient(cfg, on_command=_dispatch)

    bridge = Bridge(
        private_key,
        host=args.host,
        port=args.port,
        unit_count=args.units,
        devices=devices,
        mqtt=mqtt_client,
        state_file=Path(args.state_file) if args.state_file else None,
        allowed_peer=args.allow_peer,
    )
    if mqtt_client is not None:
        _pending.append(bridge)  # type: ignore[has-type]

    loop = asyncio.get_running_loop()
    stop = loop.create_future()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: stop.cancel() if stop.done() else stop.set_result(None))
        except NotImplementedError:
            # Windows: add_signal_handler unsupported. Fall back to KeyboardInterrupt.
            pass

    await bridge.start()
    log.info("bridge listening on %s:%d (units=%d, devices=%d, mqtt=%s)",
             args.host, bridge.server.port, args.units, len(devices),
             "yes" if mqtt_client else "no")
    log.info("press Ctrl-C to stop")
    try:
        await stop
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        log.info("shutting down")
        await bridge.stop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="omnibus-bridge",
        description="Omni-Link II controller bridging a Leviton 117A00-1 Translator to MQTT.",
    )
    parser.add_argument("--env", default=".env", help="path to .env with OMNILINK_KEY1/2")
    parser.add_argument("--host", default="0.0.0.0", help="bind host (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=4369, help="bind port (default 4369)")
    parser.add_argument("--allow-peer", default=None,
                        help="Only accept Omni-Link connections from this IP "
                             "(the Translator). Default: accept any peer.")
    parser.add_argument("--units", type=int, default=DEFAULT_UNIT_COUNT,
                        help=f"number of Units to expose (default {DEFAULT_UNIT_COUNT})")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--state-file", default=None,
                        help="Path to a JSON file the bridge reads/writes to "
                             "persist unit state across restarts. Without this, "
                             "the Translator will sync physical devices to our "
                             "fresh (all-OFF) table on session startup, turning "
                             "every light off. Recommended: `config/state.json`.")

    # Device source (one of)
    parser.add_argument("--devices-yaml", default=None,
                        help="Load device list from YAML (output of tools/scan.py). "
                             "Preferred for long-running deployments.")
    parser.add_argument("--scan", action="store_true",
                        help="Run the 43690 scanner at startup. Requires the "
                             "Translator to not be dialing the bridge already.")
    parser.add_argument("--translator", default="192.0.2.10",
                        help="Translator IP for the scanner (default 192.0.2.10)")
    parser.add_argument("--scan-port", type=int, default=43690)

    # MQTT
    parser.add_argument("--mqtt-host", default=None,
                        help="MQTT broker hostname. If unset, MQTT is disabled.")
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--mqtt-user", default=None)
    parser.add_argument("--mqtt-password", default=None)
    parser.add_argument("--mqtt-client-id", default="omnibus-bridge")
    parser.add_argument("--mqtt-base-topic", default="omnibus")
    parser.add_argument("--mqtt-discovery-prefix", default="homeassistant")

    args = parser.parse_args()
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        return 0
