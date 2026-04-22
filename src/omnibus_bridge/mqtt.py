"""MQTT client + Home Assistant auto-discovery.

Thin asyncio-friendly wrapper over `paho-mqtt` v2. Handles three flows:

  * **Discovery** — publishes `homeassistant/<domain>/omnibus_unit_<N>/config`
    at startup so HA auto-creates entities for every scanned device.
  * **State** — publishes `omnibus/unit/<N>/state` (ON/OFF) and, for dimmers,
    `omnibus/unit/<N>/brightness` (0–100) whenever the bridge's state table
    changes.
  * **Commands** — subscribes to `omnibus/unit/<N>/set` (and the dimmer
    brightness equivalent); each inbound message is dispatched to a bridge-
    supplied async callback that translates the request into a 0x3B push.

Paho runs its network loop on a dedicated thread, so every callback marshals
work back onto the asyncio event loop via `call_soon_threadsafe`. Callers
only ever await the asyncio-facing API.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Awaitable, Callable

import paho.mqtt.client as paho

from .scanner import DIMMER, FAN, LOCK, Device, RELAY, TRANSLATOR, WALLSWITCH_BUTTON

log = logging.getLogger(__name__)


# -- Configuration ----------------------------------------------------------


@dataclass(frozen=True)
class MqttConfig:
    host: str
    port: int = 1883
    username: str | None = None
    password: str | None = None
    client_id: str = "omnibus-bridge"
    base_topic: str = "omnibus"
    discovery_prefix: str = "homeassistant"
    node_id: str = "omnibus_bridge"  # disambiguates per-bridge HA unique_ids


# -- Topic helpers ----------------------------------------------------------


def state_topic(cfg: MqttConfig, unit: int) -> str:
    return f"{cfg.base_topic}/unit/{unit}/state"


def set_topic(cfg: MqttConfig, unit: int) -> str:
    return f"{cfg.base_topic}/unit/{unit}/set"


def brightness_state_topic(cfg: MqttConfig, unit: int) -> str:
    return f"{cfg.base_topic}/unit/{unit}/brightness"


def brightness_set_topic(cfg: MqttConfig, unit: int) -> str:
    return f"{cfg.base_topic}/unit/{unit}/brightness/set"


def level_topic(cfg: MqttConfig, unit: int) -> str:
    """Per-unit brightness-level topic (0..100).

    Published for wall-switch buttons during long-press dimming so HA
    automations can mirror the level to non-Omnibus lights.
    """
    return f"{cfg.base_topic}/unit/{unit}/level"


def availability_topic(cfg: MqttConfig) -> str:
    return f"{cfg.base_topic}/bridge/availability"


def discovery_topic(cfg: MqttConfig, domain: str, object_id: str) -> str:
    return f"{cfg.discovery_prefix}/{domain}/{cfg.node_id}/{object_id}/config"


# -- HA discovery payload builder -------------------------------------------


_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_]+")


def build_object_id(prefix: str, unit: int, device_name: str) -> str:
    """Public alias for _object_id — used by the legacy-discovery cleanup
    path to compute the exact object_id HA saw under the old scheme."""
    return _object_id(prefix, unit, device_name)


def _object_id(prefix: str, unit: int, device_name: str) -> str:
    """Stable object_id for HA unique_id and topic. Includes the name so it's
    human-readable in the HA dev UI, but slug-safe."""
    safe = _SAFE_NAME_RE.sub("_", device_name).strip("_").lower() or "unit"
    return f"{prefix}_{unit:03d}_{safe}"


def _device_info(translator: Device | None) -> dict:
    """HA `device` block — all entities share one Device so they group in HA."""
    info: dict = {
        "identifiers": ["omnibus_bridge"],
        "name": "Omni-Bus Bridge",
        "manufacturer": "Leviton (via omnibus-bridge)",
        "model": "117A00-1 Interface Translator",
    }
    if translator is not None:
        if translator.device_id:
            info["identifiers"].append(f"translator_{translator.device_id}")
        if translator.ip:
            info["configuration_url"] = f"http://{translator.ip}/"
    return info


def build_discovery_payloads(
    cfg: MqttConfig,
    devices: list[Device],
    translator: Device | None = None,
) -> list[tuple[str, dict]]:
    """Return a list of (topic, payload_dict) for every discoverable device.

    Relays + dimmers → `light` entities.
    Wall-switch buttons → `switch` entities (read-only; reflects physical
    press as ON/OFF state). Previously published as `event`; switched to
    the switch domain so they appear as toggles in HA and integrate
    cleanly into state-based automations.
    Translator → skipped in the MVP (future: diagnostic sensors).
    """
    avail = availability_topic(cfg)
    dev_info = _device_info(translator)
    out: list[tuple[str, dict]] = []

    for d in devices:
        if d.device_type == RELAY:
            obj_id = _object_id("unit", d.unit_number, d.name)
            topic = discovery_topic(cfg, "light", obj_id)
            payload = {
                "unique_id": obj_id,
                "name": d.name,
                "object_id": obj_id,
                "state_topic": state_topic(cfg, d.unit_number),
                "command_topic": set_topic(cfg, d.unit_number),
                "payload_on": "ON",
                "payload_off": "OFF",
                "availability_topic": avail,
                "payload_available": "online",
                "payload_not_available": "offline",
                "device": dev_info,
            }
            out.append((topic, payload))

        elif d.device_type == DIMMER:
            name = d.name or f"Dimmer {d.unit_number}"
            obj_id = _object_id("unit", d.unit_number, name)
            topic = discovery_topic(cfg, "light", obj_id)
            payload = {
                "unique_id": obj_id,
                "name": name,
                "object_id": obj_id,
                "state_topic": state_topic(cfg, d.unit_number),
                "command_topic": set_topic(cfg, d.unit_number),
                "brightness_state_topic": brightness_state_topic(cfg, d.unit_number),
                "brightness_command_topic": brightness_set_topic(cfg, d.unit_number),
                "brightness_scale": 100,
                "on_command_type": "brightness",
                "payload_on": "ON",
                "payload_off": "OFF",
                "availability_topic": avail,
                "payload_available": "online",
                "payload_not_available": "offline",
                "device": dev_info,
            }
            out.append((topic, payload))

        elif d.device_type == WALLSWITCH_BUTTON:
            name = d.name or f"Button {d.unit_number}"
            # Disambiguate duplicate names like 6x "Kitchen door" by unit.
            display_name = f"{name} (#{d.unit_number})"

            # Switch entity — ON/OFF press state.
            obj_id = _object_id("button", d.unit_number, name)
            topic = discovery_topic(cfg, "switch", obj_id)
            payload = {
                "unique_id": obj_id,
                "name": display_name,
                "object_id": obj_id,
                "state_topic": state_topic(cfg, d.unit_number),
                # HA MQTT switch requires command_topic. We subscribe + handle
                # it on the bridge side: a command updates the virtual state
                # table and republishes, but does NOT push to the Translator
                # (the button is an input device — it has no output side).
                "command_topic": set_topic(cfg, d.unit_number),
                "payload_on": "ON",
                "payload_off": "OFF",
                "optimistic": False,
                "availability_topic": avail,
                "payload_available": "online",
                "payload_not_available": "offline",
                "device": dev_info,
            }
            out.append((topic, payload))

            # Companion numeric sensor — exposes the dim level during
            # long-press UP/DOWN so HA automations can mirror it to any
            # non-Omnibus light. 0..100 %; 0 = idle, 100 = short-press ON.
            sensor_obj_id = _object_id("button_level", d.unit_number, name)
            sensor_topic = discovery_topic(cfg, "sensor", sensor_obj_id)
            sensor_payload = {
                "unique_id": sensor_obj_id,
                "name": f"{display_name} level",
                "object_id": sensor_obj_id,
                "state_topic": level_topic(cfg, d.unit_number),
                "unit_of_measurement": "%",
                "state_class": "measurement",
                "availability_topic": avail,
                "payload_available": "online",
                "payload_not_available": "offline",
                "device": dev_info,
            }
            out.append((sensor_topic, sensor_payload))

        elif d.device_type == FAN:
            obj_id = _object_id("unit", d.unit_number, d.name)
            topic = discovery_topic(cfg, "fan", obj_id)
            payload = {
                "unique_id": obj_id,
                "name": d.name,
                "object_id": obj_id,
                "state_topic": state_topic(cfg, d.unit_number),
                "command_topic": set_topic(cfg, d.unit_number),
                "payload_on": "ON",
                "payload_off": "OFF",
                "availability_topic": avail,
                "payload_available": "online",
                "payload_not_available": "offline",
                "device": dev_info,
            }
            out.append((topic, payload))

        elif d.device_type == LOCK:
            obj_id = _object_id("unit", d.unit_number, d.name)
            topic = discovery_topic(cfg, "lock", obj_id)
            payload = {
                "unique_id": obj_id,
                "name": d.name,
                "object_id": obj_id,
                "state_topic": state_topic(cfg, d.unit_number),
                "command_topic": set_topic(cfg, d.unit_number),
                "payload_lock": "LOCK",
                "payload_unlock": "UNLOCK",
                "state_locked": "LOCKED",
                "state_unlocked": "UNLOCKED",
                "availability_topic": avail,
                "payload_available": "online",
                "payload_not_available": "offline",
                "device": dev_info,
            }
            out.append((topic, payload))

        elif d.device_type == TRANSLATOR:
            # MVP: Translator itself isn't discovered as an entity (it's the
            # "device" metadata every other entity references). Diagnostic
            # sensors for IP / port / firmware are future work.
            continue

        else:
            log.warning("unknown device_type %r for unit %d, skipping",
                        d.device_type, d.unit_number)

    return out


# -- Asyncio wrapper over paho-mqtt -----------------------------------------


CommandHandler = Callable[[int, str, str], Awaitable[None]]
"""async (unit_number, command_kind, payload) -> None

`command_kind` is one of {"set", "brightness"}. `payload` is the raw string
from the MQTT message (e.g. "ON", "50"). The handler decides how to translate
it into a bridge action.
"""


class MqttClient:
    """Asyncio-friendly MQTT client wrapping paho-mqtt's threaded loop.

    Usage:
        client = MqttClient(cfg, on_command=bridge.handle_command)
        await client.start()
        ... publish state, etc. ...
        await client.stop()
    """

    def __init__(self, cfg: MqttConfig, on_command: CommandHandler) -> None:
        self.cfg = cfg
        self._on_command = on_command
        self._loop: asyncio.AbstractEventLoop | None = None
        self._connected_event = asyncio.Event()
        # With clean_session=True the broker drops our subscriptions on every
        # reconnect; we track what we subscribed to so _on_connect can restore
        # them after a broker restart or network blip.
        self._subscriptions: dict[str, int] = {}
        self._client = paho.Client(
            paho.CallbackAPIVersion.VERSION2,
            client_id=cfg.client_id,
            clean_session=True,
        )
        if cfg.username:
            self._client.username_pw_set(cfg.username, cfg.password or "")
        self._client.will_set(
            availability_topic(cfg), payload="offline", qos=1, retain=True
        )
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.on_disconnect = self._on_disconnect

    # ---- Lifecycle --------------------------------------------------------

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        log.info("MQTT connecting to %s:%d as %r",
                 self.cfg.host, self.cfg.port, self.cfg.client_id)
        # connect_async + loop_start: non-blocking TCP connect, paho retries
        self._client.connect_async(self.cfg.host, self.cfg.port, keepalive=60)
        self._client.loop_start()
        try:
            await asyncio.wait_for(self._connected_event.wait(), timeout=15.0)
        except asyncio.TimeoutError as e:
            self._client.loop_stop()
            raise ConnectionError(
                f"MQTT broker {self.cfg.host}:{self.cfg.port} did not connect "
                f"within 15 s"
            ) from e

    async def stop(self) -> None:
        # Mark offline, flush, disconnect cleanly.
        try:
            self.publish(availability_topic(self.cfg), "offline", retain=True)
            self._client.disconnect()
        finally:
            self._client.loop_stop()

    # ---- Pub/sub ----------------------------------------------------------

    def publish(self, topic: str, payload: str | bytes, *, retain: bool = False,
                qos: int = 1) -> None:
        info = self._client.publish(topic, payload=payload, qos=qos, retain=retain)
        if info.rc != paho.MQTT_ERR_SUCCESS:
            log.warning("MQTT publish to %s failed: rc=%s", topic, info.rc)

    def publish_json(self, topic: str, payload: dict, *, retain: bool = False) -> None:
        self.publish(topic, json.dumps(payload), retain=retain)

    def subscribe(self, topic: str, qos: int = 1) -> None:
        self._subscriptions[topic] = qos
        rc, _mid = self._client.subscribe(topic, qos=qos)
        if rc != paho.MQTT_ERR_SUCCESS:
            log.warning("MQTT subscribe to %s failed: rc=%s", topic, rc)

    # ---- Paho callbacks (run on paho's network thread) --------------------

    def _on_connect(self, _client, _userdata, _flags, reason_code, _properties=None):
        if reason_code == 0:
            log.info("MQTT connected to %s:%d", self.cfg.host, self.cfg.port)
            # Announce availability, set retained; LWT handles crash case.
            self._client.publish(
                availability_topic(self.cfg), "online", qos=1, retain=True
            )
            # Restore subscriptions. clean_session=True means the broker
            # forgot them during the disconnect; without this, HA commands
            # would be silently dropped after any broker blip.
            if self._subscriptions:
                log.info("MQTT re-subscribing to %d topic(s)", len(self._subscriptions))
                for topic, qos in self._subscriptions.items():
                    rc, _mid = self._client.subscribe(topic, qos=qos)
                    if rc != paho.MQTT_ERR_SUCCESS:
                        log.warning("MQTT re-subscribe %s failed: rc=%s", topic, rc)
            self._loop.call_soon_threadsafe(self._connected_event.set)
        else:
            log.error("MQTT connect refused: reason_code=%s", reason_code)

    def _on_disconnect(self, _client, _userdata, _flags, reason_code,
                       _properties=None):
        log.warning("MQTT disconnected: reason_code=%s", reason_code)

    def _on_message(self, _client, _userdata, msg):
        """Classify inbound topic; enqueue async dispatch to the bridge."""
        match = _UNIT_SET_RE.match(msg.topic)
        if match:
            unit = int(match.group("unit"))
            kind = match.group("kind") or "set"
            payload = msg.payload.decode("utf-8", errors="replace")
            coro = self._on_command(unit, kind, payload)
            asyncio.run_coroutine_threadsafe(coro, self._loop)
            return
        log.debug("MQTT unexpected topic: %s", msg.topic)


_UNIT_SET_RE = re.compile(
    r"^.*?/unit/(?P<unit>\d+)/(?:(?P<kind>brightness)/)?set$"
)
