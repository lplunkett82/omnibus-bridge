"""Tests for MQTT topic helpers + HA discovery payload construction.

Pure-function tests — no broker required.
"""
from __future__ import annotations

from omnibus_bridge.mqtt import (
    MqttConfig,
    _UNIT_SET_RE,
    availability_topic,
    brightness_set_topic,
    brightness_state_topic,
    build_discovery_payloads,
    discovery_topic,
    set_topic,
    state_topic,
)
from omnibus_bridge.scanner import DIMMER, Device, RELAY, TRANSLATOR, WALLSWITCH_BUTTON


def _cfg(**overrides) -> MqttConfig:
    return MqttConfig(host="broker.local", port=1883, **overrides)


# -- Topic helpers ----------------------------------------------------------


def test_topic_helpers_produce_expected_paths():
    cfg = _cfg()
    assert state_topic(cfg, 5) == "omnibus/unit/5/state"
    assert set_topic(cfg, 5) == "omnibus/unit/5/set"
    assert brightness_state_topic(cfg, 33) == "omnibus/unit/33/brightness"
    assert brightness_set_topic(cfg, 33) == "omnibus/unit/33/brightness/set"
    assert availability_topic(cfg) == "omnibus/bridge/availability"
    assert discovery_topic(cfg, "light", "unit_001_kitchen") == (
        "homeassistant/light/omnibus_bridge/unit_001_kitchen/config"
    )


def test_unit_set_regex_matches_set_and_brightness():
    m = _UNIT_SET_RE.match("omnibus/unit/5/set")
    assert m and m["unit"] == "5" and m["kind"] is None

    m = _UNIT_SET_RE.match("omnibus/unit/33/brightness/set")
    assert m and m["unit"] == "33" and m["kind"] == "brightness"

    # rejects unrelated topics
    assert _UNIT_SET_RE.match("omnibus/unit/5/state") is None
    assert _UNIT_SET_RE.match("omnibus/button/14/event") is None


def test_unit_set_regex_honors_custom_base_topic():
    # Base topic is just a prefix; the helper is tolerant of any path.
    m = _UNIT_SET_RE.match("home/omnibus/unit/7/set")
    assert m and m["unit"] == "7"


# -- Discovery payloads -----------------------------------------------------


def _relay(unit: int, name: str) -> Device:
    return Device(unit_number=unit, name=name, device_type=RELAY, raw_frame=b"")


def _dimmer(unit: int, name: str = "") -> Device:
    return Device(unit_number=unit, name=name, device_type=DIMMER, raw_frame=b"")


def _button(unit: int, name: str) -> Device:
    return Device(unit_number=unit, name=name, device_type=WALLSWITCH_BUTTON,
                  raw_frame=b"")


def _translator() -> Device:
    return Device(
        unit_number=0, name="Translator", device_type=TRANSLATOR, raw_frame=b"",
        device_id="XXXXXXXX", ip="192.0.2.10", netmask="255.255.255.0",
        gateway="192.168.1.1", port=43690,
    )


def test_build_discovery_emits_one_payload_per_controllable_device():
    cfg = _cfg()
    payloads = build_discovery_payloads(
        cfg,
        [_relay(1, "Kitchen"), _dimmer(33, "Lounge Down"),
         _button(14, "Kitchen door")],
        translator=_translator(),
    )
    # 1 light (relay) + 1 light (dimmer) + 2 for the button (switch + level sensor)
    assert len(payloads) == 4
    topics = [t for t, _ in payloads]
    assert any("/light/" in t and "unit_001_kitchen" in t for t in topics)
    assert any("/light/" in t and "unit_033_lounge_down" in t for t in topics)
    assert any("/switch/" in t and "button_014_kitchen_door" in t for t in topics)
    assert any("/sensor/" in t and "button_level_014_kitchen_door" in t for t in topics)


def test_relay_discovery_payload_has_on_off_topics():
    cfg = _cfg()
    (_topic, payload), = build_discovery_payloads(cfg, [_relay(1, "Kitchen")])
    assert payload["state_topic"] == "omnibus/unit/1/state"
    assert payload["command_topic"] == "omnibus/unit/1/set"
    assert payload["payload_on"] == "ON"
    assert payload["payload_off"] == "OFF"
    assert "brightness_state_topic" not in payload


def test_dimmer_discovery_payload_has_brightness_topics():
    cfg = _cfg()
    (_topic, payload), = build_discovery_payloads(cfg, [_dimmer(33, "Lounge Down")])
    assert payload["brightness_state_topic"] == "omnibus/unit/33/brightness"
    assert payload["brightness_command_topic"] == "omnibus/unit/33/brightness/set"
    assert payload["brightness_scale"] == 100
    # HA needs "brightness" on_command_type so a plain ON still carries a level
    assert payload["on_command_type"] == "brightness"


def test_dimmer_without_stored_name_falls_back_to_default():
    cfg = _cfg()
    (_topic, payload), = build_discovery_payloads(cfg, [_dimmer(33, "")])
    assert payload["name"] == "Dimmer 33"


def test_wallswitch_button_discovery_emits_switch_and_level_sensor():
    cfg = _cfg()
    payloads = build_discovery_payloads(cfg, [_button(14, "Kitchen door")])
    # Two entities per button: a switch (ON/OFF press state) and a sensor
    # (0..100 % level, updated during long-press dim streams so HA
    # automations can mirror the level to non-Omnibus lights).
    assert len(payloads) == 2
    by_domain = {t.split("/")[1]: (t, p) for t, p in payloads}

    switch_topic, switch = by_domain["switch"]
    assert switch["state_topic"] == "omnibus/unit/14/state"
    assert switch["command_topic"] == "omnibus/unit/14/set"
    assert switch["payload_on"] == "ON"
    assert switch["payload_off"] == "OFF"
    assert switch["optimistic"] is False
    assert "event_types" not in switch
    assert "#14" in switch["name"]

    sensor_topic, sensor = by_domain["sensor"]
    assert sensor["state_topic"] == "omnibus/unit/14/level"
    assert sensor["unit_of_measurement"] == "%"
    assert sensor["state_class"] == "measurement"
    assert "command_topic" not in sensor


def test_translator_is_embedded_in_device_info_not_published_as_entity():
    cfg = _cfg()
    devs = [_relay(1, "Kitchen")]
    payloads = build_discovery_payloads(cfg, devs, translator=_translator())
    assert len(payloads) == 1  # translator itself not emitted
    _, payload = payloads[0]
    # Translator IP should inform configuration_url on the shared Device
    assert payload["device"]["configuration_url"] == "http://192.0.2.10/"
    # Device identifiers include the Translator's hardware ID
    assert any("XXXXXXXX" in ident for ident in payload["device"]["identifiers"])
