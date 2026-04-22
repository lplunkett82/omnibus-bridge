# omnibus-bridge

A Python asyncio daemon that bridges a Leviton/HAI **117A00-1 Omni-Bus
Interface Translator** directly to **Home Assistant** over MQTT, with
automatic entity discovery. No OmniPro II controller required.

It implements the Omni-Link II protocol on the controller side: the
Translator dials the bridge, the bridge answers status polls and pushes
state changes, and every Omni-Bus device — relays, dimmers, wall-switch
buttons — appears in Home Assistant as a first-class entity.

## Status

| Phase | Status |
|-------|--------|
| Protocol decoding & session handshake      | Done |
| Device scanner (auto-inventory)            | Done |
| Push-based state sync + HA auto-discovery  | Done |
| Wall-switch button entities + long-press dim support | Done |
| State persistence across restarts          | Done |
| HA add-on / HACS packaging                 | Not started |

The bridge has been running continuously against a 36-device installation
(19 relays, 1 dimmer, 16 wall-switch buttons across keypads and single-
button stations) since 2026-04-22.

## Supported hardware

- **Translator:** Leviton 117A00-1 Rev 2, firmware V2.34 (others untested)
- **Omni-Bus devices** exposed as Units on the Translator:
  - Relay channels → Home Assistant `light` entities
  - Dimmer modules → `light` entities with brightness
  - Wall-switch buttons (ALC / Extended house-code format) → `switch`
    entities (ON/OFF state reflects physical press) plus a companion
    `sensor` giving a 0–100 % level during long-press holds

## Requirements

- Python **3.12+**
- `paho-mqtt >= 2.0` (not the `1.x` packaged in older Debian)
- An MQTT broker reachable from both the bridge and Home Assistant
  (Mosquitto add-on works fine)
- Translator must be reconfigurable to dial the bridge (via OMNIBUS
  Software → CBIT Profile → Leviton Omni-Link → Controller IP + Port)

## Quick start

### 1. Install

```bash
git clone https://github.com/lplunkett82/omnibus-bridge
cd omnibus-bridge
pip install -e .
```

### 2. Get the Translator's encryption keys

The 128-bit AES key is configured on the Translator via OMNIBUS Software.
Split into two 64-bit halves ("Encryption Key 1" and "Encryption Key 2").
Put them in a `.env` file at the repo root:

```
OMNILINK_KEY1=0123456789ABCDEF
OMNILINK_KEY2=FEDCBA9876543210
```

### 3. Scan your Omni-Bus to generate a device inventory

```bash
python -m omnibus_bridge.scanner <translator-ip> > config/units.yaml
```

(Translator must not have an active OMNIBUS Software session during the
scan; the channel is shared.)

Review the output — the scanner can miss buttons on unusual keypad layouts
and occasionally emits blank-name entries you'll want to prune.

### 4. Point the Translator at the bridge

Open OMNIBUS Software → CBIT Profile → Leviton Omni-Link → Controller IP
= `<bridge IP>`, Port = `4369` → Download to the Translator.

### 5. Run

```bash
python -m omnibus_bridge \
    --devices-yaml config/units.yaml \
    --state-file config/state.json \
    --mqtt-host <broker IP> \
    --mqtt-user <user> --mqtt-password <password> \
    --log-level INFO
```

Home Assistant will auto-discover every unit within a few seconds.

## MQTT topic layout

```
omnibus/unit/<N>/state              ON / OFF
omnibus/unit/<N>/set                command (ON / OFF)
omnibus/unit/<N>/brightness         0..100 (dimmers only)
omnibus/unit/<N>/brightness/set     0..100 command
omnibus/unit/<N>/level              0..100 (wall-switch long-press level)
omnibus/bridge/availability         online / offline (LWT)

homeassistant/light/omnibus_bridge/unit_<N>_<slug>/config      discovery
homeassistant/switch/omnibus_bridge/button_<N>_<slug>/config
homeassistant/sensor/omnibus_bridge/button_level_<N>_<slug>/config
```

## CLI options

| Flag | Default | Notes |
|------|---------|-------|
| `--port`               | `4369` | TCP port the Translator dials |
| `--units`              | `36`   | Unit-table size |
| `--state-file`         | —      | JSON path for cross-restart persistence (recommended) |
| `--devices-yaml`       | —      | Device inventory (from the scanner) |
| `--scan`               | off    | Run the 43690 scanner at startup instead of reading YAML |
| `--mqtt-host`          | —      | Broker hostname; MQTT disabled if unset |
| `--mqtt-port`          | `1883` | |
| `--mqtt-user/password` | —      | |
| `--mqtt-base-topic`    | `omnibus` | |
| `--mqtt-discovery-prefix` | `homeassistant` | |
| `--log-level`          | `INFO` | `DEBUG` logs every inbound frame |

## Home Assistant automation example

Mirror a wall-switch button's long-press dim level onto a Hue bulb:

```yaml
trigger:
  platform: state
  entity_id: sensor.kitchen_door_level
action:
  service: light.turn_on
  target:
    entity_id: light.hue_kitchen
  data:
    brightness_pct: "{{ trigger.to_state.state | int(0) }}"
mode: restart
```

## Known limitations

- **Bridge restart gap (~14 s).** Once, after any bridge restart, the
  Translator tries to resume its prior session with a stale AES key.
  The bridge tells it to start over; the Translator backs off 14 seconds
  before opening a fresh handshake. Verified to be a Translator-side
  timer, not fixable from our end without a session-key persistence
  feature.
- **Linked-switch LED state is not mirrored.** If a relay is linked to a
  wall-switch LED on the Omni-Bus wire, turning the relay on via HA
  lights the LED physically — but the HA switch tile won't reflect that.
  Bridge-side mirroring is on the roadmap.
- **First boot with no state file** writes an empty state table to disk
  and turns every light OFF. One warm-up cycle populates the file; all
  subsequent restarts retain state cleanly.

## Testing

```bash
python -m pytest
```

82 tests covering CRC, crypto, protocol round-trips, session state
machine, transport, state persistence, MQTT discovery, and bridge
integration flow.

## Safety

- The bridge is the only thing talking to the Translator at runtime. It
  is the source of truth for unit state; the Translator syncs physical
  devices to whatever the bridge reports at session start. **Always**
  run with `--state-file` pointing at persistent storage.
- The Translator has 8 client slots. Avoid running multiple bridge
  instances against it concurrently.
- Physical wall switches actuate lights locally on the RS-485 wire even
  when the bridge is down. HA automations break, but manual control
  survives.

## Architecture

```
Home Assistant
   ↕ MQTT (auto-discovery + state)
omnibus-bridge     ← this repo (Omni-Link II controller, TCP :4369)
   ↑ Omni-Link II (Translator dials outbound)
Leviton 117A00-1 Interface Translator
   ↕ Omni-Bus RS-485
Relays • Dimmers • Wall-switches • Keypads
```

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for wire-level detail and
[docs/ROADMAP.md](docs/ROADMAP.md) for what's done, what's deferred,
and what's next.

## License

TBD — not yet open-sourced. Phase 6 will publish under MIT.
