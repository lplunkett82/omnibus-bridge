# Device model + MQTT schema

## Device types

| Type         | Omni-Bus examples                       | HA entity     |
|--------------|------------------------------------------|---------------|
| `dimmer`     | 119A00-1, 119A00-2 DIN dimmers          | `light`       |
| `switch`     | Relay output modules                     | `switch`      |
| `keypad`     | Wired/wireless wall stations, keyfobs   | `event` + `device_trigger` |
| `input`      | Dry contact inputs                       | `binary_sensor` |
| `scene`      | OMNIBUS-programmed scenes                | `scene`       |

## Internal device model (Python)

```python
@dataclass
class Device:
    address: DeviceAddress      # (node_id, channel)
    name: str                   # from config.yaml
    kind: Literal["dimmer","switch","keypad","input","scene"]
    area: str | None            # "Kitchen", "Living Room", etc.
    state: DeviceState          # last known state

@dataclass
class DeviceAddress:
    node: int                   # 1–255
    channel: int                # 1–N depending on module
    def topic_id(self) -> str:
        return f"{self.node:03d}_{self.channel:02d}"
```

## MQTT topic structure

Base prefix: `omnibus/` (configurable)

### State (bridge → HA)
```
omnibus/light/<topic_id>/state       # "ON" | "OFF"
omnibus/light/<topic_id>/brightness  # 0–255
omnibus/switch/<topic_id>/state
omnibus/event/<topic_id>             # JSON: {"button": 3, "action": "press"}
omnibus/bridge/status                # "online" | "offline" (LWT)
```

### Command (HA → bridge)
```
omnibus/light/<topic_id>/set         # JSON: {"state":"ON","brightness":180}
omnibus/switch/<topic_id>/set        # "ON" | "OFF"
omnibus/scene/<scene_id>/activate    # any payload triggers
```

### HA auto-discovery
Published once on startup, retained, to `homeassistant/<component>/omnibus_<topic_id>/config`.
Example for a dimmer:

```json
{
  "name": "Kitchen Pendants",
  "unique_id": "omnibus_005_01",
  "state_topic": "omnibus/light/005_01/state",
  "command_topic": "omnibus/light/005_01/set",
  "brightness_state_topic": "omnibus/light/005_01/brightness",
  "brightness_command_topic": "omnibus/light/005_01/set",
  "schema": "json",
  "availability_topic": "omnibus/bridge/status",
  "device": {
    "identifiers": ["omnibus_node_005"],
    "name": "Omni-Bus Dimmer Node 5",
    "manufacturer": "Leviton",
    "model": "Omni-Bus Dimmer",
    "via_device": "omnibus_translator"
  }
}
```

## Config file format (`config.yaml`)

```yaml
translator:
  host: 192.168.1.50
  port: 4369           # update once confirmed in Phase 1
  reconnect_seconds: 5

mqtt:
  host: 192.168.1.10
  port: 1883
  username: !env MQTT_USER
  password: !env MQTT_PASS
  base_topic: omnibus
  discovery_prefix: homeassistant

devices:
  - address: [5, 1]
    kind: dimmer
    name: Kitchen Pendants
    area: Kitchen
  - address: [5, 2]
    kind: dimmer
    name: Kitchen Island
    area: Kitchen
  - address: [12, 1]
    kind: keypad
    name: Master Bedroom Keypad
    area: Master Bedroom
    buttons: 6
```

Long term, generate this file from the OMNIBUS Software config export so it
stays in sync with the physical install.
