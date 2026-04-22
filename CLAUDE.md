# omnibus-bridge — project context

This file is read by Claude Code sessions and by new contributors. It
summarises the project's intent, architecture, and working conventions.

## What this is

A Python asyncio daemon that speaks the **Omni-Link II protocol** to a
Leviton/HAI 117A00-1 Omni-Bus Interface Translator and exposes every
Omni-Bus device (relays, dimmers, wall-switch buttons) to Home Assistant
via MQTT with auto-discovery.

The bridge is the Omni-Link II **controller**, not the client. The
Translator dials the bridge on TCP `4369` and we answer. No OmniPro II
is required in the runtime path.

## Architecture

```
Omni-Bus devices (wall stations, dimmers, relays, wireless keypads)
        │ (RS-485 Omni-Bus network)
        ▼
117A00-1 Interface Translator
        │ TCP/IP — Omni-Link II
        ▼
omnibus-bridge (this repo — Python asyncio)
        │ MQTT (+ Home Assistant auto-discovery)
        ▼
Home Assistant
```

## Key protocol facts

The **Omni-Link II Protocol Description** (HAI document 20P00 Rev 3.0,
Oct 2009) is the authoritative spec. Points that actually matter at the
code level:

- Session handshake (40-bit session ID, 128-bit session key derivation).
- AES-128 encryption with per-block sequence-number XOR — not CBC, not CTR.
- Inner frame `0x21 | length | type | data | CRC-16-LSB | CRC-16-MSB`
  (CRC-16 poly `0xA001`, init `0x0000`).
- Outer packet `seq(2) | type(1) | reserved(1) | body`.
- Message types we handle: `REQ_OBJECT_STATUS (0x22)`,
  `OBJECT_STATUS (0x23)`, `REQ_EXT_OBJECT_STATUS (0x3A)`,
  `EXT_OBJECT_STATUS (0x3B)`, `CONTROLLER_COMMAND (0x14)`,
  `ENABLE_NOTIFICATIONS (0x15)`, plus the handshake types 1–6.
- **Reply seq MUST echo the request's seq.** Using our own counter makes
  the Translator classify the controller as flaky — slow 2 s polling and
  ~16 s session drops. Echoing gives ~225 ms polls and indefinite sessions.
- HA-originated writes go out as `0x3B seq=0` unsolicited pushes.
- Physical wall-switch events arrive as `CONTROLLER_COMMAND cmd=0/1 p2=unit`.
- Long-press dimming arrives as `CONTROLLER_COMMAND cmd=9 p1=0..100`
  streamed at ~4 Hz. The Translator always sends a decreasing stream;
  the bridge flips direction between holds to give a rocker-dimmer UX.

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the fully decoded wire
details.

## Repo layout

```
omnibus-bridge/
├── README.md              public-facing install + usage
├── CLAUDE.md              this file
├── pyproject.toml
├── .env.example           OMNILINK_KEY1/KEY2 template
├── docs/
│   ├── PROTOCOL.md        wire-level notes (Omni-Link II + extensions)
│   ├── SCHEMA.md          device model + MQTT topic structure
│   ├── ROADMAP.md         phases, what's done, what's deferred
│   ├── BUGS.md            known quirks and workarounds
│   ├── RECON.md           reverse-engineering notes
│   ├── STYLE.md           code style
│   └── SKILLS.md          testing and tooling tips
├── src/omnibus_bridge/
│   ├── crc.py             CRC-16/A001
│   ├── crypto.py          AES-128 + seq XOR + session key derivation
│   ├── session.py         handshake state machine (controller-side)
│   ├── protocol.py        inner-frame encode/decode, message types
│   ├── transport.py       asyncio TCP server
│   ├── scanner.py         43690 device enumeration
│   ├── state.py           UnitStateTable + persistence
│   ├── objects.py         Device domain models
│   ├── mqtt.py            paho-mqtt + HA auto-discovery
│   ├── config.py          .env / CLI config loading
│   └── main.py            composition root + CLI entrypoint
├── tests/                 pytest — unit + integration
└── tools/                 one-shot scripts for captures, scans, decoding
```

## Safety rules

- **The bridge is the source of truth for unit state.** The Translator
  syncs physical devices to whatever we report at session start, so
  always run with `--state-file` pointing at persistent storage.
- **Translator has 8 client slots total.** Don't run multiple bridge
  instances against it.
- **Wall switches actuate lights locally on the RS-485 wire** even when
  the bridge is down. HA automations break, but physical control works.
- **Back up OMNIBUS Software config** before changing the Controller IP
  setting on the Translator. The change is reversible via the same tool.

## Testing

```bash
python -m pytest
```

82+ tests covering CRC, crypto, protocol round-trips, session state
machine, transport, state persistence, MQTT discovery, scanner parsing,
and bridge integration.

## Working notes

- Prefer editing existing files over creating new ones.
- Don't add hypothetical-future abstractions; only what the current task
  requires.
- Keep comments focused on the non-obvious (why, not what).
- Packet captures live in `captures/` (gitignored). Regenerate by port-
  mirroring the Translator's switch port and running `tcpdump` on the
  capture host.

## Home Assistant entity management

- **Renaming entities**: use HA's WebSocket API
  (`config/entity_registry/update`) while HA is running. This is the same
  mechanism the HA UI uses and persists across restarts. Connect to
  `ws://supervisor/core/api/websocket`, authenticate with
  `$SUPERVISOR_TOKEN`, then send
  `{"id": N, "type": "config/entity_registry/update", "entity_id": "...", "name": "..."}`.
- **Do NOT edit `/config/.storage/core.entity_registry` directly** — HA
  overwrites user-set `name` fields on restart when MQTT discovery
  re-processes retained messages.
- **Do NOT change `name` in `units.yaml` to rename entities** — the `name`
  field feeds into `object_id` and `unique_id` in MQTT discovery. Changing
  it creates new entities with new entity IDs instead of renaming existing
  ones.
- **HA SSH access**: `ssh -p 2222 -i ~/.ssh/id_ed25519 root@192.168.1.16`.
  The `websocket-client` Python package is installed for WebSocket API use.

## Reference material

- **Omni-Link II Protocol Description, Rev 3.0, Oct 2009** (HAI doc 20P00)
- **Omni-Bus Interface Translator Reference Manual** (HAI 117R00-1 Rev 2.20)
- Related open-source implementations for cross-reference:
  - [excaliburpartners/OmniLinkBridge](https://github.com/excaliburpartners/OmniLinkBridge) (C#)
  - [Matodak/omnilink](https://github.com/Matodak/omnilink) (Java)
  - [mantorok1/homebridge-omnilink-platform](https://github.com/mantorok1/homebridge-omnilink-platform) (Node.js)
  - [racingmars/omnilink](https://github.com/racingmars/omnilink) (Go)
