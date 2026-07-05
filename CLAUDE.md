
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

## Current operational state (2026-07-05)

- Bridge runs in **CT 103** on the Proxmox host: `192.168.1.36:4370`,
  Debian 12, Python 3.11 venv, systemd unit `omnibus-bridge.service`
  with `Restart=always` and `--onboot 1`. Old pve rollback install
  deleted 2026-07-05.
- Translator at `192.168.1.30`, dials the bridge from an ephemeral
  source port (4097+ range observed). MQTT broker at
  `192.168.1.16:1883`. `start.sh` runs with
  `--allow-peer 192.168.1.30` — only the Translator may connect.
- **2026-07-05 hardening deployed** (commit `c9db96b`): newest
  connection evicts a stale client, 30 s handshake watchdog, peer
  allowlist, pushes requeued on socket errors, 60 s TTL on queued
  pushes, MQTT-unreachable-at-boot no longer fatal, state-file load
  hardened.
- **Active investigation:** post-reconnect phantom relay actuations.
  Confirmed mechanism (silent TCP disconnect → reconnect → handshake →
  `~4 s` later Translator pushes `cmd=1` burst → relay physically
  energises). ~9 reconnects/day observed Apr-Jul; post-handshake
  `cmd=1` bursts recur regularly. Root cause (bridge `0x3B` push vs
  Translator-side) still unproven. See [docs/BUGS.md](docs/BUGS.md).
  Note: Uptime Kuma (CT 108, `192.168.1.28`) TCP-probes the bridge
  port every 60 s; harmless since the allowlist, but it shows up in
  logs as rejected connections.
- **Rolling pcap rig**: systemd unit `omnibus-pcap.service` on pve,
  capturing on `veth103i0` (CT 103's veth on the host — the old USB
  mirror NIC `enx00e04c69e3ff` is physically gone from pve). 1h ×
  72-file ring at `/root/captures/omnibus_rolling_*.pcap`. Next
  phantom-on will have full decryptable bytes
  (`tools/pcap_decrypt.py` + keys from CT 103 `.env`).

## Reference material

- **Omni-Link II Protocol Description, Rev 3.0, Oct 2009** (HAI doc 20P00)
- **Omni-Bus Interface Translator Reference Manual** (HAI 117R00-1 Rev 2.20)
- Related open-source implementations for cross-reference:
  - [excaliburpartners/OmniLinkBridge](https://github.com/excaliburpartners/OmniLinkBridge) (C#)
  - [Matodak/omnilink](https://github.com/Matodak/omnilink) (Java)
  - [mantorok1/homebridge-omnilink-platform](https://github.com/mantorok1/homebridge-omnilink-platform) (Node.js)
  - [racingmars/omnilink](https://github.com/racingmars/omnilink) (Go)
