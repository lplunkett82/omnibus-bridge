# Roadmap

Status legend: ⬜ not started · 🟡 in progress · ✅ done · ⚠️ blocked

## Phase 0 — Setup

- ✅ Python 3.12+ project scaffold (asyncio, cryptography, paho-mqtt, pyyaml, pytest, ruff)
- ✅ Docs skeleton (PROTOCOL.md, SCHEMA.md, STYLE.md, BUGS.md, RECON.md, etc.)
- ✅ `.env.example` for the Translator's 128-bit private key

## Phase 1 — Protocol verification

- ✅ CRC-16/A001 implementation + test against spec example
- ✅ AES-128 + sequence-XOR encryption layer verified byte-for-byte
  against live capture
- ✅ Full handshake decoded: type 1 → 2 → 3 → 4, per-session key derivation
- ✅ Role inversion confirmed: the Translator is the client, the
  controller (us or OmniPro) listens on TCP `4369`

## Phase 2 — Object enumeration + passive listening

- ✅ 43690 scanner tool (`src/omnibus_bridge/scanner.py`) enumerates
  every Omni-Bus device visible to the Translator
- ✅ Unit-status + extended-status record format decoded
- ✅ `CONTROLLER_COMMAND (0x14)` and `EXT_OBJECT_STATUS (0x3B)` paths
  mapped

## Phase 3 — Bridge daemon

- ✅ `crc.py`, `crypto.py` — sans-IO primitives
- ✅ `session.py` — controller-side handshake state machine
- ✅ `protocol.py` — inner-frame encode/decode for every message type
- ✅ `transport.py` — asyncio TCP server on port 4369
- ✅ `objects.py` / `scanner.py` — device model, seeded from scanner or
  hand-curated YAML
- ✅ `state.py` — `UnitStateTable` with JSON persistence
- ✅ `mqtt.py` — paho-mqtt + HA auto-discovery (lights, dimmers,
  switches, companion level sensors)
- ✅ End-to-end: HA toggle → MQTT → bridge → Translator → relay actuates

## Phase 4 — Hardening

- ✅ Seq-echo in replies (critical for poll cadence + session
  longevity — see [docs/BUGS.md](BUGS.md))
- ✅ State persistence across bridge restarts
- ✅ Long-press dim support with alternating direction
- ✅ MQTT re-subscribe on reconnect
- ✅ TCP keepalive tuning (~8 s dead-peer detection)
- ⬜ Prometheus metrics endpoint (optional)
- ⬜ Systemd service file (only for bare-metal installs; HA add-on
  doesn't need it)

## Phase 5 — OmniPro II removal

- ✅ Controller-IP cutover path identified and documented
- ✅ Verified live: bridge accepts handshake, answers polls, drives
  lights via `0x3B` pushes
- ⬜ Long-term standalone soak — run bridge for 7 days with OmniPro off

## Phase 6 — HA add-on packaging

- ⬜ `Dockerfile` (Alpine + Python 3.12)
- ⬜ `config.yaml` (MQTT + Translator IP + keys)
- ⬜ `run.sh` entrypoint
- ⬜ Ingress web UI with a Scan button
- ⬜ HACS-compatible repo published

## Phase 7 — Open source

- ⬜ MIT LICENSE
- ⬜ Public repo announcement on home-assistant.io community,
  r/homeassistant, Cocoontech

## Phase 8 — Native HA integration (optional, later)

- ⬜ `custom_components/omnibus/` with config flow UI, proper device_info
- ⬜ HACS submission

---

## Deferred — Linked-switch state mirroring

**Symptom:** toggle a relay/dimmer in HA → the Omni-Bus-linked wall
switch's LED lights up physically, but the switch's HA tile stays OFF.

**Cause:** when we push `0x3B seq=0` for the load unit, the Translator
actuates both the relay AND the linked wall switch's LED via RS-485
linkage, but only reports the load unit upstream. The switch unit is
never mentioned.

**Fix (proposed):**
- Add a `linked_switches: [<unit>, ...]` field to relay/dimmer entries
  in `units.yaml`.
- In `Bridge._on_state_change`, when a relay/dimmer state changes,
  mirror the same ON/OFF to every `linked_switches` unit via
  `state.set_status(...)`. The existing state-change callback chain
  publishes to MQTT.

**Blocker:** no reliable source for the switch↔load link map without
either manual entry by the installer or decoding of the OMNIBUS Software
upload/download 32-byte record format (op `0E 09 28` on port 43690,
semantics TBD).
