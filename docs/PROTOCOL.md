# Protocol — Omni-Link II implementation notes for omnibus-bridge

Authoritative source: `docs/reference/Omni-Link_II_Rev_3.0.pdf`
(HAI document 20P00, Rev 3.0, October 2009).

This doc is NOT a re-derivation of the spec. It is:
1. A summary of the parts relevant to us
2. Our decisions on how to implement them in Python asyncio
3. Notes on Omni-Bus-specific behaviour (which will be populated during
   Phase 1 and 2 against the live Translator)

## Outer packet format

Every Omni-Link II packet over TCP has this 4-byte header followed by payload:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌─────────────────────────────┬───────────────┬───────────────┐
│       Sequence number       │   Msg type    │    Reserved   │
│          (16 bits)          │    (8 bits)   │    (= 0x00)   │
├─────────────────────────────┴───────────────┴───────────────┤
│                         Message data                          │
│                     (variable, may be empty)                  │
└───────────────────────────────────────────────────────────────┘
```

Sequence number is MSB first. 0 = sequence tracking disabled. Client
increments for every outbound packet, wrapping 65535 → 1.

Message type values (from spec Appendix A):

| Value | Meaning                                         |
|-------|-------------------------------------------------|
| 0     | No message                                      |
| 1     | Client request new session                      |
| 2     | Controller acknowledge new session              |
| 3     | Client request secure connection                |
| 4     | Controller acknowledge secure connection        |
| 5     | Client session terminated                       |
| 6     | Controller session terminated                   |
| 7     | Controller cannot start new session             |
| 32    | Omni-Link II application data message (0x20)    |

Only type 32 and type 3 messages are encrypted. Everything else is plaintext.

## Session handshake

```
Client                                    Controller (Translator)
  │                                                  │
  ├─ type 1, no data  ──────────────────────────────▶│
  │                                                  │
  │◀──── type 2, data = protocol_version (2B) +  ────┤
  │           session_id (5B, random, MSB first)     │
  │                                                  │
  │  [client derives session key:                    │
  │     high 88 bits = private_key[0..10]            │
  │     low 40 bits  = private_key[11..15] XOR       │
  │                    session_id                ]   │
  │                                                  │
  ├─ type 3, data = AES_encrypt(session_id) ────────▶│
  │                                                  │
  │◀──── type 4, data = AES_encrypt(session_id) ─────┤
  │                                                  │
  │          (secure session established)            │
  │                                                  │
  ├─ type 32, data = AES_encrypt(inner_frame) ──────▶│
  │◀──── type 32, data = AES_encrypt(inner_frame) ───┤
  │                                                  │
  ├─ type 5, no data  ──────────────────────────────▶│
  │◀──── type 6, no data ────────────────────────────┤
```

### Private key

The private key is the 128-bit value configured on the Translator/controller.
It's split into two "encryption keys" in the UI, each 8 bytes / 16 hex chars.
Concatenate key1 + key2 → 16 bytes → the private key.

Stored in `.env` as `OMNILINK_KEY1=...` and `OMNILINK_KEY2=...`. Never commit.

## AES-128 with sequence-number XOR

Per the spec:

1. Data is padded with zeros on the right to a multiple of 16 bytes
2. For each 16-byte block, XOR byte[0] with seq_MSB and byte[1] with seq_LSB
3. AES-128-ECB encrypt with the session key
4. Transmit

Decryption is the reverse. Note the quirk: it's ECB + seq-XOR, NOT standard
AES-CBC or AES-CTR. This effectively gives you a seq-derived IV on the first
block but the same modification on every block (all blocks of a single
message XOR against the same seq number). We implement this exactly as
specified — don't get creative.

## Inner frame (application data message)

Wrapped inside the encrypted payload of a type-32 outer packet:

```
┌──────┬────────┬─────────┬──────────────┬────────┬────────┐
│ 0x21 │ length │  type   │     data     │ CRC-L  │ CRC-H  │
│      │ (1 B)  │ (1 B)   │  (variable)  │ (1 B)  │ (1 B)  │
└──────┴────────┴─────────┴──────────────┴────────┴────────┘
```

- Start byte always `0x21` (`!`)
- `length` = number of bytes in `type + data` (so min 1 for msg with no data)
- CRC-16 polynomial `0xA001`, initial value `0x0000`
- CRC is computed over `length + type + data` (i.e. everything between start
  byte and CRC)
- CRC bytes are LSB then MSB on the wire

### Reference: sample ACK from spec (page 5)

```
0x21 0x01 0x01 0xC0 0x50
```

Our CRC implementation MUST produce `0xC0 0x50` for input `0x01 0x01`. This
is our first unit test.

## Message types we will use

All values are the `type` byte of the inner frame (i.e. after the encrypted
outer packet layer is peeled off).

| Type | Name                         | Direction    | Notes                         |
|------|------------------------------|--------------|-------------------------------|
| 0x01 | ACKNOWLEDGE                  | ← Translator | Generic OK                    |
| 0x02 | NEGATIVE ACKNOWLEDGE         | ← Translator | Malformed or rejected         |
| 0x03 | END OF DATA                  | ← Translator | "No more" terminator          |
| 0x14 | CONTROLLER COMMAND           | → Translator | The lighting commands         |
| 0x15 | ENABLE NOTIFICATIONS         | → Translator | Turn on push events           |
| 0x16 | REQ SYSTEM INFORMATION       | → Translator | Phase 1 probe                 |
| 0x17 | SYSTEM INFORMATION           | ← Translator | Model + firmware + phone      |
| 0x1E | REQ OBJECT TYPE CAPACITIES   | → Translator | How many of each type         |
| 0x1F | OBJECT TYPE CAPACITIES       | ← Translator | Reply to 0x1E                 |
| 0x20 | REQ OBJECT PROPERTIES        | → Translator | Walk device list              |
| 0x21 | OBJECT PROPERTIES            | ← Translator | Reply to 0x20                 |
| 0x22 | REQ OBJECT STATUS            | → Translator | Current state                 |
| 0x23 | OBJECT STATUS                | ← Translator | Reply to 0x22 AND push event  |
| 0x37 | OTHER EVENT NOTIFICATIONS    | ← Translator | Switch presses, system events |
| 0x3A | REQ EXTENDED OBJECT STATUS   | → Translator | Firmware 3.0+ richer status   |
| 0x3B | EXTENDED OBJECT STATUS       | ← Translator | Reply to 0x3A                 |

## CONTROLLER COMMAND (type 0x14)

Single-byte command, 1-byte param P1, 2-byte param P2 (MSB first).

For Omni-Bus lighting (assuming it's mapped to ALC-style units — to verify in
Phase 2):

| Command | P1         | P2     | Description                        |
|---------|------------|--------|------------------------------------|
| 0       | 0          | unit# | Unit off                            |
| 1       | 0          | unit# | Unit on                             |
| 9       | 0-100      | unit# | Dimmer level (%)                    |
| 16+s    | 0          | unit# | Dim by s steps (s=1-9)              |
| 32+s    | 0          | unit# | Brighten by s steps                 |
| 60/61/62| scene#     | —      | Scene off/on/set (Leviton-specific) |

## UNIT STATUS (type 0x23, object type 0x02)

5 bytes per unit in the response:

```
unit_number_MSB | unit_number_LSB | status | time_MSB | time_LSB
```

Status byte values depend on unit type. For ALC-style (likely what Omni-Bus
maps to):

- 0 = off
- 1 = on
- 100-200 = level 0-100% (subtract 100)

Time is seconds remaining on a timed command (0 if none).

## OTHER EVENT NOTIFICATIONS (type 0x37)

Payload is a list of 16-bit event codes. Relevant to us:

**ALC / UPB / RadioRA / Starlite switch press:**
```
1111 ssss uuuu uuuu
         (high byte)   (low byte)
```
- s = switch code: 0=off, 1=on, 2-11 = switch 1-10
- u = unit number (8 bits — so limited to unit ≤ 255 at this notification
  level; higher-numbered units may use a different encoding, verify in Phase 2)

**UPB Link (Leviton scenes probably use this):**
```
1111 11cc nnnn nnnn
```
- c = command: 0=off, 1=on, 2=set, 3=fade stop
- n = link number

## Unit types and the Omni-Bus question

From spec page 18:

| Type | Description     |
|------|-----------------|
| 1    | Standard (X-10) |
| 2    | Extended        |
| 3    | Compose         |
| 4    | UPB             |
| 5    | HLC Room        |
| 6    | HLC Load        |
| 7    | Lumina Mode     |
| 8    | RadioRA         |
| 9    | CentraLite      |
| 10   | ViziaRF Room    |
| 11   | ViziaRF Load    |
| 12   | Flag            |
| 13   | Output          |
| 14   | Audio Zone      |
| 15   | Audio Source    |

**Omni-Bus is not listed explicitly**, but PC Access (OmniPro II config,
`PrincessSt_April_2026.pca`, inspected 2026-04-20) shows every Omni-Bus unit
configured with **House Code Format = Extended**. The dropdown offers UPB,
HLC, RadioRA, ZigBee, etc. — none of those were chosen. That strongly implies
the Translator exposes Omni-Bus devices as **unit_type 2 (Extended)** over
Omni-Link II, with unit index as the address (Address/Node ID column is `n/a`
— Extended uses implicit A1…P16 positions encoded in the unit number).

Annotations like `(A1 / BR1-1)` map the Extended house code (A1) to a
Bus/Ring/Position identifier on the physical Omni-Bus wire.

Additional finding from the same config: **keypads live in the Units list
alongside dimmers/relays**, not in a separate collection. Unit 014
"6BUTTON SW6" is a 6-button wall station. Phase 2 enumeration must expect
mixed device kinds under a single `REQ_OBJECT_PROPERTIES` walk of Units,
and button-press events still come via OTHER EVENT NOTIFICATIONS (type 0x37)
keyed on the same unit number.

**Phase 2 enumeration confirms this** by reading unit_type directly from the
Translator for each unit and verifying the value is 2. ALC-style status byte
semantics (0/1/100–200) from the UNIT STATUS section apply.

## Implementation notes for asyncio

- Use `asyncio.StreamReader`/`StreamWriter` (open_connection)
- Single task per connection for reads, send via `drain()`-ed writes
- Response correlation: push outgoing requests onto a pending-replies dict
  keyed by sequence number, resolve futures when replies arrive
- Notification handling: dispatch type-0x23 and type-0x37 inbound messages
  to a separate queue that the bridge's state manager consumes
- Session timeout: the spec doesn't specify one but OmniLinkBridge uses 5
  minutes of inactivity. Send a lightweight query (e.g. REQ_SYSTEM_STATUS)
  every 60s to keep the session alive.

## Known unknowns (resolved during Phase 1 & 2)

- [ ] TCP port number the Translator listens on
- [ ] Translator model number in SYSTEM INFORMATION response
- [ ] Whether encryption keys from OMNIBUS Software match what Omni-Link II
      expects (there may be two separate key slots — Omni-Link II vs Bus
      Gateway)
- [ ] Omni-Bus unit_type value(s)
- [ ] How 256+ unit addresses encode in OTHER EVENT NOTIFICATIONS (8 bits
      only in the documented `1111 ssss uuuu uuuu` — spec may be incomplete)
- [ ] Whether wall-switch button *presses* (not just on/off state changes)
      come through as OTHER EVENT or some other mechanism — if Omni-Bus
      wireless keypads use the 433MHz radio, the Translator may need a
      different notification path

## Live device behaviour

*Populated during Phase 1 and Phase 2-Fallback against 192.0.2.10.*

| Finding | Value | Source |
|---------|-------|--------|
| Open TCP ports (SYN scan) | 80, 43690, 43694 | nmap -sS -p 1-65535 2026-04-20 |
| **Active TCP port** (missed by initial nmap) | **4106** | port-mirror capture 2026-04-21 |
| **Active UDP port** (missed by initial nmap — TCP only) | **43692** | port-mirror capture 2026-04-21 |
| Device model string | "HAI OmniBus Interface Translator 117A00-1 Rev 2" | HTTP GET / → static info page |
| Firmware revision | **V2.34** | HTTP GET / → static info page |
| Web UI behaviour | Serves the same 366-byte info page for every path, auto-refreshes every 60s. **No config UI.** | HTTP probe 2026-04-20 |
| Port 43690 | **OMNIBUS Software programming channel**, not Omni-Link II. HDLC-style framing `7E …payload… 7F`. Silent to the spec Omni-Link II handshake because it expects the 43690 dialect. See "OMNIBUS Software protocol (port 43690, observed)" below. | dialect_probe.py 2026-04-20 (silent), OMNIBUS SW upload/download capture 2026-04-22 (decoded) |
| Port 43694 (Bus Gateway) | Alive. Responded with ASCII `[BS012=000]\r` to arbitrary input. Not used by OmniPro II at runtime. | raw probe 2026-04-20 |
| **Port 4106 (Omni-Link II)** | **Spec-compliant Omni-Link II, fully encrypted.** Every packet has the 4-byte spec header `seq(2)+type(2)+reserved(1)` with type `0x20` (application data), AES-128 ciphertext payloads in 16/192-byte lengths. `seq=0` 20B pushes from OmniPro correlate 1:1 with lighting commands. See "4106 protocol (observed)" below. | Proxmox-host capture 2026-04-21 + decode |
| **Port 43692 (UDP broadcast)** | Translator emits 28-byte UDP frames from src port 58783 → `0.0.0.0:43692`, L2 dst `ff:ff:ff:ff:ff:ff`, in pairs ~3ms apart. Emissions correlate with state changes on the OmniPro UI. Announcement channel, format TBD. | port-mirror capture 2026-04-21 |
| Model number (Omni-Link II) | N/A — handshake never completed | — |
| Supported object types | N/A — 43690 never answered; must decode via 4106 captures | — |
| Omni-Bus unit_type | Expected 2 (Extended) — verify via 4106 decoding | PC Access shows all units as House Code Format = Extended |
| Keypads location | In Units list (not separate) | PC Access: unit 014 "6BUTTON SW6" alongside dimmers |

### 2026-04-21 — Phase 1 superseded, 4106 is the real channel

After the 43690 silence was confirmed, we set up a managed-switch port mirror
(UniFi US-8-150W, port 5 = Translator → port 3 = capture USB NIC `enxXXXXXXXXXXXX`,
Rx+Tx) and captured passively on the Proxmox host. The first 20 mirrored
unicast frames revealed a live TCP conversation we had never seen:

```
192.0.2.10.4106  > 192.0.2.11.4369  Flags [P.] length 20    (Translator → OmniPro, 20 byte push)
192.0.2.11.4369  > 192.0.2.10.4106  Flags [.]  ack          (OmniPro ack)
192.0.2.11.4369  > 192.0.2.10.4106  Flags [P.] length 196   (OmniPro → Translator, 196 byte push)
192.0.2.10.4106  > 192.0.2.11.4369  Flags [.]  ack          (Translator ack)
... repeats continuously ...
```

- Translator listens on TCP **4106** (0x100A).
- OmniPro II connects from source port **4369** (0x1111).
- TCP window 8192 on Translator side, 255 + MSS=255 advertised on OmniPro
  side (unusually small — consistent with a 2009 embedded controller).
- Chatter rate observed: roughly 5-8 exchanges per second during idle.
- **No TLS / no obvious plaintext**, so the 20B/196B payloads are binary —
  likely a poll/status pair. Wire format to be extracted from the planned
  canary-toggle capture.

**Implication:** the Omni-Link II spec at `docs/reference/` describes a
different protocol than what the Translator actually speaks in standalone
mode with Omni-Bus devices. The CRC-16/A001 and AES-128/seq-XOR modules we
built may still apply (same HAI DNA), but the framing, opcodes, and
handshake have to be rediscovered from captures.

### Capture rig (reference for next session)

- **Switch:** UniFi US-8-150W at `192.0.2.206`. SSH auth from UniFi Network
  → Settings → Control Plane → Device Authentication (username: `admin`,
  password in UniFi UI). Mirror: `(UBNT) # show monitor session 1` →
  `Probe=0/3 Src=0/5 Rx,Tx`. Translator confirmed on Port 5 via MAC table
  (`00:1E:C0:XX:XX:XX`).
- **Capture NIC:** USB-to-Ethernet `enxXXXXXXXXXXXX` (MAC `XX:XX:XX:XX:XX:XX`,
  Realtek r8152, 1000FDX) plugged into switch Port 3. Sits on Proxmox host
  bound to bridge `vmbr1` (no IP).
- **Capture command (Proxmox host, NOT inside LXC):**
  ```bash
  tcpdump -i enxXXXXXXXXXXXX -nn -s 0 \
      -w /root/captures/omnibus_<purpose>_$(date +%Y%m%d_%H%M%S).pcap \
      'host 192.0.2.10 and host 192.0.2.11'
  ```
- **Do not capture inside CT 102.** The vmbr1 Linux bridge filters mirrored
  unicast (it learns MACs from mirrored frames and then suppresses forwarding
  them to other bridge ports). The bridge still sees broadcasts, which is
  why earlier tests on `eth1` inside the LXC only caught the UDP 43692
  broadcasts — a red herring that looked like a broken mirror.

## 4106 protocol (observed)

**2026-04-21 — 4106 is Omni-Link II, fully encrypted.** The
`omnibus_toggle_20260421_220641.pcap` capture (HA-driven 10-action script:
ON/OFF pairs for units 001, 002, 015, 017, 010, 10s between each) confirms
that port 4106 speaks the spec-compliant Omni-Link II framing from
`docs/reference/Omni-Link_II_Rev_3.0.pdf`. Port 43690 was silent simply
because the Translator doesn't listen there — **4106 is the Omni-Link II
port on this device**, not a separate protocol.

### Evidence

Every packet on the established OmniPro ↔ Translator session has the
spec-described outer header:

```
  seq_hi  seq_lo  type  reserved  <payload>
  -----   -----   ----  --------  ---------
   0x25    0x49   0x20    0x00    <16B AES ciphertext>     ← 20B total
   0x25    0x4A   0x20    0x00    <192B AES ciphertext>    ← 196B total
   0x25    0x4B   0x20    0x00    <16B AES ciphertext>
   ...
```

- Sequence numbers increment by exactly 1 per outbound packet per side.
- Type `0x20` (= 32 decimal) = "Omni-Link II application data message"
  (spec Appendix A, matches PROTOCOL.md:43).
- Reserved byte is always `0x00` as spec requires.
- Payload length is always a multiple of 16 (one AES-128 block): observed
  20B (1 block) and 196B (12 blocks). Exactly what the spec's block-padded
  AES-128 + seq-XOR scheme produces.

### Traffic pattern (idle)

During idle, an endless poll loop runs:

```
  Translator → OmniPro   20B  (seq incrementing, type 0x20)     ~5-8 Hz
  OmniPro    → Translator 196B (seq incrementing, type 0x20)
```

This is almost certainly a continuous status-query loop (Translator asks
OmniPro something short, OmniPro replies with a large encrypted response).

### Command pattern (observed)

The HA script fired 10 actions at T+~11s, ~21s, ~31s, … ~101s. Every
action produced exactly one anomalous packet from OmniPro:

| T+       | Size | seq  | Pattern                                       |
|----------|------|------|-----------------------------------------------|
| 10.299s  | 20B  | **0** | `00 00 20 00 …` — out-of-band push             |
| 20.235s  | 20B  | **0** | same                                          |
| 30.619s  | 20B  | **0** | same                                          |
| 40.318s  | 20B  | **0** | same                                          |
| 50.286s  | 20B  | **0** | same                                          |
| 60.329s  | 20B  | **0** | same                                          |
| 70.291s  | 20B  | **0** | same                                          |
| 80.448s  | 20B  | **0** | same                                          |
| 90.293s  | 20B  | **0** | same                                          |
| 100.302s | 20B  | **0** | same                                          |

10 script actions → 10 `seq=0` packets, each 9.7–10.4s apart. Spec
(Appendix A) notes `seq=0` means "sequence tracking disabled" — i.e. no
reply expected. These are almost certainly **CONTROLLER COMMAND (inner
type 0x14)** writes — "turn unit N on/off". We can't confirm without
decrypting; that's the next milestone.

### Implications

- **The CRC-16/A001 and AES-128/seq-XOR modules (11/11 passing in
  `tests/test_crc.py`, `tests/test_crypto.py`) apply directly.** They are
  no longer orphaned.
- **Phase 1 is unblocked.** `tools/dialect_probe.py` now defaults to port
  4106 and should complete a session with the existing `.env` keys.
- **Passive decryption of OmniPro's session is not possible** from this
  capture — OmniPro was already mid-session when tcpdump started, so the
  session_id (established at handshake) is unknown and the session key
  cannot be derived. Decryption requires either (a) capturing a fresh
  OmniPro handshake or (b) running our own session against 4106 in
  parallel and decrypting our own traffic.

### 2026-04-21 late evening — full decryption + architecture inversion

Briefly blocked OmniPro at the UniFi switch (port 8 disable) to free the
slot so `dialect_probe.py` could complete. Connection to 4106 still
refused after block; traced to the fact that each session uses a different
ephemeral-looking port on the Translator side (4106 → 4111 after
reconnect → 4097 was a stray). Started a tcpdump, unblocked OmniPro, and
captured the full reconnect handshake in
`captures/omnibus_reconnect_20260421_225621.pcap`:

```
T+2.060s  ← Translator   4B  type=0x01  CLIENT REQ NEW SESSION
T+2.070s  → Translator  11B  type=0x02  CONTROLLER ACK: proto_ver=1, session_id=87BC60F692
T+2.097s  ← Translator  20B  type=0x03  CLIENT REQ SECURE (16B enc session_id)
T+2.141s  → Translator  20B  type=0x04  CONTROLLER ACK SECURE (identical 16B)
T+3.327s onward         ... encrypted app-data traffic (type 0x20) ...
```

**`.env` keys are correct.** Encrypting `session_id + 11×0x00` with the
derived session key and seq `0x0E9B` produced ciphertext
`74B3F36A3E8E66C5B170DF377CA9401F` — byte-identical to what's on the
wire. CRC + AES + seq-XOR + session-key derivation all work end-to-end.

### Decrypted payload findings

Every Translator→OmniPro 20B push decrypts to:

```
21 06 22 02 00 01 00 24 48 99   ← inner frame (CRC valid)
   └─ type=0x22 REQ_OBJECT_STATUS
      data = 02 00 01 00 24
             ├─ object_type = 0x02 (Unit)
             ├─ start_index = 0x0001 (1)
             └─ end_index   = 0x0024 (36)
```

Every OmniPro→Translator 196B reply decrypts to:

```
21 B6 23 02 <36 × 5-byte unit records> CRC_LO CRC_HI
   └─ type=0x23 OBJECT_STATUS
      obj_type=0x02 (Unit), 36 records × 5B each = 180B + 1B obj_type
      Records: unit_num_MSB | unit_num_LSB | status | time_MSB | time_LSB
```

Status byte of `0x01` observed for unit 18 (B2 Fan) and several others —
matches the PC Access "ON" status snapshot. Format and semantics confirm
the spec's Unit Status encoding (0=off, 1=on, 100-200 = level 0-100%).

### Role inversion — the big finding

**The Translator is the Omni-Link II *client*. OmniPro II is the
*controller*.** Evidence:

- Translator sends type-0x01 NEW SESSION REQ (spec-defined as *client →
  controller*)
- OmniPro sends type-0x02 NEW SESSION ACK (spec-defined as *controller →
  client*)
- OmniPro listens on TCP port **4369**, which is the well-known
  Omni-Link II server port for OmniPro II controllers
- The Translator's ports 4106/4111/4097 are its **ephemeral source ports**
  for the outbound TCP connection to `192.0.2.11:4369`, not listening
  ports for an incoming protocol
- Translator polls OmniPro every ~130ms for unit status; OmniPro owns the
  object model

This means `nmap`-finding "open TCP ports 43690 / 43694" on the Translator
are other services (probably the legacy server-mode Omni-Link II that's
disabled, and the OMNIBUS Software programming channel) — neither is the
runtime conduit.

### Architecture pivot

The original plan (bridge → Translator over Omni-Link II) is inverted:
we need to implement an Omni-Link II **controller** (server on
`0.0.0.0:4369`) that the Translator connects **outbound** to. Then
reconfigure the Translator to point at our bridge's IP instead of
OmniPro's `192.0.2.11`.

```
Home Assistant
    ↑ MQTT
omnibus-bridge   ← Omni-Link II controller (server on 4369)
    ↑ Omni-Link II (Translator connects outbound to us)
117A00-1 Translator   ← reconfigured to target bridge IP, not OmniPro
    ↓ Omni-Bus RS-485
Omni-Bus devices
```

Implementation work:
- Listen on `0.0.0.0:4369`, accept one Translator connection at a time
- Answer REQ_OBJECT_STATUS (0x22) with our maintained unit state table
- Answer REQ_OBJECT_PROPERTIES (0x20) with unit names/types from config
- Answer REQ_OBJECT_TYPE_CAPACITIES (0x1E) with plausible capacities
- Accept CONTROLLER COMMAND (0x14) writes — route to MQTT state changes
  published to HA (bridge updates its own table, Translator picks it up
  on next poll)
- Track session seq numbers, enforce handshake, terminate cleanly

### Known gaps remaining

- [ ] Find the "Controller IP" field in OMNIBUS Software or PC Access
      that tells the Translator where to connect
- [ ] Verify the Translator will accept our handshake if we use the same
      shared key as OmniPro (it should — the key is Translator-side config)
- [x] ~~Decrypt a session where OmniPro issues a CONTROLLER COMMAND (0x14)
      so we can see the exact byte format of a unit ON/OFF write~~ —
      **superseded**: OmniPro does not use `0x14` to drive the Translator;
      it uses unsolicited `0x3B` EXT_OBJECT_STATUS pushes with seq=0.
      See "Command/status path" below.
- [x] ~~Walk the OmniPro→Translator command path~~ — decoded below.
- [x] ~~Understand what ENABLE_NOTIFICATIONS (0x15) does~~ — the
      Translator (as the Omni-Link II client) sends `0x15` with data=`01`
      to OmniPro immediately after the handshake. This is what opts it in
      to the unsolicited `seq=0, 0x3B` status pushes.

### Command / status path (decoded 2026-04-21 late evening v2)

Fresh pcap `captures/omnibus_hs_toggle_20260421_233617.pcap` captured the
full reconnect handshake **and** six HA-triggered canary toggles (units 4,
9, 11 — each ON then OFF, ~5s apart). With per-TCP-session key derivation
in `tools/pcap_decrypt.py`, every post-handshake inner frame decrypts with
valid CRC.

**The write path is not `CONTROLLER_COMMAND (0x14)`.** OmniPro drives the
Translator via **unsolicited `EXT_OBJECT_STATUS (0x3B)` pushes with
`seq=0`** (spec's "sequence tracking disabled" marker, meaning no ACK is
expected). One push per state change. Observed timing for the six
toggles matched the operator's wall-clock sequence 1:1.

Inner frame on the wire (after outer-packet decrypt):

```
21 | 0A | 3B | <data 9B> | CRC_LO | CRC_HI
            ├── inner type = 0x3B (EXT_OBJECT_STATUS)
            └── length byte 0x0A = type(1) + data(9) = 10

data (9 bytes):
  02     07     00     <unit_lo>   <status>   00 00 00 00
  │      │      └── unit # (16-bit big-endian; high byte 0x00 for u ≤ 255)
  │      └── 0x07 — constant across all 8 captured pushes. Purpose TBD.
  │          Hypothesis: "number of following bytes" (7) = one record of
  │          7 bytes following the obj_type byte.
  └── obj_type = 0x02 (Unit)

status byte: 0x00 = OFF, 0x01 = ON  (matches ALC-style semantics)
```

Eight seq=0 pushes captured in the toggle window:

| T+       | Unit | Status | Notes                                  |
|----------|------|--------|----------------------------------------|
| 384.950s | 1    | 0 (OFF)| Post-handshake state sync (x2)         |
| 384.963s | 1    | 0 (OFF)| Duplicate 13ms after the first         |
| 451.390s | **4**| 1 (ON) | canary 004 ON                          |
| 456.469s | **4**| 0 (OFF)| canary 004 OFF                         |
| 473.067s | **9**| 1 (ON) | canary 009 ON                          |
| 479.127s | **9**| 0 (OFF)| canary 009 OFF                         |
| 485.400s | **11**|1 (ON) | canary 011 ON                          |
| 490.857s | **11**|0 (OFF)| canary 011 OFF                         |

The reverse direction — **`CONTROLLER_COMMAND (0x14)` Translator →
OmniPro** — was observed once in the same capture:

```
T+384.883s  Translator → OmniPro  seq=6  inner type=0x14
  cmd=0 (UNIT_OFF)  p1=0  p2=1
```

No seq=0 anomaly on this one; it's a normal sequenced request. the operator did
not toggle unit 1; this is almost certainly the Translator forwarding a
physical event it observed on the Omni-Bus wire (someone flipping a
switch on a wall station) upstream to OmniPro so OmniPro's state matches
reality.

### Topology, as now understood

```
         HA toggle → OmniPro ──0x3B seq=0 push──▶ Translator ──▶ Omni-Bus wire
                                                      │
                                                      │  0x22 REQ_OBJECT_STATUS  (~130ms poll)
                                                      ├───────────────────────────▶ OmniPro
                                                      ◀─── 0x23 OBJECT_STATUS ────

                                                      │ 0x14 CONTROLLER_COMMAND
  wall switch press → Omni-Bus wire → Translator ─────┴──────────────────────────▶ OmniPro
```

- **Write path (HA → light):** OmniPro pushes `0x3B seq=0` to Translator.
- **Read path (light state → HA):** Translator polls `0x22` every ~130ms;
  OmniPro replies with `0x23` carrying all 36 units' current state.
- **Physical event path (wall switch → HA):** Translator sends
  `0x14 CONTROLLER_COMMAND` upstream with `cmd=0/1 p2=unit#`. OmniPro
  updates its state model, which then propagates to HA via the usual
  OmniPro→HA integration.

### Implications for the bridge (Phase 3)

The server-side session and protocol modules now have a concrete target:

1. **Accept & complete handshake.** Type 1 → respond type 2 with our own
   random 5-byte session_id → accept type 3 → verify the decrypted
   session_id → send type 4. Per-session key = `derive_session_key(
   private_key, session_id)`. Use the same `OMNILINK_KEY1/2` the
   Translator is already provisioned with — no change on the Translator
   side.

2. **Answer `REQ_OBJECT_STATUS (0x22)` from our state table.** Reply
   with `0x23` + obj_type(0x02) + 5-byte records. Poll cadence is
   ~130ms; nothing fancy — just answer from a dict.

3. **Push state changes as `0x3B seq=0`.** When HA publishes a state
   change to MQTT, translate it to a seq=0 outer packet with inner
   frame `21 0A 3B 02 07 00 <unit_lo> <status> 00 00 00 00 CRC_LO CRC_HI`
   and send it unsolicited. No reply expected.

4. **Accept inbound `CONTROLLER_COMMAND (0x14)`.** Parse `cmd/p1/p2`,
   map `cmd 0/1` to OFF/ON for `p2` = unit #, update our state table,
   publish to MQTT so HA sees the physical switch press.

5. **Respect `ENABLE_NOTIFICATIONS (0x15)`.** The Translator will send
   this right after handshake. We can simply ACK with `0x01`; since our
   `0x3B` pushes are unconditional (we always want HA to see state), the
   flag is effectively always enabled. Still, record it so behaviour can
   be toggled later.

6. **Answer `REQ_EXT_OBJECT_STATUS (0x3A)`** with the same record format
   the Translator already accepts (9-byte data per the format above).
   Observed 3x in the reconnect capture, 0x in the toggle capture, so
   it's session-startup-only in normal operation. Implement it to
   survive the Translator's enumeration walk.

Open: what does the `0x07` marker byte mean in the 0x3B record? Since
every observed push has identical `02 07`, for now we emit that fixed
prefix when we push state changes. If the Translator refuses packets
with other values, we stick with 0x07. If it accepts variations, we can
experiment to understand its semantics.

### 2026-04-22 — Translator is silent about linked-switch LED state

When the controller pushes `0x3B seq=0` for a load (e.g. relay unit 10),
the Translator actuates the relay AND any Omni-Bus-linked wall-switch LED
via RS-485 linkage. The Translator then echoes `CONTROLLER_COMMAND cmd=0/1
p2=<load_unit>` back upstream (with coalescing: 4 rapid ON/OFF pushes
produced only 2 echoes in testing, 3s behind the pushes). **The linked
wall-switch unit's state change is never reported** — only the load unit is.
Same is true for physical wall-switch presses: the Translator reports the
load that changed, not the button that caused it.

Implication: the bridge cannot learn linked-switch state from the wire. If
HA needs to see the switch tile reflect its LED, the bridge must mirror
relay/dimmer state onto linked switch units itself, driven by a static
link map (see ROADMAP.md "Deferred — Linked-switch state mirroring").

### Observed in the reconnect capture (also confirmed in toggle capture)

- **`ENABLE_NOTIFICATIONS (0x15)` sent once by the Translator after
  handshake**, data = `01` (enable). This is the Translator opting in to
  the `0x3B seq=0` pushes — consistent with spec semantics even though
  the topology is inverted from the spec's assumed direction.
- **`REQ_OBJECT_STATUS (0x22)` parameters are always `obj_type=2,
  start=1, end=36`.** The Translator polls for exactly 36 units at a
  time. This implies the Translator's unit space is 1..36; any bridge
  implementation must be prepared to answer that full range. (Matches
  PC Access `PrincessSt_April_2026.pca`, which shows 36 unit slots
  configured under Omni-Bus.)
- **`EXT_OBJECT_STATUS (0x3B)` as REPLY** (not push, seq ≠ 0) observed
  3x in the reconnect capture. Same 9-byte record format.

### 2026-04-20 — Phase 1 blocker: port 43690 silent

The dialect probe completed TCP handshake on `192.0.2.10:43690` and sent a
spec-compliant new-session request (`seq=0 type=1 reserved=0`, 4 bytes: `00 00
01 00`). The Translator never responded within 30 seconds. Repeated with a
direct asyncio probe — same result. Port 43694 (Bus Gateway) by contrast
responds instantly with ASCII to even malformed input.

Working hypotheses (ordered by next-check cost):

1. **Omni-Link II is disabled by config.** The 117A00-1 reference manual
   section 5 is titled "HAI Omni-Link Interface Setup" — this is consistent
   with it being an opt-in feature. Likely toggled in OMNIBUS Software →
   Translator device → Setup/Network tab. **Check this next.**
2. **Translator's Omni-Link II speaks a dialect that differs from the OmniPro
   II spec.** The 117A00-1 is a bridge device, not a controller, so the
   handshake opcodes/format may differ. Would need to capture what OMNIBUS
   Software sends on 43690 when it talks to the Translator (if it ever does).
3. **43690 is intended for outbound Omni-Link II connections from the
   Translator to an external controller** (the opposite direction), not
   server-mode. TCP listeners on embedded devices are sometimes one-way
   scaffolding.

If #1 doesn't resolve it, we pivot to **Phase 2-Fallback** — the Bus Gateway
ASCII protocol on 43694. That surface is clearly alive and is the channel
OMNIBUS Software uses for everything.

## OMNIBUS Software protocol (port 43690, observed)

**2026-04-22** — captured a full OMNIBUS Software session while the operator
performed *Upload from c-bit* followed by *Download to c-bit* from the PC
at `192.0.2.21`. Pcap: `captures/omnibus_omnibusSW_20260421_235941.pcap`
(33.6 s, 2141 packets on 43690, plus 497 on the unchanged 4097↔4369
runtime channel). This resolves what 43690 actually is.

**It is not Omni-Link II and not encrypted.** It is a plaintext HDLC-style
framed programming protocol that OMNIBUS Software (the Windows config
tool) uses to upload/download the Translator's configuration database.
Orthogonal to the Omni-Link II bridge work on 4369.

### Framing

```
7E  <header>  <body>  <checksum:1B>  7F
└── start                            └── end
```

Header differs by direction:

| Direction | Header bytes | Meaning                                                      |
|-----------|--------------|--------------------------------------------------------------|
| → Translator | `03 01 12 34 <src_id:4B> <dst_id:4B>` | `03 01 12 34` = request-from-PC marker; src then dst IDs  |
| ← Translator | `00 <src_id:4B> <dst_id:4B>`          | `00` = reply-from-device marker                           |

Device IDs observed in this capture:
- `XX XX XX XX` — Translator (`192.0.2.10`)
- `XX XX XX XX` — OMNIBUS Software PC (`192.0.2.21`)

The first PC→Translator packet carries `dst_id = 00 00 00 00` until the
Translator responds with its own ID; subsequent frames use the learned
pair. Structure suggests these IDs are HAI-assigned device identifiers
(not MAC bytes — Translator MAC is `00:1E:C0:XX:XX:XX`, doesn't match).

Escape handling for `7E`/`7F` inside payloads was not needed in this
capture (body bytes happened not to collide). TBD whether there's a
byte-stuffing scheme — low risk since our Phase 3 work doesn't touch
this channel.

### Operations observed

| Op (body prefix) | Size | Count | Meaning                                             |
|------------------|------|-------|-----------------------------------------------------|
| `0E 08 08 <ot> 00 00 <page> 00` | 26B req | 97 | **Read config page**. `ot` = object type (01 = system, 02 = Units). 256B + 184B response (TCP-fragmented) carrying the page payload. |
| `0E 09 28 <ot> <page> 00 <rec> 00 60 …` | 58B req | 756 | **Write config record**. Walks `page` 00..5F × `rec` 00..07 for `ot = 02` (Units). Short ACK reply. |
| `0E 08 08 03 00 00 01 00` | 26B req | 1 | Session end / commit marker (last request before stop). |

- Upload (read) phase: T+2.24 s → T+31.29 s (97 reads of obj_type=02
  pages 0x00–0x5F).
- Download (write) phase: T+19.29 s → T+31.27 s (756 record writes).
- Phases overlap — OMNIBUS Software interleaves reads and writes.

### Key config field: controller IP+port

In one of the 256B read replies (T+4.29 s, obj_type=01 page 00, the
system/network config), at body offset 200:

```
18 04 21 08 00 07  C0 00 02 0B  11 11  01 01  C0 00 02 15  AA AA  02 00  C0 00 02 15
                   └─ 192.0.2.11 ─┘  │      └─ 192.0.2.21 ─┘  │      └─ 192.0.2.21 ─┘
                                       │                          │
                        ═══════════════╪══════════════════════════╪═════════════════════
                      controller IP+port (4369)         OMNIBUS SW PC IP+port (43690)
```

`C0 00 02 0B 11 11` is the **controller IP and port** the Translator
currently dials outbound on the runtime Omni-Link II channel. This is
the field Phase 5 needs to flip: overwrite with the bridge's IP and
(port `11 11` = 4369) to point the Translator at our bridge instead of
OmniPro II.

The second `C0 00 02 15 AA AA` triple is the OMNIBUS Software PC's
in-session identity on the 43690 channel (`192.0.2.21:43690`). Not
relevant to Phase 5.

### What this unblocks

- **Phase 5 cutover mechanism is known.** We can point the Translator at
  our bridge by writing the controller-IP record through this same
  channel (or by hand in OMNIBUS Software, which is easier for the
  one-time switch). No need to guess where the setting lives.
- **43690 "silence" in Phase 1 is explained.** The dialect probe was
  speaking Omni-Link II framing; the Translator was waiting for
  HDLC-framed OMNIBUS SW requests. Both observations are consistent.
- **No new bridge work.** We do NOT need to speak the 43690 protocol for
  the bridge itself — runtime traffic flows over Omni-Link II on 4369.
  The 43690 work is deferred until we automate the Phase 5 cutover (if
  ever; manual config flip will likely suffice).

### 43690 framing — fully decoded 2026-04-22

From `captures/omnibus_omnibusSW_20260421_235941.pcap` (upload/download,
1741 frames across 2 directions):

- **No byte stuffing.** 0/1741 frames have `0x7E`/`0x7F`/`0x7D` in the
  body. The Translator's config payloads happen to never contain these
  bytes, so naive `7E ... 7F` split works.
- **Checksum = CRC-8/MAXIM (poly `0x8C` reflected = 0x31 normal).**
  - T->PC (replies): `init=0x00, xor_out=0x00` → **98.3 %** (856/871)
  - PC->T (requests): `init=0x00, xor_out=0x00` → 0 %; **`init=0x05`** → 98.4 % (856/870)
  - The ~1.6 % miss rate per direction is TCP retransmit / framing edge
    cases that surface as off-by-one body lengths. Known acceptable.
- **Record granularity for `obj_type=02`:** each page holds 8 × 32-byte
  records. Each record is prefixed with the 3-byte magic `60 42 94`.
  96 pages × 8 records = **768 slot addresses** on the Omni-Bus wire.

### Device-enumeration dialect (List Devices feature)

From `captures/omnibus_listdevices_20260422_103628.pcap` (2 KB, captured
while OMNIBUS Software ran *List Devices*, 2026-04-22):

This is a **different conversation mode** on the same port 43690,
separate from the upload/download dialect above. The PC establishes a
short-lived TCP session, sends **2 discovery frames**, and the Translator
pushes **40 device-record frames** back unsolicited.

**Request side — exact bytes (both CRC-validated as `crc8_8C init=0x05`):**

```
#1  discovery with src=0, dst=0:
    7E 03 01 12 34 00 00 00 00 00 00 00 00 02 01 00 8B 7F

#2  broadcast enumerate:
    7E 03 01 12 34 00 00 00 00 FF FF FF FF 02 01 00 F9 7F
```

Response 1 is a 71-byte reply carrying the Translator's own 4-byte ID
and config metadata. Response 2+ (38 frames total in this capture) are
device records.

**Device record frame layout — same field positions across all three kinds:**

```
offset  bytes              meaning
------  -----------------  -------------------------------------------
0x00    00                 reply-from-device marker
0x01-4  xx xx xx xx        Omni-Bus address bytes (bus/ring/position)
0x05-8  FF FF FF FF        broadcast destination wildcard
0x09    04                 type marker
0x0A    00 or FF           (wire mode?)
0x0B-E  23 17 13 81  /     message-type quad. Distinguishes:
        21 11 10 81  /       23 17 13 81 → relay channel
        21 13 11 82  /       21 11 10 81 → 6-button wall switch
        00 27 13 23 82       21 13 11 82 → 1/2/3-button wall switch
                             00 27 13 23 82 → dimmer
0x0F    00
0x10    xx                 area / zone (1E-20 observed)
0x11    01-06              port/sub-index on the parent module
0x12    00
0x13-6  FF 00 7C FF        separator
0x17-25 <15 bytes>         NAME field, ASCII. Some characters have
                           bit 7 set as a wire-encoding artifact —
                           mask & 0x7F to decode. Nul-padded.
                           14-char effective max (Translator truncates
                           "Bathroom Pendant" → "Bathroom Penda").
0x26    xx                 UNIT NUMBER (1-36 in this system)
0x27-2D 00 00 00 00 00 00  zeros padding (also has level/state for dimmer)
0x2E    1E                 \  RELAY ONLY: 1E 5A trailer marker.
0x2F    5A                 /  Wall-switch records end at 0x2D + CRC.
                              Dimmer extends to 0x33 with level data.
end     xx                 CRC — algorithm differs from upload/download
                           dialect; not needed for read-only scanning.
```

**Record kinds — distinguished by frame length:**

| Raw bytes | Body bytes | Kind                  | Trailer | Name field |
|-----------|------------|-----------------------|---------|------------|
| 49        | 48         | Relay channel         | `1E 5A` | required (rejected if empty) |
| 47        | 46         | Wall-switch button    | none    | optional (Translator may store empty) |
| 53        | 52         | Dimmer                | none    | optional (user fills it in via OMNIBUS SW) |
| 71        | 70         | Translator (discovery) | none   | N/A — identity/network fields instead |

The Translator announces itself in two back-to-back 71B frames at the head of
each List-Devices burst (dst=`00000000`, then dst=`FFFFFFFF`). Both carry
identical identity payload — deduplicate in the scanner. Field offsets:

```
offset   4 bytes  Translator device ID     (XX XX XX XX in this system)
offset  46 4 bytes  IPv4 address           (C0 00 02 0A = 192.0.2.10)
offset  50 4 bytes  netmask                (FF FF FF 00 = /24)
offset  54 4 bytes  gateway                (C0 A8 01 01 = 192.168.1.1)
offset  58 2 bytes  listen port (big-endian u16, 0xAAAA = 43690)
```

A 6-button wall switch (e.g. `Kitchen door`) produces 6 individual records,
each at a separate unit number, all sharing the same name. A 4CH relay
module produces 4 records (one per channel), each with its own name.

**Empty relay slots** (frames with valid header + 1E 5A trailer but
all-zero name field) appear in the burst — filter them out as
unprovisioned addresses on the wire.

**Bit-7 encoding in names:** some characters in the 16-byte name field
have bit 7 set (`'o'` → `0xEF`, `'B'` → `0xC2`, etc.). Masking `& 0x7F`
recovers clean ASCII. The exact semantic of which chars get the bit set
is unclear (not strictly end-of-word, not strictly length-related); it
may be a wire-level encoding artifact carried through from the RS-485.

**Empty slots:** records with all-zero name bytes (e.g., byte `0x28`
unit number but no name) are empty unit addresses not provisioned on
the Omni-Bus wire. Filter them out when scanning.

### Still TBD on 43690 (deferred — not blocking for the scanner)

- Exact CRC algorithm for 47/49B device-enumeration records (the
  request-side CRC is confirmed, but record CRCs use a non-standard
  algorithm we haven't cracked yet)
- Full grammar of the bytes 0x01-0x16 of each record (device type
  encoding — dimmer vs relay vs keypad — likely lives in one of
  these bytes, also Omni-Bus physical address)
- Byte-stuffing rules if `7E`/`7F` ever appears in a payload
  (unobserved so far, defensive handling recommended)
