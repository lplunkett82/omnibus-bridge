# Bugs & quirks

## 2026-04-27/28 — phantom relay activations after silent TCP reconnect

**Symptom:** relays switch on without any HA automation or wall-switch
press. Originally observed on the pve install as morning hallway lights
(units 13 "Hall Floor", 15 "Hall Pendant") between roughly 05:30 and
08:30 local time. After migration to CT 103 the rate dropped ~50× but
the issue persists at lower frequency: bedroom pendant (unit 8 "B1
Pendant") came on at 02:12 AEST on 2026-04-28.

**Mechanism (confirmed 2026-04-28):** every observed phantom-on tracks
1:1 with the sequence
`silent disconnect → Translator reconnect → handshake complete →
~4 s later, Translator pushes a CONTROLLER_COMMAND burst that includes
cmd=1 for at least one relay`. The relay physically actuates as part of
that burst and stays on until something (HA automation, the user, a
wall-switch press) turns it off again.

The 2026-04-28 event in `/root/omnibus-bridge/bridge.log` is the
clearest example:

```
16:12:13 translator disconnected: 192.168.1.30:4102      ← silent TCP timeout
16:12:51 translator connected:    192.168.1.30:4097
16:12:53 handshake complete (session_id=7ECD0D0EA6)
16:12:57 physical event: cmd=1 p2=13 (Hall Floor)        ┐
16:12:57 physical event: cmd=1 p2=15 (Hall Pendant)      │ post-reconnect burst
16:12:57 physical event: cmd=1 p2=8  (B1 Pendant)        │
16:12:57 physical event: cmd=0 p2=13 (Hall Floor)        │
16:12:57 physical event: cmd=0 p2=15 (Hall Pendant)      ┘
16:13:20 cmd=0 p2=8 + p2=27 (paired = wall-switch off press)
```

Hall Floor and Hall Pendant got ON-then-OFF in the same second
(harmless). B1 Pendant got ON only — physically energised, stayed on
for 23 s until the user flipped the wall switch.

**Underlying TCP cause (confirmed):** the silent disconnect is the
bridge's SO_KEEPALIVE probes timing out (kernel `ETIMEDOUT`, raised as
`TimeoutError`). The read loop in [transport.py](../src/omnibus_bridge/transport.py)
originally caught `ConnectionError` but not `TimeoutError` — they're
sibling subclasses of `OSError`, not parent/child — so the exception
bubbled to the generic handler and logged as `ERROR` + traceback. Fix
in commit `3f7e7c3` (2026-04-27) added `TimeoutError` to the catch.
This is **purely cosmetic**: it cleans up the log signature but does
NOT prevent the disconnect, the burst, or the phantom actuation. The
TCP blip itself appears to be a real network-path artifact (~30/4d on
pve, ~1-2/day on CT 103) and may not be eliminable from the bridge
side.

**Why the burst contains `cmd=1` is not yet proven.** Three candidate
mechanisms, ordered by next-check cost:

1. The bridge's state-restore on handshake-complete is sending
   `0x3B seq=0` with stale ON values from a previous session, and the
   Translator is faithfully obeying.
2. The Translator unilaterally actuates relays during the disconnect
   window and reports the resulting state on reconnect — independent
   of anything the bridge does.
3. Race between the bridge's post-handshake state push and the
   Translator's own poll cadence leaves a window in which the
   Translator's view is authoritative and disagrees with ours.

A continuous packet capture is running on the pve host (rolling 72×1h,
filter `host 192.168.1.30 and host 192.168.1.36`, see
`/root/captures/ROLLING_README.txt`) so the next phantom-on can be
decrypted byte-for-byte. The decrypted handshake + immediately-following
seconds will show whether the burst is bridge-originated `0x3B` or
Translator-originated `0x14`, which determines whether the fix lives in
the bridge or has to be a defensive layer (post-handshake state
reassertion + reconnect-grace-period filter on inbound `cmd=1`).

**Earlier-claim correction:** an earlier version of this note (2026-04-27)
stated the LXC migration alone "fixed the user-visible symptom". The
2026-04-28 02:12 AEST event disproves that. The migration reduced rate
(~50×) but did not eliminate the mechanism.

## 2026-04-21 — nmap SYN scan missed the live protocol port (4106)

Initial reconnaissance ran `nmap -sS -p 1-65535 192.0.2.10` (2026-04-20)
and reported **80, 43690, 43694** as the only open TCP ports. We spent the
next day assuming the Translator's runtime protocol had to be on one of
those. It wasn't. Port **4106** is the actual live channel — the OmniPro II
keeps a long-lived TCP session open to `192.0.2.10:4106` from its own
ephemeral port 4369, and that session was already established when nmap
ran. SYN scans don't surface ports that are busy with an established TCP
session; the SYN to an already-accepting socket may go to an in-use queue
and not come back as an advertised open port.

Lessons:
- `nmap -sS` is not authoritative on a live embedded device. Re-run with
  `-sT` or, better, a full passive capture to see what's actually talking.
- Always correlate against a MAC-table dump on the switch: if we'd looked
  at the Translator's switch port early, we would have seen sustained
  TCP 4106/4369 traffic and skipped the spec rabbit hole.

## 2026-04-21 — Linux bridge filters mirrored unicast (vmbr1 inside capture LXC)

The capture LXC (CT 102, `192.0.2.305`) has a second NIC `eth1` attached to
a silent Proxmox bridge `vmbr1` bound to the USB-to-Ethernet capture adapter.
When the UniFi switch began delivering mirrored frames to the USB NIC, the
Linux bridge on the host **learned the source MACs (Translator, OmniPro,
etc.) as living on the USB-NIC port** and then suppressed forwarding those
frames across the bridge — standard same-port-flood-prevention. Inside the
LXC, `tcpdump -i eth1` only caught L2 broadcasts (which flood regardless)
and not the unicast TCP we actually needed. It looked exactly like a broken
port mirror but was the bridge doing its job.

**Workaround:** capture on the Proxmox host directly against the USB NIC
(`tcpdump -i enxXXXXXXXXXXXX`), not inside the LXC. The LXC is still useful
as an isolated workspace (tshark, analysis) but not as the capture sink.

Avenues not yet tried (if LXC capture ever becomes necessary):
- Pass the USB NIC into the LXC as a device (no bridge), so the LXC sees the
  raw mirror stream with no same-port filtering
- Disable MAC learning on `vmbr1` (`brctl setageing vmbr1 0` isn't quite
  right — look at `bridge link set dev <veth> learning off` per-port)
- Use an `ebtables -t broute` DROP rule that forces frames into `PREROUTING`
  before forwarding decisions

## 2026-04-20 — Port 43690 silent to Omni-Link II handshake

The Translator (117A00-1 Rev 2, firmware V2.34) accepts TCP connections on
port 43690 but does not respond to the spec-compliant new-session request
(`seq=0 type=1 reserved=0`, bytes `00 00 01 00`) for at least 30 seconds.
Verified with both `tools/dialect_probe.py` and a direct raw asyncio probe.

Hypotheses (see [PROTOCOL.md](PROTOCOL.md) "Live device behaviour"):
1. Omni-Link II is disabled in Translator config
2. The Translator uses a different handshake dialect than OmniPro II
3. Port 43690 is for outbound-from-Translator traffic, not server-mode

Workaround: pivoting to Bus Gateway protocol on 43694 (Phase 2-Fallback).

## 2026-04-20 — Bus Gateway (port 43694) non-deterministic under fuzzing

Sending arbitrary bytes to 43694 produces `[BS###=VVV]\r`-style responses but
the mapping from input to `###` is not deterministic across probes. First
run: `\x01` → `BS001`, `\x01\x00` → `BS002`, `\x00\x00\x01` → `BS003`. Second
run: most of the same payloads produce no response, `\x00\x01` → `BS004`,
`8×\x00` → `BS012`, `9×\x00` → `BS013`.

Best guess: the Translator maintains per-source-IP state on 43694 AND
OmniPro II is concurrently driving the same channel. Our probes interleave
with legitimate traffic and observe a shared queue we don't control.

Implication for reverse engineering: **don't fuzz 43694**. Capture legitimate
OmniPro ↔ Translator traffic passively instead. See
[ROADMAP.md](ROADMAP.md) Phase 2-Fallback.

## 2026-04-20 — HTTP on port 80 has no config UI

The Translator's web server returns the same 366-byte static info page for
every path requested (`/`, `/setup.html`, `/network.html`, etc.), with a 60s
auto-refresh meta. Useful only as a model/firmware identifier. Do not expect
to configure the Translator via browser.
