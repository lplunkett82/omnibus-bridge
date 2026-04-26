# Bugs & quirks

## 2026-04-27 — phantom hallway-light morning activations on pve install

**Symptom:** for several mornings while the bridge ran on the Proxmox host
directly (`/root/omnibus-bridge-v2/`), the hallway relays (units 13 "Hall
Floor" and 15 "Hall Pendant") would switch on between roughly 05:30 and
08:30 local time without any HA automation or wall-switch press. User
manually cleared them from HA each time (e.g. 06:22 OFF push observed in
the old bridge log on 2026-04-25).

**Cause (confirmed):** the read loop in
[transport.py](../src/omnibus_bridge/transport.py) was catching
`ConnectionError` but not `TimeoutError`. When SO_KEEPALIVE probes
failed (kernel returns `ETIMEDOUT`, raised as `TimeoutError`, NOT a
`ConnectionError` — they're sibling subclasses of `OSError`), the
exception bubbled to the generic `except Exception` and was logged as
ERROR with a traceback. Functionally the session still recovered: the
Translator reconnected within seconds and rehandshook.

**Mechanism (hypothesis, not proven):** the morning phantom-on
correlates strongly with reconnect events but the exact path by which a
reconnect leaves a hallway relay physically energised wasn't isolated.
Working theory is that on a non-trivial fraction of reconnects, the
post-handshake state push from the bridge and the Translator's own poll
cadence get out of order, leaving the Translator with stale "on" state
for the relay until the next push lands. Worth captures-driven
investigation if it ever recurs.

The pve install averaged ~30 such reconnects per 4 days, with morning
clusters in the 05–09 window. After the 2026-04-26 migration to CT 103,
reconnect rate dropped ~50× (1 reconnect in the first 20 h, recovered
cleanly), and morning phantoms stopped — the new LXC's network path is
materially quieter. Migration alone fixed the user-visible symptom.

**Fix:** add `TimeoutError` to the read-loop's expected-disconnect
exceptions so silent-peer keepalive timeouts log at INFO ("translator
disconnected") instead of an ERROR + traceback. Doesn't change recovery
behaviour, but stops the noisy log signature and removes one source of
false-alarm triage. Cosmetic but worth keeping clean now that the
underlying instability is gone.

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
