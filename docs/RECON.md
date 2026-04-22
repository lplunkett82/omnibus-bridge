# Pre-Phase-0 reconnaissance checklist

Run through this before opening Claude Code. These are things easier for a
human at a keyboard than for an AI, and the answers shape every later phase.

Translator: `192.0.2.10` (MAC `00:1E:C0:XX:XX:XX`)

---

## 1. Port scan the Translator

From your workstation (PowerShell or WSL) or any machine on the LAN:

```bash
nmap -sS -p 1-65535 -T4 192.0.2.10
```

If you don't have nmap installed, grab it from nmap.org — takes 30 seconds on
Windows.

**Record the open ports here:**

```
Open TCP ports:
  <port> — <nmap service guess>
  <port> — <nmap service guess>
```

Expected findings (from the 117A00-1 manual and community reports):

- **80 / tcp** — likely a web config page. Open it in a browser at
  `http://192.0.2.10` and screenshot whatever it shows. Don't log in
  unless you know the credentials — some Leviton gear locks out after
  failed attempts.
- **A custom TCP port** — this is the one the OmniPro II uses. Could be
  anywhere. Common suspects: 4369, 7777, 4369, 10001, 23 (telnet-style).
  This is the port we need for Phase 1.
- **USB / RS-232 are not over TCP** — ignore them for now.

## 2. Verify the hypothesis with a banner grab

For each open non-web port, try:

```bash
nc -v 192.0.2.10 <port>
```

Type nothing, just wait 5 seconds. Does it send a banner? Close it down. We're
not actually probing — we just want to see if anything is unsolicitedly sent
on connect. Record any bytes received.

## 3. Find the OmniPro II IP

Check your router's DHCP table for a device with a HAI / Leviton MAC prefix.
Common HAI OUIs:

- `00:0D:F5` (Home Automation Inc, pre-Leviton)
- `00:1E:C0` (Microchip — same as your Translator, but different device)
- `74:DA:EA` (Leviton)

Or just find it by elimination: everything on your LAN that isn't a phone,
laptop, Frigate camera, etc. Ping-sweep if needed:

```bash
nmap -sn 192.168.1.0/24
```

**OmniPro II IP:** `________________`

## 4. Confirm both boxes talk to each other

On a Linux box on the same LAN (your Proxmox host or any LXC):

```bash
sudo tcpdump -i any -nn "host 192.0.2.10 and host <omnipro_ip>" -c 20
```

Toggle a light from the OmniPro II interface. If packets appear, you've
confirmed the conversation and the ports in use are logged right there.

**Record the observed port pair(s):**

```
OmniPro <port> ↔ Translator <port>
```

This is the answer to "what port do we connect to in Phase 1." If tcpdump
shows the Translator accepting connections on e.g. port 7777, that's the
port the bridge will use too.

## 5. Proxmox network topology check

For Phase 1, the LXC running the sniffer needs to see the traffic between
OmniPro and Translator. Answer these:

- [ ] Are OmniPro, Translator, and the Proxmox host all on the same VLAN /
      subnet (192.168.1.0/24 looks like one flat network)?
- [ ] Is your Proxmox `vmbr0` bridge on the same network? (usually yes)
- [ ] Can you create an LXC that attaches to `vmbr0`?

If all yes: the sniffer LXC can just run `tcpdump` on its own interface
and will see every packet **to and from** the Translator (because
the Translator is chatting directly with it or with another host on the
bridge). Wait — actually, no, switches don't flood unicast. So:

**The important question:** does your switch support port mirroring, OR is
there a hub/dumb switch in the path, OR can you run tcpdump directly on the
Proxmox host (which sees all its own bridge traffic)?

Easiest answer for most setups: **run the sniffer on the Proxmox host itself
or in an LXC with `promisc=1`** — it sees all traffic on `vmbr0` because the
Linux bridge copies unicast to the promiscuous interface.

If your network is segmented (e.g. Translator on a separate IoT VLAN), flag
this now. The fix is typically a SPAN port on your managed switch.

## 6. Back up the OMNIBUS config — DO THIS NOW

Open OMNIBUS Software on your Windows box. Connect to the Translator. Do a
full export / save-as of the current config. This file contains:

- Every device address on the bus
- Device names and types
- Scenes
- Button-to-action bindings (link configuration)
- RF keypad pairings

Copy it to:
- Your Proxmox server
- Your PFP backup destination
- An offline USB stick

Without this file, a misfire in Phase 2 or 3 could force you to re-learn the
entire house. With it, worst case is `omnibus.exe → restore → done`.

## 7. Snapshot the OmniPro II config too

Use PC Access (HAI software) to export the OmniPro II programming. Even
though we plan to keep it running, same logic: back it up before touching
anything.

## 8. Document which lights do what

For Phase 1 testing we want 2–3 "canary" devices — lights whose state we can
freely toggle without annoying anyone. Pick them now and write their OMNIBUS
addresses here:

| Friendly name | Unit # | PC Access annotation | Type (TBD via enum) | Location    |
|---------------|--------|----------------------|----------------------|-------------|
| Bath Pendant  | 004    | (A4 / BR1-4)         | likely dimmer        | Bathroom    |
| Back Door     | 009    | (A9 / BR1-9)         | TBD                  | Back door   |
| Front Porch   | 011    | (A11 / BR1-11)       | likely dimmer        | Front porch |

Source: PC Access `PrincessSt_April_2026.pca`, Setup → Units, 2026-04-20.
All three configured as House Code Format = Extended, Address/Node ID = n/a
(flat unit index is the Omni-Link II address we'll query in Phase 1/2).

These are the lights we'll use for "turn on / capture bytes / turn off /
capture bytes" diff-testing in Phase 1 step 2.

## 9. Find the Translator encryption keys — HIGH PRIORITY

The Omni-Link II protocol uses AES-128 with a 128-bit private key. That key
is configured on the Translator as two 8-byte ("64-bit") values. Without
them, the session handshake fails and nothing else works.

Places to look, in order:

1. **The Translator's web UI** at `http://192.0.2.10`. There's usually a
   Setup or Network page that lists/configures the keys.
2. **OMNIBUS Software** on your Windows box. Open it, connect to the
   Translator, find the Translator's device entry, and look at its Setup or
   Network tab. The keys are normally visible there (sometimes labelled
   "Encryption Key 1" and "Encryption Key 2", each 16 hex characters).
3. **The OmniPro II** — if the OmniPro II is acting as the config master for
   the Translator, the keys may only be visible on its keypad under Setup
   → Network Setup.

Record them somewhere safe (password manager is fine) and also copy them to
`.env` in the repo as `OMNILINK_KEY1=...` and `OMNILINK_KEY2=...` — each
value is 16 hex characters with no separators.

**NEVER commit `.env` to git.** The `.gitignore` handles this, but be
careful.

## 10. Grab the Reference Manual if you can

Nice-to-have, not blocking. The Omni-Link II protocol spec
(`Omni-Link_II_Rev_3.0.pdf`) is the critical document for Phase 1 and we
already have that. The **117A00-1 Translator Reference Manual** would tell
us definitively what TCP port the Translator uses and confirm Omni-Link II
is supported in standalone mode — but we can discover both via nmap and the
dialect probe without it.

Try in order:
1. Leviton dealer portal (if you have login)
2. `site:archive.org "Omni-Bus Interface Translator Reference Manual"` on web.archive.org
3. Ask on Cocoontech — they are archiving this material
4. Studylib or DocPlayer (may work in-browser without download)

If found, drop it in `docs/reference/117R00-1_Rev2.pdf`.

---

## Deliverables to bring into Phase 0

Once this checklist is done, you'll have:

- Confirmed open TCP port(s) on 192.0.2.10
- OmniPro II IP
- Network topology sanity check (Proxmox can see the traffic)
- Config backups (both OMNIBUS and OmniPro II PC Access) stored offline
- 2–3 canary devices identified with OMNIBUS addresses
- **The Translator encryption keys** (two 16-hex-char values) — HARD
  requirement before Phase 1
- The Omni-Link II protocol PDF committed at
  `docs/reference/Omni-Link_II_Rev_3.0.pdf`
- Possibly: the 117A00-1 Reference Manual as bonus

Paste the port numbers and OmniPro IP into `CLAUDE.md` (the "Key hardware
identifiers" section has TBD placeholders), put the encryption keys into
`.env`, then proceed to the Phase 0 setup prompt for Claude Code.
