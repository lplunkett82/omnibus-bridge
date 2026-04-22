# Captures

Raw pcap files live in this directory and are **gitignored**
(see [.gitignore](../.gitignore) — `captures/` plus `*.pcap` / `*.pcapng`
patterns).

This index is the committed record of what each capture contains, so analysis
notes survive even when the pcap itself doesn't cross machines.

## Naming convention

```
omnibus_<purpose>_<YYYYMMDD>_<HHMMSS>.pcap
```

Examples:
- `omnibus_toggle_20260420_225400.pcap` — canary toggle session
- `omnibus_discovery_20260421_083000.pcap` — OMNIBUS Software launching

## Format of each index entry

For every capture, add an entry to the table below:

- **Capture file** — filename (gitignored, not on GitHub)
- **Date/time** — wall-clock of the session start
- **Capture host** — where tcpdump ran (LXC name, Proxmox host, etc.)
- **Filter** — the tcpdump BPF filter used
- **Trigger log** — T-relative seconds and action, tightly correlated with the
  narration captured during the session

## Sessions

### 2026-04-22 — OMNIBUS Software upload + download session

| Field | Value |
|-------|-------|
| Capture file | `omnibus_omnibusSW_20260421_235941.pcap` (local only, gitignored) |
| Capture host | Proxmox host (interface `enxXXXXXXXXXXXX`) |
| Filter | `host 192.0.2.10` (broadened to catch OMNIBUS SW PC traffic too) |
| OMNIBUS Software PC | 192.0.2.21 (new to the project, source port 28139) |
| Packets | 2641 total — 2141 on port 43690 (OMNIBUS SW ↔ Translator), 497 on 4097↔4369 (unchanged runtime) |
| Duration | 33.6 s |
| Trigger | The operator ran *Upload from c-bit* then *Download to c-bit* in OMNIBUS Software |

**Outcome:** decoded the 43690 protocol framing + operations and located
the controller-IP config field that Phase 5 needs to flip. See
[docs/PROTOCOL.md](../docs/PROTOCOL.md) → "OMNIBUS Software protocol
(port 43690, observed)".

### 2026-04-21 — first 4106 toggle capture (planned, rig live)

| Field | Value |
|-------|-------|
| Capture file | `omnibus_toggle_<ts>.pcap` — TBD once captured |
| Capture host | **Proxmox host** (not inside LXC — bridge filters mirrored unicast) |
| Capture interface | `enxXXXXXXXXXXXX` (USB-to-Ethernet on UniFi switch port 3, mirror dest for port 5) |
| Filter | `host 192.0.2.10 and host 192.0.2.11` (catches the whole 4106/4369 conversation) |
| OmniPro II IP | 192.0.2.11 |
| Translator IP | 192.0.2.10 |
| Expected ports | TCP 4106 (Translator) ↔ 4369 (OmniPro), UDP 43692 broadcasts |
| Canaries | 004 Bath Pendant, 009 Back Door |

Capture command (run on Proxmox host):

```bash
mkdir -p /root/captures
tcpdump -i enxXXXXXXXXXXXX -nn -s 0 \
  -w /root/captures/omnibus_toggle_$(date +%Y%m%d_%H%M%S).pcap \
  'host 192.0.2.10 and host 192.0.2.11'
```

Trigger log (fill in at capture time):

| T+(s) | Action | Wall-clock |
|-------|--------|------------|
| 0     | Capture start | |
| 10    | Idle baseline | |
| 20    | Query status of unit 004 from OmniPro UI | |
| 30    | Idle | |
| 40    | Unit 004 ON from OmniPro UI | |
| 50    | Idle | |
| 60    | Unit 004 OFF from OmniPro UI | |
| 70    | Idle | |
| 80    | Unit 009 ON then OFF from OmniPro UI | |
| 90    | Capture stop (Ctrl-C) | |

After capture:

```bash
# on Proxmox host
ls -lh /root/captures/
# then scp to Windows repo
scp /root/captures/omnibus_toggle_*.pcap \
    user@<workstation>:/path/to/omnibus-bridge/captures/
```
