# network-ids

A small passive intrusion detection tool written in Python. It watches TCP
traffic on an interface and flags three common patterns:

- **SYN scan** - one host sending SYNs really fast (the default behaviour of
  tools like `nmap -sS`)
- **Port scan** - one host probing a lot of distinct ports over a longer
  window (catches slower/stealthier scans that don't trip the rate-based
  check)
- **SYN flood** - a target getting buried in half-open connections

This started as a "how would I actually detect a port scan" question for
myself, so it's intentionally simple - sliding time windows and counters,
no ML, no signature database. Real tools (Snort, Suricata, Zeek) do this
with a lot more sophistication, but the core idea is the same.

## How detection works

Every incoming TCP packet with the SYN flag set (and ACK *not* set - so we
don't count normal SYN-ACK replies) gets checked against three sliding
windows:

1. How many SYNs has this source sent in the last `SYN_SCAN_WINDOW`
   seconds? Too many -> SYN scan.
2. How many *distinct destination ports* has this source touched in the
   last `PORT_SCAN_WINDOW` seconds? Too many -> port scan. This is
   separate from #1 because a slow scanner (one port every couple seconds)
   won't trip the rate check but will still rack up distinct ports over
   time.
3. How many SYNs has a given `dst_ip:dst_port` received in the last
   `FLOOD_WINDOW` seconds, regardless of source? Too many -> SYN flood.

Alerts have a cooldown (15s by default) per (type, key) so one ongoing
scan doesn't spam the log with a hundred lines a second.

## Running it

```bash
pip install -r requirements.txt

sudo python3 ids.py -i eth0
```

Needs root because scapy is doing raw socket capture. Alerts get printed
to stdout and appended to `alerts.log`. Every 30 seconds it also prints a
quick summary (packet counts, alert counts, top talkers by packet count).

### Trying it against yourself

If you don't have a second machine handy, you can generate traffic that
trips the detectors from the same box (in a VM/container, don't do this on
a network you don't control):

```bash
sudo python3 ids.py -i lo &
nmap -sS -T4 127.0.0.1 -p 1-500
```

You should see PORT_SCAN and/or SYN_SCAN alerts show up depending on how
fast nmap fires.

## Tests

```bash
pip install pytest
pytest test_ids.py -v
```

The tests craft packets directly with scapy and feed them into
`Detector.handle_packet()` rather than actually sniffing - no root or
real interface needed to run the suite.

## Known limitations / things I'd do differently with more time

- Thresholds are hardcoded constants tuned by eyeballing my own traffic,
  not anything principled. On a busier network they'd need retuning or a
  more adaptive approach (baseline + deviation instead of a fixed number).
- No IPv6 support right now, only IPv4.
- SYN flood detection doesn't try to distinguish spoofed source IPs from a
  legitimately busy server - a popular web server could plausibly trip it
  under a traffic spike, not just an actual attack.
- Everything's in-memory, so a restart loses all history. Fine for a demo,
  not fine for anything long-running.
- No allowlisting - a NAT gateway or another local scanner (Nessus, etc.)
  running "for real" reasons would get flagged same as an attacker.
# IDS


# Architecture

```text
Network Interface
 -> Scapy Sniffer -> Packet Parser -> Detection Engine
 -> {SYN Scan | Port Scan | SYN Flood} -> Alert Manager -> Console/alerts.log
```

## Detection Algorithms

|Detector|Method|Complexity|
|---|---|---|
|SYN Scan|Sliding window deque|Amortized O(1)|
|Port Scan|Hash map of ports|Average O(1)|
|SYN Flood|Sliding window|Amortized O(1)|

## Design Decisions
- Sliding windows prevent stale traffic.
- Ignore SYN-ACK packets to reduce false positives.
- Alert cooldown prevents log spam.
- Separate SYN-rate and distinct-port detection.

## Future Improvements (Planned)
### Engineering
- Configurable thresholds (JSON/YAML).
- Structured JSON logging.
- Severity levels.
- Live dashboard.
- IPv6 support.
- Allowlisting.
- Persistent storage.
- Mininet-based testing.

### Machine Learning Extension
Current version is intentionally rule-based.

Packets
    │
    ▼
Scapy Sniffer
    │
    ▼
Packet Parser
    │
    ▼
Detection Engine
    │
 ┌──┴───────────────┐
 │                  │
SYN Scan       Port Scan
 │                  │
 └──────┬───────────┘
        ▼
 Alert Manager
        ▼
 alerts.log

Potential datasets: CICIDS2017, UNSW-NB15, CICDDoS2019.
