#!/usr/bin/env python3
"""
ids.py - a small, passive network intrusion detector

Sits on an interface, watches TCP traffic go by and flags a few
classic recon/attack patterns:

    - SYN scan     -> one source hammering many ports very fast
    - port scan    -> one source probing lots of distinct ports
                       (same idea as above but caught over a longer
                       window, so slower/stealthier scans get picked
                       up too)
    - SYN flood    -> a destination getting buried in half-open
                       connections

This is NOT meant to compete with Snort/Suricata. It's a learning
project to understand what those tools are actually doing under the
hood - simple counters and sliding time windows, nothing fancier.

Usage:
    sudo python3 ids.py -i eth0
    sudo python3 ids.py -i wlan0 --log alerts.log

Needs root (or CAP_NET_RAW) because scapy is doing raw packet capture.
"""

import argparse
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import sniff, IP, TCP

# ---------------------------------------------------------------------------
# tunables - these are just what worked ok in my own testing on a home
# network, will probably need retuning on anything with real traffic
# ---------------------------------------------------------------------------

SYN_SCAN_WINDOW = 3          # seconds
SYN_SCAN_THRESHOLD = 20      # syn packets from one src inside that window

PORT_SCAN_WINDOW = 10         # seconds, longer window catches slower scans
PORT_SCAN_PORT_THRESHOLD = 15  # distinct dst ports touched by one src

FLOOD_WINDOW = 2             # seconds
FLOOD_THRESHOLD = 120        # syn packets aimed at one dst:port

ALERT_COOLDOWN = 15          # don't re-fire the same alert more than this often

STATS_INTERVAL = 30          # print a quick summary every N seconds


class Detector:
    def __init__(self, log_path):
        self.log_path = log_path

        # per-source-ip timestamps, used for the syn-scan (fast) check
        self.syn_times_by_src = defaultdict(deque)

        # per-source-ip -> {port: last_seen_ts}, used for port-scan check
        self.ports_by_src = defaultdict(dict)

        # per (dst_ip, dst_port) -> deque of timestamps, for flood check
        self.syn_times_by_dst = defaultdict(deque)

        self.last_alert = {}  # (alert_type, key) -> last fired time

        self.total_packets = 0
        self.total_syn = 0
        self.alert_count = 0
        self.start_time = time.time()

        # crude "top talkers" counter, just for the stats printout
        self.packets_by_src = defaultdict(int)

        try:
            self.log_file = open(self.log_path, "a")
        except OSError as e:
            print(f"couldn't open log file {self.log_path}: {e}")
            sys.exit(1)

    # -----------------------------------------------------------------
    def handle_packet(self, pkt):
        if IP not in pkt or TCP not in pkt:
            return

        self.total_packets += 1
        ip = pkt[IP]
        tcp = pkt[TCP]
        src = ip.src
        dst = ip.dst
        dport = tcp.dport
        now = time.time()

        self.packets_by_src[src] += 1

        # a "pure" syn: SYN flag set, ACK flag not set. this is what a
        # scanner sends when it's probing, as opposed to the SYN-ACK
        # a real server sends back
        flags = tcp.flags
        is_syn = bool(flags & 0x02) and not bool(flags & 0x10)

        if not is_syn:
            return

        self.total_syn += 1
        self._check_syn_scan(src, now)
        self._check_port_scan(src, dport, now)
        self._check_syn_flood(dst, dport, now)

    # -----------------------------------------------------------------
    def _check_syn_scan(self, src, now):
        dq = self.syn_times_by_src[src]
        dq.append(now)
        cutoff = now - SYN_SCAN_WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= SYN_SCAN_THRESHOLD:
            self._fire("SYN_SCAN", src,
                       f"{len(dq)} SYNs from {src} in under {SYN_SCAN_WINDOW}s "
                       f"- looks like a fast port scan (nmap -sS style)")

    def _check_port_scan(self, src, dport, now):
        ports = self.ports_by_src[src]
        ports[dport] = now

        # prune ports we haven't seen touched recently, otherwise this
        # dict just grows forever for a chatty client
        cutoff = now - PORT_SCAN_WINDOW
        stale = [p for p, t in ports.items() if t < cutoff]
        for p in stale:
            del ports[p]

        if len(ports) >= PORT_SCAN_PORT_THRESHOLD:
            self._fire("PORT_SCAN", src,
                       f"{src} has touched {len(ports)} distinct ports in the "
                       f"last {PORT_SCAN_WINDOW}s")

    def _check_syn_flood(self, dst, dport, now):
        key = (dst, dport)
        dq = self.syn_times_by_dst[key]
        dq.append(now)
        cutoff = now - FLOOD_WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= FLOOD_THRESHOLD:
            self._fire("SYN_FLOOD", f"{dst}:{dport}",
                       f"{len(dq)} SYNs hit {dst}:{dport} in {FLOOD_WINDOW}s "
                       f"- possible SYN flood")

    # -----------------------------------------------------------------
    def _fire(self, alert_type, key, message):
        cooldown_key = (alert_type, key)
        now = time.time()
        last = self.last_alert.get(cooldown_key, 0)
        if now - last < ALERT_COOLDOWN:
            return  # already warned about this recently, skip

        self.last_alert[cooldown_key] = now
        self.alert_count += 1

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {alert_type}: {message}"
        print(f"!! {line}")
        self.log_file.write(line + "\n")
        self.log_file.flush()

    # -----------------------------------------------------------------
    def print_stats(self):
        uptime = int(time.time() - self.start_time)
        print(f"\n--- stats @ {uptime}s uptime ---")
        print(f"packets seen: {self.total_packets}  (syn: {self.total_syn})")
        print(f"alerts fired: {self.alert_count}")

        top = sorted(self.packets_by_src.items(), key=lambda x: x[1], reverse=True)[:5]
        if top:
            print("top talkers:")
            for ip, count in top:
                print(f"    {ip:<16} {count}")
        print("---------------------------------\n")


def main():
    parser = argparse.ArgumentParser(description="tiny passive IDS for SYN scans / port scans / SYN floods")
    parser.add_argument("-i", "--iface", default=None, help="interface to sniff on (default: scapy picks one)")
    parser.add_argument("--log", default="alerts.log", help="file to write alerts to")
    parser.add_argument("--no-stats", action="store_true", help="don't print periodic stats")
    args = parser.parse_args()

    detector = Detector(args.log)
    print(f"listening on {args.iface or 'default interface'}, logging alerts to {args.log}")
    print("ctrl+c to stop\n")

    last_stats_time = time.time()

    def on_packet(pkt):
        nonlocal last_stats_time
        detector.handle_packet(pkt)
        if not args.no_stats and time.time() - last_stats_time > STATS_INTERVAL:
            detector.print_stats()
            last_stats_time = time.time()

    try:
        sniff(iface=args.iface, filter="tcp", prn=on_packet, store=False)
    except PermissionError:
        print("permission denied - try running with sudo")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        print("\nshutting down, final stats:")
        detector.print_stats()
        detector.log_file.close()


if __name__ == "__main__":
    main()
