"""
tests for the detection logic in ids.py

instead of actually sniffing traffic (which needs root + a real
interface), we just build packets in memory with scapy and feed them
straight into Detector.handle_packet. that's the part that actually
matters - the sniff() call is just plumbing.
"""

import time
import tempfile
import os

from scapy.all import IP, TCP

from ids import Detector, SYN_SCAN_THRESHOLD, PORT_SCAN_PORT_THRESHOLD, FLOOD_THRESHOLD


def make_syn(src, dst, dport, sport=12345):
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")


def make_synack(src, dst, dport, sport=12345):
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="SA")


def new_detector():
    # write the log somewhere throwaway so tests don't leave junk around
    fd, path = tempfile.mkstemp()
    os.close(fd)
    return Detector(path)


def test_normal_traffic_does_not_alert():
    d = new_detector()
    pkt = make_syn("10.0.0.5", "10.0.0.1", 80)
    d.handle_packet(pkt)
    d.handle_packet(make_synack("10.0.0.1", "10.0.0.5", 12345))
    assert d.alert_count == 0


def test_non_tcp_packets_are_ignored():
    d = new_detector()
    # a plain IP packet with no TCP layer shouldn't blow anything up
    d.handle_packet(IP(src="1.2.3.4", dst="5.6.7.8"))
    assert d.total_packets == 0


def test_syn_ack_is_not_counted_as_scan_traffic():
    d = new_detector()
    for i in range(SYN_SCAN_THRESHOLD + 5):
        d.handle_packet(make_synack("10.0.0.5", "10.0.0.1", 1000 + i))
    assert d.total_syn == 0
    assert d.alert_count == 0


def test_syn_scan_triggers_after_threshold():
    d = new_detector()
    attacker = "192.168.1.50"
    victim = "192.168.1.1"

    # same port every time so this only trips the syn-scan (rate) check
    # and not the port-scan (distinct ports) check as a side effect
    for i in range(SYN_SCAN_THRESHOLD - 1):
        d.handle_packet(make_syn(attacker, victim, 80))
    assert d.alert_count == 0

    # one more pushes it over
    d.handle_packet(make_syn(attacker, victim, 80))
    assert d.alert_count == 1


def test_port_scan_uses_distinct_ports_not_packet_count():
    d = new_detector()
    attacker = "192.168.1.77"
    victim = "192.168.1.1"

    # hammer the SAME port a bunch of times - should not look like a
    # port scan even though the packet count is high, because it's
    # only ever one port
    for _ in range(PORT_SCAN_PORT_THRESHOLD + 10):
        d.handle_packet(make_syn(attacker, victim, 443))
        time.sleep(0.001)

    port_scan_alerts = [k for k in d.last_alert if k[0] == "PORT_SCAN"]
    assert len(port_scan_alerts) == 0


def test_port_scan_triggers_on_many_distinct_ports():
    d = new_detector()
    attacker = "192.168.1.77"
    victim = "192.168.1.1"

    for port in range(PORT_SCAN_PORT_THRESHOLD + 3):
        d.handle_packet(make_syn(attacker, victim, 2000 + port))

    port_scan_alerts = [k for k in d.last_alert if k[0] == "PORT_SCAN"]
    assert len(port_scan_alerts) == 1


def test_syn_flood_triggers_from_multiple_sources_at_one_target():
    d = new_detector()
    victim = "10.0.0.1"

    # a flood is usually spoofed/distributed sources hitting one
    # dst:port, so simulate that instead of a single attacker
    for i in range(FLOOD_THRESHOLD + 5):
        fake_src = f"10.1.{i % 200}.{i % 250}"
        d.handle_packet(make_syn(fake_src, victim, 80))

    flood_alerts = [k for k in d.last_alert if k[0] == "SYN_FLOOD"]
    assert len(flood_alerts) == 1


def test_alert_cooldown_prevents_spam():
    d = new_detector()
    attacker = "10.0.0.9"
    victim = "10.0.0.1"

    for i in range(SYN_SCAN_THRESHOLD + 20):
        d.handle_packet(make_syn(attacker, victim, 80))

    # no matter how far over the threshold we go, cooldown should
    # keep this from firing more than once in the same test run
    assert d.alert_count == 1
