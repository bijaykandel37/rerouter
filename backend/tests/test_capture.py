import socket
import struct

from rerouter.collectors.capture import (FlowTable, PacketCapture, parse_dns_answers,
                                         parse_packet)
from tests.test_dpi import build_client_hello


def eth_ipv4_udp(src, dst, sport, dport, payload=b""):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + iph + udp


def eth_ipv4_tcp(src, dst, sport, dport, payload=b"", flags=0x18):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 0xFFFF, 0, 0) + payload
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + iph + tcp


class _CapSink:
    def __init__(self):
        self.names = {}

    def submit(self, records):
        pass

    def learn_names(self, mapping, source):
        self.names.update(mapping)


def dns_response(name, ips):
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    msg = struct.pack("!HHHHHH", 1, 0x8180, 1, len(ips), 0, 0) + qname + struct.pack("!HH", 1, 1)
    for addr in ips:
        msg += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(addr)
    return msg


def test_parse_udp_packet():
    src, dst, sport, dport, proto, size, flags, payload = parse_packet(
        eth_ipv4_udp("192.168.1.5", "1.1.1.1", 5555, 53, b"abc"))
    assert (src, dst, sport, dport, proto) == ("192.168.1.5", "1.1.1.1", 5555, 53, 17)
    assert size == 20 + 8 + 3 and payload == b"abc"


def test_vlan_tagged_frame():
    frame = eth_ipv4_udp("10.0.0.1", "10.0.0.2", 1, 2)
    tagged = frame[:12] + b"\x81\x00\x00\x0a" + frame[12:]
    assert parse_packet(tagged)[:2] == ("10.0.0.1", "10.0.0.2")


def test_dns_answers_mapped_to_query_name():
    assert parse_dns_answers(dns_response("example.com", ["93.184.216.34", "93.184.216.35"])) == {
        "93.184.216.34": "example.com", "93.184.216.35": "example.com"}


def test_flow_table_expiry():
    t = FlowTable()
    key = ("a", "b", 1, 2, 6)
    t.add(key, 100, 0x02, 1000.0)
    t.add(key, 50, 0x10, 1005.0)
    assert t.expire(1010.0) == []
    [f] = t.expire(1021.0)
    assert f.bytes == 150 and f.packets == 2 and f.tcp_flags == 0x12


def test_capture_extracts_sni_and_fingerprint():
    cap = PacketCapture(_CapSink(), "lo")
    hello = build_client_hello("telemetry.example.net")
    frame = eth_ipv4_tcp("192.168.1.50", "93.184.216.34", 51000, 443, hello)
    cap._handle(frame, 1000.0)
    # idle-expire the flow and inspect the record it produced
    [rec] = cap.table.expire(1000.0, force=True)
    assert rec.host == "telemetry.example.net"
    assert rec.fingerprint and len(rec.fingerprint) == 32
    assert rec.tls_version == "TLS 1.2"
    assert cap.sink.names["93.184.216.34"] == "telemetry.example.net"
    assert cap.l7_seen == 1


def test_capture_http_host():
    cap = PacketCapture(_CapSink(), "lo")
    frame = eth_ipv4_tcp("192.168.1.51", "10.0.0.9", 52000, 80,
                         b"GET / HTTP/1.1\r\nHost: printer.lan\r\n\r\n")
    cap._handle(frame, 1000.0)
    [rec] = cap.table.expire(1000.0, force=True)
    assert rec.host == "printer.lan"
    assert rec.fingerprint is None  # plaintext HTTP has no TLS fingerprint


def test_capture_gives_up_l7_after_max_tries():
    cap = PacketCapture(_CapSink(), "lo")
    key = ("192.168.1.9", "1.2.3.4", 5000, 443, 6)
    for _ in range(10):
        cap.table.add(key, 100, 0x10, 1000.0)
        cap._inspect(cap.table.flows[key], b"not a handshake", "1.2.3.4")
    assert cap.table.flows[key][5]["tries"] <= 5
