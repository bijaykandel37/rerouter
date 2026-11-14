import socket
import struct

from rerouter.collectors.netflow import NetflowParser


def ip(s):
    return socket.inet_aton(s)


def test_v5():
    hdr = struct.pack("!HHIIIIBBH", 5, 1, 100_000, 1_700_000_000, 0, 1, 0, 0, 0)
    rec = struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", ip("192.168.1.2"), ip("8.8.8.8"),
                      ip("0.0.0.0"), 1, 2, 10, 1500, 90_000, 99_000, 5353, 53, 0, 0x18, 17, 0,
                      0, 0, 24, 0, 0)
    [f] = NetflowParser().parse(hdr + rec, "10.0.0.1")
    assert (f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.proto) == (
        "192.168.1.2", "8.8.8.8", 5353, 53, 17)
    assert f.bytes == 1500 and f.packets == 10
    assert f.ts_end == 1_700_000_000 - 1.0 and f.ts_start == 1_700_000_000 - 10.0


def test_v5_sampling_scales_counts():
    hdr = struct.pack("!HHIIIIBBH", 5, 1, 0, 1_700_000_000, 0, 1, 0, 0, (1 << 14) | 100)
    rec = struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", ip("1.1.1.1"), ip("2.2.2.2"), ip("0.0.0.0"),
                      0, 0, 1, 64, 0, 0, 1, 2, 0, 0, 6, 0, 0, 0, 0, 0, 0)
    [f] = NetflowParser().parse(hdr + rec, "x")
    assert f.bytes == 6400 and f.packets == 100


def _v9_packet(flowsets: bytes, count: int) -> bytes:
    return struct.pack("!HHIIII", 9, count, 50_000, 1_700_000_000, 1, 7) + flowsets


def test_v9_template_then_data():
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4), (22, 4), (21, 4)]
    tpl = struct.pack("!HH", 256, len(fields)) + b"".join(struct.pack("!HH", *f) for f in fields)
    tpl_set = struct.pack("!HH", 0, 4 + len(tpl)) + tpl
    data = (ip("10.0.0.5") + ip("93.184.216.34") + struct.pack("!HHBIIII", 40000, 443, 6, 5000,
            7, 40_000, 49_000))
    pad = b"\0" * ((4 - (len(data) + 4) % 4) % 4)
    data_set = struct.pack("!HH", 256, 4 + len(data) + len(pad)) + data + pad
    p = NetflowParser()
    assert p.parse(_v9_packet(data_set, 1), "r") == []  # no template yet
    flows = p.parse(_v9_packet(tpl_set + data_set, 2), "r")
    assert len(flows) == 1
    f = flows[0]
    assert (f.src_ip, f.dst_ip, f.dst_port, f.bytes, f.packets) == (
        "10.0.0.5", "93.184.216.34", 443, 5000, 7)
    assert f.ts_end == 1_700_000_000 - 1.0
    assert f.ts_start == 1_700_000_000 - 10.0


def test_ipfix_with_variable_length_and_ipv6():
    fields = [(27, 16), (28, 16), (7, 2), (11, 2), (4, 1), (1, 8), (2, 8), (152, 8), (153, 8),
              (82, 65535)]
    tpl = struct.pack("!HH", 300, len(fields)) + b"".join(struct.pack("!HH", *f) for f in fields)
    tpl_set = struct.pack("!HH", 2, 4 + len(tpl)) + tpl
    rec = (socket.inet_pton(socket.AF_INET6, "fd00::2") +
           socket.inet_pton(socket.AF_INET6, "2606:4700::1111") +
           struct.pack("!HHBQQQQ", 50000, 53, 17, 120, 2, 1_700_000_000_000, 1_700_000_001_500)
           + bytes([4]) + b"eth0")
    data_set = struct.pack("!HH", 300, 4 + len(rec)) + rec
    body = tpl_set + data_set
    msg = struct.pack("!HHIII", 10, 16 + len(body), 1_700_000_005, 1, 1) + body
    [f] = NetflowParser().parse(msg, "r6")
    assert f.src_ip == "fd00::2" and f.dst_ip == "2606:4700::1111"
    assert f.bytes == 120 and f.ts_start == 1_700_000_000.0 and f.ts_end == 1_700_000_001.5
    assert f.source == "ipfix"


def test_garbage_is_ignored():
    p = NetflowParser()
    assert p.parse(b"\x00\x09\xff", "x") == []
    assert p.parse(struct.pack("!HH", 9, 1) + b"\x00" * 3, "x") == []
