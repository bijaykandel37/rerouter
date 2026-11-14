from rerouter.netutil import NetworkClassifier, classify_app, mac_vendor


def test_direction_classification():
    c = NetworkClassifier(["192.168.1.0/24"], ["203.0.113.45"])
    assert c.classify("192.168.1.2", "8.8.8.8", 5000, 53).direction == "upload"
    d = c.classify("8.8.8.8", "192.168.1.2", 53, 5000)
    assert (d.direction, d.local_ip, d.remote_ip, d.local_port, d.remote_port) == (
        "download", "192.168.1.2", "8.8.8.8", 5000, 53)
    assert c.classify("192.168.1.2", "192.168.1.3", 1, 2).direction == "lan"
    assert c.classify("203.0.113.45", "1.1.1.1", 1, 53).direction == "upload"
    assert c.classify("1.2.3.4", "5.6.7.8", 1, 2).direction == "transit"


def test_app_classification():
    assert classify_app(6, 51000, 443) == "https"
    assert classify_app(17, 51000, 443) == "quic"
    assert classify_app(6, 22, 50123) == "ssh"  # inbound to a local SSH server
    assert classify_app(1, 0, 0) == "icmp"
    assert classify_app(6, 50000, 50001) == "tcp/ephemeral"


def test_vendor():
    assert mac_vendor("b8:27:eb:00:00:01") == "Raspberry Pi"
    assert mac_vendor("7a:00:00:00:00:01") == "Randomized (private) MAC"
