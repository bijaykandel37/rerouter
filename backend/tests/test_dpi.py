import struct

from rerouter.collectors.dpi import (inspect_tcp_payload, parse_http_request,
                                     parse_tls_client_hello)


def _ext(etype: int, body: bytes) -> bytes:
    return struct.pack("!HH", etype, len(body)) + body


def build_client_hello(sni: str = "example.com", ciphers=(0x1301, 0x1302),
                       with_grease: bool = True) -> bytes:
    cipher_vals = list(ciphers)
    if with_grease:
        cipher_vals = [0x0A0A, *cipher_vals]  # a GREASE cipher that JA3 must drop
    cs = b"".join(struct.pack("!H", c) for c in cipher_vals)

    name = sni.encode()
    sni_ext = _ext(0x0000, struct.pack("!H", len(name) + 3) + b"\x00"
                   + struct.pack("!H", len(name)) + name)
    groups = _ext(0x000A, struct.pack("!H", 4) + struct.pack("!HH", 0x1A1A, 0x001D))  # GREASE+x25519
    point_formats = _ext(0x000B, bytes([1, 0]))
    alpn = _ext(0x0010, struct.pack("!H", 3) + bytes([2]) + b"h2")
    exts = sni_ext + groups + point_formats + alpn

    body = (struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00"
            + struct.pack("!H", len(cs)) + cs + bytes([1, 0])
            + struct.pack("!H", len(exts)) + exts)
    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def test_tls_sni_and_ja3():
    hello = build_client_hello("cdn.example.com")
    r = parse_tls_client_hello(hello)
    assert r is not None
    assert r["sni"] == "cdn.example.com"
    assert r["tls_version"] == "TLS 1.2"
    assert r["alpn"] == ["h2"]
    # JA3: version,ciphers,extensions,curves,point_formats; GREASE excluded.
    version, ciphers, exts, curves, pts = r["ja3"].split(",")
    assert version == "771"  # 0x0303
    assert "2586" not in ciphers.split("-")  # 0x0a0a GREASE dropped
    assert ciphers.split("-") == ["4865", "4866"]
    assert curves.split("-") == ["29"]  # x25519, GREASE 0x1a1a dropped
    assert set(exts.split("-")) == {"0", "10", "11", "16"}
    assert len(r["ja3_hash"]) == 32 and all(c in "0123456789abcdef" for c in r["ja3_hash"])


def test_tls_fingerprint_is_stable_and_sni_independent():
    a = parse_tls_client_hello(build_client_hello("a.example.com"))
    b = parse_tls_client_hello(build_client_hello("b.example.net"))
    assert a["ja3_hash"] == b["ja3_hash"]  # same client, different host
    c = parse_tls_client_hello(build_client_hello("a.example.com", ciphers=(0x1301,)))
    assert c["ja3_hash"] != a["ja3_hash"]  # different client offering


def test_not_a_client_hello():
    assert parse_tls_client_hello(b"\x16\x03\x01\x00\x04\x02\x00\x00\x00") is None  # ServerHello
    assert parse_tls_client_hello(b"GET / HTTP/1.1\r\n\r\n") is None
    assert parse_tls_client_hello(b"\x16\x03") is None  # truncated


def test_truncated_client_hello_does_not_raise():
    full = build_client_hello("example.com")
    for cut in range(6, len(full)):
        parse_tls_client_hello(full[:cut])  # must not raise


def test_http_request():
    req = (b"GET /api/status?x=1 HTTP/1.1\r\nHost: device.local:8080\r\n"
           b"User-Agent: curl/8.4\r\nAccept: */*\r\n\r\n")
    r = parse_http_request(req)
    assert r["method"] == "GET" and r["path"] == "/api/status?x=1"
    assert r["host"] == "device.local" and r["user_agent"] == "curl/8.4"
    assert parse_http_request(b"\x16\x03\x01rubbish") is None


def test_inspect_dispatch():
    assert inspect_tcp_payload(build_client_hello("x.example.com"))["host"] == "x.example.com"
    assert inspect_tcp_payload(build_client_hello("x.example.com"))["kind"] == "tls"
    http = inspect_tcp_payload(b"POST /u HTTP/1.1\r\nHost: iot.example.org\r\n\r\n")
    assert http["host"] == "iot.example.org" and http["kind"] == "http"
    assert inspect_tcp_payload(b"\x00\x01\x02\x03rubbish data") is None
