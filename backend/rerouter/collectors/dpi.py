"""Passive application-layer inspection for captured packets.

These functions read only metadata that endpoints send **in the clear** at the
start of a connection:

* the **TLS ClientHello** -- the requested server name (SNI), the offered TLS
  version and ALPN, and a **JA3 client fingerprint** (a hash of the hello's
  cipher/extension/curve lists, which identifies the client software);
* **plaintext HTTP** request headers -- method, Host and User-Agent.

Nothing here decrypts anything. TLS application data is never parsed; only the
unencrypted handshake and cleartext HTTP are read. This is the passive half of
rerouter's traffic analysis. Payload decryption is a separate, explicitly
opt-in, per-device path via mitmproxy -- see ``docs/mitmproxy.md``.
"""

from __future__ import annotations

import hashlib
import struct

# TLS GREASE values (RFC 8701): reserved values a client sprinkles in to keep
# servers tolerant. They are random per-connection, so JA3 must ignore them.
_GREASE = {(b << 8) | b for b in (0x0A, 0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A,
                                  0x8A, 0x9A, 0xAA, 0xBA, 0xCA, 0xDA, 0xEA, 0xFA)}

_TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ",
                 b"PATCH ", b"TRACE ", b"CONNECT ")


def _is_grease(v: int) -> bool:
    return v in _GREASE


def _u16(data: bytes, pos: int) -> int:
    return struct.unpack_from("!H", data, pos)[0]


def parse_tls_client_hello(data: bytes) -> dict | None:
    """Parse a TLS ClientHello. Returns ``None`` if the bytes are not one.

    Result keys: ``sni`` (str|None), ``tls_version`` (str), ``alpn`` (list|None),
    ``ja3`` (str), ``ja3_hash`` (md5 hex). Bounds are checked throughout so a
    truncated or malformed hello yields ``None`` rather than raising.
    """
    try:
        if len(data) < 6 or data[0] != 0x16:  # content type: handshake
            return None
        pos = 5  # skip record header (type + version + length)
        if data[pos] != 0x01:  # handshake type: client_hello
            return None
        hs_len = int.from_bytes(data[pos + 1:pos + 4], "big")
        pos += 4
        end = min(len(data), pos + hs_len)

        client_version = _u16(data, pos)
        pos += 2 + 32  # legacy_version + random
        if pos + 1 > end:
            return None
        pos += 1 + data[pos]  # session_id

        if pos + 2 > end:
            return None
        cs_len = _u16(data, pos)
        pos += 2
        ciphers = []
        cs_end = pos + cs_len
        while pos + 2 <= min(cs_end, end):
            c = _u16(data, pos)
            pos += 2
            if not _is_grease(c):
                ciphers.append(c)
        pos = cs_end
        if pos + 1 > end:
            return None
        pos += 1 + data[pos]  # compression_methods

        sni = None
        alpn: list[str] = []
        extensions: list[int] = []
        curves: list[int] = []
        point_formats: list[int] = []

        if pos + 2 <= end:
            ext_end = min(end, pos + 2 + _u16(data, pos))
            pos += 2
            while pos + 4 <= ext_end:
                etype, elen = struct.unpack_from("!HH", data, pos)
                pos += 4
                edata = data[pos:pos + elen]
                pos += elen
                if not _is_grease(etype):
                    extensions.append(etype)
                if etype == 0x0000:  # server_name
                    sni = _parse_sni(edata) or sni
                elif etype == 0x000A and len(edata) >= 2:  # supported_groups
                    glen = _u16(edata, 0)
                    for i in range(2, min(2 + glen, len(edata)) - 1, 2):
                        g = _u16(edata, i)
                        if not _is_grease(g):
                            curves.append(g)
                elif etype == 0x000B and len(edata) >= 1:  # ec_point_formats
                    point_formats = list(edata[1:1 + edata[0]])
                elif etype == 0x0010:  # ALPN
                    alpn = _parse_alpn(edata)

        ja3 = ",".join((str(client_version), "-".join(map(str, ciphers)),
                        "-".join(map(str, extensions)), "-".join(map(str, curves)),
                        "-".join(map(str, point_formats))))
        return {
            "sni": sni, "alpn": alpn or None,
            "tls_version": _TLS_VERSIONS.get(client_version, f"0x{client_version:04x}"),
            "ja3": ja3,
            "ja3_hash": hashlib.md5(ja3.encode(), usedforsecurity=False).hexdigest(),
        }
    except (struct.error, IndexError):
        return None


def _parse_sni(edata: bytes) -> str | None:
    if len(edata) < 5:
        return None
    list_end = min(2 + _u16(edata, 0), len(edata))
    p = 2
    while p + 3 <= list_end:
        ntype = edata[p]
        nlen = _u16(edata, p + 1)
        p += 3
        name = edata[p:p + nlen]
        p += nlen
        if ntype == 0 and name:  # host_name
            host = name.decode("ascii", "replace").rstrip(".").lower()
            return host if _plausible_host(host) else None
    return None


def _parse_alpn(edata: bytes) -> list[str]:
    if len(edata) < 2:
        return []
    out: list[str] = []
    end = min(2 + _u16(edata, 0), len(edata))
    p = 2
    while p < end:
        ln = edata[p]
        p += 1
        out.append(edata[p:p + ln].decode("ascii", "replace"))
        p += ln
    return out


def parse_http_request(data: bytes) -> dict | None:
    """Parse the head of a cleartext HTTP/1.x request.

    Result keys: ``method``, ``path``, ``host`` (str|None), ``user_agent``.
    """
    if not data.startswith(_HTTP_METHODS):
        return None
    head = data[:8192].split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    try:
        method, path, proto = lines[0].split(b" ", 2)
    except ValueError:
        return None
    if not proto.startswith(b"HTTP/"):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        if sep:
            headers[key.strip().lower().decode("ascii", "replace")] = \
                value.strip().decode("ascii", "replace")
    host = headers.get("host")
    if host:
        host = host.split(":")[0].rstrip(".").lower()
        if not _plausible_host(host):
            host = None
    return {
        "method": method.decode("ascii", "replace"),
        "path": path.decode("ascii", "replace")[:512],
        "host": host,
        "user_agent": headers.get("user-agent", "")[:256] or None,
    }


def _plausible_host(host: str) -> bool:
    return (1 < len(host) <= 253 and "." in host
            and all(c.isalnum() or c in ".-_" for c in host))


def inspect_tcp_payload(payload: bytes) -> dict | None:
    """Best-effort: pull passive L7 metadata from the start of a TCP stream.

    Returns a dict with any of ``host``, ``fingerprint`` (JA3 hash),
    ``tls_version``, ``ja3``, ``user_agent``, ``method``, and ``kind``
    ("tls"|"http"), or ``None`` if nothing recognisable is present.
    """
    if len(payload) < 4:
        return None
    if payload[0] == 0x16:  # TLS handshake
        tls = parse_tls_client_hello(payload)
        if tls:
            return {"host": tls["sni"], "fingerprint": tls["ja3_hash"],
                    "tls_version": tls["tls_version"], "ja3": tls["ja3"],
                    "alpn": tls["alpn"], "kind": "tls"}
    http = parse_http_request(payload)
    if http:
        return {"host": http["host"], "user_agent": http["user_agent"],
                "method": http["method"], "kind": "http"}
    return None
