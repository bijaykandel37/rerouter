"""Packet-capture sensor (Linux AF_PACKET, needs CAP_NET_RAW).

Use it when rerouter runs *on* the router, on a box in-line with it, or on a
host attached to a switch mirror/SPAN port of the router's uplink. Packets are
aggregated into flows (5-tuple, 30s active / 15s idle timeout) and DNS answers
are decoded so remote IPs can be labelled with the names clients looked up.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import time

from .dpi import inspect_tcp_payload
from .flowstore import FlowRecord, FlowSink

log = logging.getLogger(__name__)

ETH_P_ALL = 0x0003
ACTIVE_TIMEOUT = 30.0
IDLE_TIMEOUT = 15.0
L7_MAX_TRIES = 5  # give up L7 inspection after this many data packets per flow


def parse_packet(frame: bytes) -> tuple | None:
    """Return (src, dst, sport, dport, proto, ip_len, tcp_flags, l4_payload) or None."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    off = 14
    while ethertype in (0x8100, 0x88A8) and len(frame) >= off + 4:  # VLAN tags
        ethertype = struct.unpack_from("!H", frame, off + 2)[0]
        off += 4
    if ethertype == 0x0800:
        if len(frame) < off + 20:
            return None
        vihl = frame[off]
        ihl = (vihl & 0x0F) * 4
        total_len = struct.unpack_from("!H", frame, off + 2)[0]
        frag = struct.unpack_from("!H", frame, off + 6)[0]
        proto = frame[off + 9]
        src = socket.inet_ntop(socket.AF_INET, frame[off + 12: off + 16])
        dst = socket.inet_ntop(socket.AF_INET, frame[off + 16: off + 20])
        l4 = off + ihl
        if frag & 0x1FFF:  # non-first fragment: no L4 header
            return src, dst, 0, 0, proto, total_len, 0, b""
    elif ethertype == 0x86DD:
        if len(frame) < off + 40:
            return None
        payload_len = struct.unpack_from("!H", frame, off + 4)[0]
        proto = frame[off + 6]
        src = socket.inet_ntop(socket.AF_INET6, frame[off + 8: off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, frame[off + 24: off + 40])
        total_len = payload_len + 40
        l4 = off + 40
        # skip common extension headers
        while proto in (0, 43, 60) and len(frame) >= l4 + 2:
            proto, hlen = frame[l4], (frame[l4 + 1] + 1) * 8
            l4 += hlen
    else:
        return None

    sport = dport = flags = 0
    payload = b""
    if proto == 6 and len(frame) >= l4 + 14:
        sport, dport = struct.unpack_from("!HH", frame, l4)
        flags = frame[l4 + 13]
        doff = (frame[l4 + 12] >> 4) * 4
        payload = frame[l4 + doff:]
    elif proto == 17 and len(frame) >= l4 + 8:
        sport, dport = struct.unpack_from("!HH", frame, l4)
        payload = frame[l4 + 8:]
    return src, dst, sport, dport, proto, total_len, flags, payload


def _read_name(msg: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    while True:
        if pos >= len(msg) or depth > 10:
            raise ValueError("bad name")
        ln = msg[pos]
        if ln == 0:
            return ".".join(labels), pos + 1
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack_from("!H", msg, pos)[0] & 0x3FFF
            name, _ = _read_name(msg, ptr, depth + 1)
            labels.append(name)
            return ".".join(labels), pos + 2
        labels.append(msg[pos + 1: pos + 1 + ln].decode("ascii", "replace"))
        pos += 1 + ln


def parse_dns_answers(msg: bytes) -> dict[str, str]:
    """Extract {ip: queried_name} from a DNS response (A/AAAA, following CNAMEs
    back to the name the client originally asked for)."""
    if len(msg) < 12:
        return {}
    flags, qd, an = struct.unpack_from("!HHH", msg, 2)
    if not flags & 0x8000 or an == 0:
        return {}
    pos = 12
    qname = None
    for _ in range(qd):
        qname, pos = _read_name(msg, pos)
        pos += 4
    result: dict[str, str] = {}
    for _ in range(an):
        _, pos = _read_name(msg, pos)
        rtype, _, _, rdlen = struct.unpack_from("!HHIH", msg, pos)
        pos += 10
        rdata = msg[pos: pos + rdlen]
        pos += rdlen
        if qname and rtype == 1 and rdlen == 4:
            result[socket.inet_ntop(socket.AF_INET, rdata)] = qname
        elif qname and rtype == 28 and rdlen == 16:
            result[socket.inet_ntop(socket.AF_INET6, rdata)] = qname
    return result


class FlowTable:
    # entry layout: [start, end, bytes, packets, flags, meta]
    def __init__(self) -> None:
        self.flows: dict[tuple, list] = {}

    def add(self, key: tuple, size: int, flags: int, now: float) -> list:
        f = self.flows.get(key)
        if f is None:
            f = [now, now, size, 1, flags, {}]
            self.flows[key] = f
        else:
            f[1] = now
            f[2] += size
            f[3] += 1
            f[4] |= flags
        return f

    def expire(self, now: float, force: bool = False) -> list[FlowRecord]:
        out = []
        for key, f in list(self.flows.items()):
            if force or now - f[1] > IDLE_TIMEOUT or now - f[0] > ACTIVE_TIMEOUT:
                src, dst, sport, dport, proto = key
                meta = f[5]
                out.append(FlowRecord(f[0], f[1], src, dst, sport, dport, proto, f[2], f[3],
                                      f[4], source="capture", host=meta.get("host"),
                                      fingerprint=meta.get("fingerprint"),
                                      tls_version=meta.get("tls_version")))
                del self.flows[key]
        return out


class PacketCapture:
    def __init__(self, sink: FlowSink, interface: str):
        self.sink = sink
        self.interface = interface
        self.table = FlowTable()
        self.packets = 0
        self.l7_seen = 0
        self.error: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="capture", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((self.interface, 0))
            sock.settimeout(1.0)
        except (OSError, AttributeError) as exc:
            self.error = f"capture on {self.interface} unavailable: {exc}"
            log.error(self.error)
            return
        log.info("capturing packets on %s", self.interface)
        last_expire = time.time()
        while not self._stop.is_set():
            try:
                frame = sock.recv(65535)
            except socket.timeout:
                frame = b""
            except OSError as exc:
                self.error = str(exc)
                log.error("capture error: %s", exc)
                break
            now = time.time()
            if frame:
                self._handle(frame, now)
            if now - last_expire >= 1.0:
                last_expire = now
                expired = self.table.expire(now)
                if expired:
                    self.sink.submit(expired)
        self.sink.submit(self.table.expire(time.time(), force=True))
        sock.close()

    def _handle(self, frame: bytes, now: float) -> None:
        parsed = parse_packet(frame)
        if parsed is None:
            return
        src, dst, sport, dport, proto, size, flags, payload = parsed
        self.packets += 1
        entry = self.table.add((src, dst, sport, dport, proto), size, flags, now)
        if proto == 17 and sport == 53 and payload:
            try:
                names = parse_dns_answers(payload)
            except (ValueError, struct.error, IndexError):
                return
            if names:
                self.sink.learn_names(names, "dns")
        elif proto == 6 and payload:
            self._inspect(entry, payload, dst)

    def _inspect(self, entry: list, payload: bytes, dst: str) -> None:
        """Pull SNI / HTTP host / JA3 from the first data packets of a TCP flow."""
        meta = entry[5]
        if meta.get("host") or meta.get("tries", 0) >= L7_MAX_TRIES:
            return
        meta["tries"] = meta.get("tries", 0) + 1
        info = inspect_tcp_payload(payload)
        if not info:
            return
        for key in ("host", "fingerprint", "tls_version"):
            if info.get(key) and not meta.get(key):
                meta[key] = info[key]
        self.l7_seen += 1
        if info.get("host"):
            # SNI / Host names the destination server -- useful everywhere.
            self.sink.learn_names({dst: info["host"]}, info.get("kind", "sni"))

    def status(self) -> dict:
        return {"interface": self.interface, "packets": self.packets,
                "active_flows": len(self.table.flows), "l7_observed": self.l7_seen,
                "error": self.error,
                "running": bool(self._thread and self._thread.is_alive())}

