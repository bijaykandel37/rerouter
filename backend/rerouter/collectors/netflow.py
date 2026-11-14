"""NetFlow v5 / v9 and IPFIX (v10) collector.

Point your router's flow exporter at UDP ``<rerouter-host>:2055``:

* OpenWrt:  ``softflowd -i br-lan -n <host>:2055 -v 9`` (package ``softflowd``)
* MikroTik: ``/ip traffic-flow set enabled=yes`` and add a target with version 9 or ipfix
* pfSense/OPNsense: ``softflowd``/NetFlow plugin, Cisco: ``ip flow-export``
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import struct
import time
from collections import Counter

from .flowstore import FlowRecord, FlowSink

log = logging.getLogger(__name__)

V5_HEADER = struct.Struct("!HHIIIIBBH")
V5_RECORD = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")
V9_HEADER = struct.Struct("!HHIIII")
IPFIX_HEADER = struct.Struct("!HHIII")
SET_HEADER = struct.Struct("!HH")

# Information element ids we understand (shared by v9 and IPFIX).
F_BYTES, F_PKTS, F_PROTO, F_FLAGS, F_SPORT, F_SRC4 = 1, 2, 4, 6, 7, 8
F_IN_IF, F_DPORT, F_DST4, F_OUT_IF = 10, 11, 12, 14
F_LAST, F_FIRST, F_OUT_BYTES, F_OUT_PKTS = 21, 22, 23, 24
F_SRC6, F_DST6, F_SAMPLING = 27, 28, 34
F_TOTAL_BYTES, F_TOTAL_PKTS = 85, 86
F_START_S, F_END_S, F_START_MS, F_END_MS = 150, 151, 152, 153
F_SYS_INIT_MS = 160

_ADDR_FIELDS = {F_SRC4, F_DST4, F_SRC6, F_DST6}


class NetflowParser:
    """Stateful parser (keeps v9/IPFIX templates per exporter + domain)."""

    def __init__(self) -> None:
        self.templates: dict[tuple[str, int, int], list[tuple[int, int]]] = {}
        self.sampling: dict[tuple[str, int], int] = {}
        self.stats: Counter = Counter()

    def parse(self, data: bytes, exporter: str) -> list[FlowRecord]:
        if len(data) < 4:
            return []
        version = struct.unpack_from("!H", data)[0]
        try:
            if version == 5:
                return self._v5(data, exporter)
            if version == 9:
                return self._v9(data, exporter)
            if version == 10:
                return self._ipfix(data, exporter)
        except (struct.error, ValueError, IndexError) as exc:
            self.stats["malformed"] += 1
            log.debug("malformed v%s packet from %s: %s", version, exporter, exc)
            return []
        self.stats["unsupported_version"] += 1
        return []

    # -- NetFlow v5 -----------------------------------------------------------
    def _v5(self, data: bytes, exporter: str) -> list[FlowRecord]:
        (_, count, uptime, secs, nsecs, _, _, _, sampling) = V5_HEADER.unpack_from(data)
        rate = sampling & 0x3FFF or 1
        now = secs + nsecs / 1e9
        out = []
        off = V5_HEADER.size
        for _ in range(count):
            if off + V5_RECORD.size > len(data):
                break
            r = V5_RECORD.unpack_from(data, off)
            off += V5_RECORD.size
            first, last = r[7], r[8]
            out.append(FlowRecord(
                ts_start=now - ((uptime - first) & 0xFFFFFFFF) / 1000.0,
                ts_end=now - ((uptime - last) & 0xFFFFFFFF) / 1000.0,
                src_ip=str(ipaddress.IPv4Address(r[0])),
                dst_ip=str(ipaddress.IPv4Address(r[1])),
                src_port=r[9], dst_port=r[10], proto=r[13],
                bytes=r[6] * rate, packets=r[5] * rate, tcp_flags=r[12],
                source="netflow", exporter=exporter,
            ))
        self.stats["v5"] += len(out)
        return out

    # -- NetFlow v9 -----------------------------------------------------------
    def _v9(self, data: bytes, exporter: str) -> list[FlowRecord]:
        _, _, uptime, secs, _, source_id = V9_HEADER.unpack_from(data)
        ctx = {"uptime": uptime, "secs": secs}
        out: list[FlowRecord] = []
        off = V9_HEADER.size
        while off + 4 <= len(data):
            set_id, length = SET_HEADER.unpack_from(data, off)
            if length < 4:
                break
            body = data[off + 4: off + length]
            off += length
            if set_id == 0:
                self._v9_templates(body, exporter, source_id)
            elif set_id == 1:
                self._v9_option_templates(body, exporter, source_id)
            elif set_id >= 256:
                out.extend(self._data(body, exporter, source_id, set_id, ctx, "netflow"))
        self.stats["v9"] += len(out)
        return out

    def _v9_templates(self, body: bytes, exporter: str, domain: int) -> None:
        pos = 0
        while pos + 4 <= len(body):
            tid, count = struct.unpack_from("!HH", body, pos)
            pos += 4
            fields = []
            for _ in range(count):
                ftype, flen = struct.unpack_from("!HH", body, pos)
                pos += 4
                fields.append((ftype, flen))
            self.templates[(exporter, domain, tid)] = fields

    def _v9_option_templates(self, body: bytes, exporter: str, domain: int) -> None:
        pos = 0
        while pos + 6 <= len(body):
            tid, scope_len, opt_len = struct.unpack_from("!HHH", body, pos)
            pos += 6
            fields = []
            for _ in range((scope_len + opt_len) // 4):
                ftype, flen = struct.unpack_from("!HH", body, pos)
                pos += 4
                # scope fields use their own type space; neutralise them
                fields.append((ftype if len(fields) >= scope_len // 4 else 0x7FFF, flen))
            self.templates[(exporter, domain, tid)] = fields
            if len(body) - pos < 4:
                break

    # -- IPFIX ----------------------------------------------------------------
    def _ipfix(self, data: bytes, exporter: str) -> list[FlowRecord]:
        _, length, export_time, _, domain = IPFIX_HEADER.unpack_from(data)
        ctx = {"export_time": export_time}
        out: list[FlowRecord] = []
        off = IPFIX_HEADER.size
        end = min(length, len(data))
        while off + 4 <= end:
            set_id, slen = SET_HEADER.unpack_from(data, off)
            if slen < 4:
                break
            body = data[off + 4: off + slen]
            off += slen
            if set_id in (2, 3):
                self._ipfix_templates(body, exporter, domain, options=set_id == 3)
            elif set_id >= 256:
                out.extend(self._data(body, exporter, domain, set_id, ctx, "ipfix"))
        self.stats["ipfix"] += len(out)
        return out

    def _ipfix_templates(self, body: bytes, exporter: str, domain: int, options: bool) -> None:
        pos = 0
        while pos + 4 <= len(body):
            tid, count = struct.unpack_from("!HH", body, pos)
            pos += 4
            scope = 0
            if options:
                scope = struct.unpack_from("!H", body, pos)[0]
                pos += 2
            if tid < 256:  # template withdrawal or padding
                break
            fields = []
            for i in range(count):
                ftype, flen = struct.unpack_from("!HH", body, pos)
                pos += 4
                if ftype & 0x8000:  # enterprise-specific element
                    pos += 4
                    ftype = 0x7FFF
                if i < scope:
                    ftype = 0x7FFF
                fields.append((ftype, flen))
            self.templates[(exporter, domain, tid)] = fields

    # -- data records (v9 + IPFIX) -------------------------------------------
    def _data(self, body: bytes, exporter: str, domain: int, tid: int, ctx: dict,
              source: str) -> list[FlowRecord]:
        template = self.templates.get((exporter, domain, tid))
        if template is None:
            self.stats["missing_template"] += 1
            return []
        out = []
        pos = 0
        min_len = sum(1 if flen == 65535 else flen for _, flen in template)
        while pos + min_len <= len(body) and min_len > 0:
            values: dict[int, bytes] = {}
            for ftype, flen in template:
                if flen == 65535:  # IPFIX variable length
                    flen = body[pos]
                    pos += 1
                    if flen == 255:
                        flen = struct.unpack_from("!H", body, pos)[0]
                        pos += 2
                values[ftype] = body[pos: pos + flen]
                pos += flen
            rec = self._to_record(values, exporter, domain, ctx, source)
            if rec is not None:
                out.append(rec)
        return out

    def _to_record(self, v: dict[int, bytes], exporter: str, domain: int, ctx: dict,
                   source: str) -> FlowRecord | None:
        def num(key: int, default: int = 0) -> int:
            raw = v.get(key)
            return int.from_bytes(raw, "big") if raw else default

        if F_SAMPLING in v and not (_ADDR_FIELDS & v.keys()):
            # options record announcing the sampling rate
            self.sampling[(exporter, domain)] = max(1, num(F_SAMPLING))
            return None
        if F_SRC4 in v and F_DST4 in v:
            src = str(ipaddress.IPv4Address(v[F_SRC4]))
            dst = str(ipaddress.IPv4Address(v[F_DST4]))
        elif F_SRC6 in v and F_DST6 in v:
            src = str(ipaddress.IPv6Address(v[F_SRC6]))
            dst = str(ipaddress.IPv6Address(v[F_DST6]))
        else:
            return None

        rate = self.sampling.get((exporter, domain), 1)
        nbytes = num(F_BYTES) or num(F_TOTAL_BYTES) or num(F_OUT_BYTES)
        npkts = num(F_PKTS) or num(F_TOTAL_PKTS) or num(F_OUT_PKTS)

        if F_START_MS in v or F_END_MS in v:
            end = num(F_END_MS) / 1000.0 or num(F_START_MS) / 1000.0
            start = num(F_START_MS) / 1000.0 or end
        elif F_START_S in v or F_END_S in v:
            end = float(num(F_END_S) or num(F_START_S))
            start = float(num(F_START_S) or end)
        elif (F_FIRST in v or F_LAST in v) and "uptime" in ctx:
            up, secs = ctx["uptime"], ctx["secs"]
            end = secs - ((up - num(F_LAST, up)) & 0xFFFFFFFF) / 1000.0
            start = secs - ((up - num(F_FIRST, up)) & 0xFFFFFFFF) / 1000.0
        elif (F_FIRST in v or F_LAST in v) and F_SYS_INIT_MS in v:
            init = num(F_SYS_INIT_MS) / 1000.0
            end = init + num(F_LAST) / 1000.0
            start = init + num(F_FIRST) / 1000.0
        else:
            end = float(ctx.get("export_time") or ctx.get("secs") or time.time())
            start = end
        return FlowRecord(
            ts_start=start, ts_end=max(end, start), src_ip=src, dst_ip=dst,
            src_port=num(F_SPORT), dst_port=num(F_DPORT), proto=num(F_PROTO),
            bytes=nbytes * rate, packets=npkts * rate, tcp_flags=num(F_FLAGS) & 0xFF,
            source=source, exporter=exporter,
        )


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, collector: "NetflowCollector"):
        self.collector = collector

    def datagram_received(self, data: bytes, addr) -> None:
        self.collector.handle(data, addr[0])


class NetflowCollector:
    def __init__(self, sink: FlowSink, bind: str = "0.0.0.0", port: int = 2055):
        self.sink = sink
        self.bind = bind
        self.port = port
        self.parser = NetflowParser()
        self.exporters: dict[str, dict] = {}
        self._transport: asyncio.DatagramTransport | None = None
        self.error: str | None = None

    def handle(self, data: bytes, exporter: str) -> None:
        records = self.parser.parse(data, exporter)
        info = self.exporters.setdefault(exporter, {"packets": 0, "flows": 0, "last_seen": 0})
        info["packets"] += 1
        info["flows"] += len(records)
        info["last_seen"] = time.time()
        if records:
            self.sink.submit(records)

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            self._transport, _ = await loop.create_datagram_endpoint(
                lambda: _Protocol(self), local_addr=(self.bind, self.port))
            log.info("NetFlow/IPFIX collector listening on udp/%s:%s", self.bind, self.port)
        except OSError as exc:
            self.error = str(exc)
            log.error("cannot start NetFlow collector on %s:%s: %s", self.bind, self.port, exc)

    def stop(self) -> None:
        if self._transport:
            self._transport.close()

    def status(self) -> dict:
        return {"listening": self._transport is not None, "bind": self.bind, "port": self.port,
                "error": self.error, "exporters": self.exporters,
                "parser": dict(self.parser.stats)}
