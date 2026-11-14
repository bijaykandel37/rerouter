"""The flow sink: every collector (NetFlow/IPFIX, packet capture, simulator)
hands raw flow records here. Records are classified (direction, local/remote
side, application), batched into SQLite and streamed to live subscribers."""

from __future__ import annotations

import asyncio
import collections
import logging
import socket
import threading
import time
from dataclasses import dataclass

from ..db import Database
from ..live import LiveHub
from ..netutil import NetworkClassifier, classify_app, proto_name

log = logging.getLogger(__name__)

INSERT_SQL = (
    "INSERT INTO flows(ts_start, ts_end, src_ip, dst_ip, src_port, dst_port, proto, bytes,"
    " packets, tcp_flags, direction, local_ip, remote_ip, local_port, remote_port, app,"
    " source, exporter) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
)


@dataclass(slots=True)
class FlowRecord:
    ts_start: float
    ts_end: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    bytes: int
    packets: int
    tcp_flags: int = 0
    source: str = "netflow"
    exporter: str | None = None


class FlowSink:
    def __init__(self, db: Database, classifier: NetworkClassifier, hub: LiveHub,
                 flush_interval: float = 1.0, max_buffer: int = 200_000):
        self.db = db
        self.classifier = classifier
        self.hub = hub
        self.flush_interval = flush_interval
        self._buf: collections.deque[FlowRecord] = collections.deque(maxlen=max_buffer)
        self._lock = threading.Lock()
        self.names: dict[str, str] = {}
        self._pending_names: dict[str, tuple[str, str]] = {}
        self._ptr_queue: asyncio.Queue[str] | None = None
        self._ptr_seen: set[str] = set()
        self.reverse_dns = False
        self.stats = {"received": 0, "stored": 0, "dropped": 0, "last_flush": 0.0,
                      "by_source": collections.Counter()}

    # -- ingestion (thread-safe) -------------------------------------------
    def submit(self, records: list[FlowRecord]) -> None:
        with self._lock:
            before = len(self._buf)
            self._buf.extend(records)
            overflow = before + len(records) - len(self._buf)
            self.stats["received"] += len(records)
            if overflow > 0:
                self.stats["dropped"] += overflow

    def learn_names(self, mapping: dict[str, str], source: str) -> None:
        """Record IP -> hostname knowledge (from sniffed DNS answers etc.)."""
        with self._lock:
            for ip, name in mapping.items():
                if self.names.get(ip) != name:
                    self.names[ip] = name
                    self._pending_names[ip] = (name, source)

    def load_names(self) -> None:
        for row in self.db.query("SELECT ip, name FROM hostnames"):
            self.names[row["ip"]] = row["name"]

    def name_for(self, ip: str | None) -> str | None:
        return self.names.get(ip) if ip else None

    # -- background tasks ----------------------------------------------------
    async def run(self) -> None:
        self.load_names()
        self._ptr_queue = asyncio.Queue(maxsize=10_000)
        ptr_task = asyncio.create_task(self._ptr_worker())
        try:
            while True:
                await asyncio.sleep(self.flush_interval)
                try:
                    await self.flush()
                except Exception:  # keep the pipeline alive
                    log.exception("flow flush failed")
        finally:
            ptr_task.cancel()

    async def flush(self) -> int:
        with self._lock:
            batch = list(self._buf)
            self._buf.clear()
            names = self._pending_names
            self._pending_names = {}
        now = time.time()
        if names:
            await self.db.aexecutemany(
                "INSERT INTO hostnames(ip, name, source, ts) VALUES(?,?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET name=excluded.name, source=excluded.source,"
                " ts=excluded.ts",
                [(ip, n, s, now) for ip, (n, s) in names.items()],
            )
        if not batch:
            return 0
        rows, live = [], []
        for rec in batch:
            c = self.classifier.classify(rec.src_ip, rec.dst_ip, rec.src_port, rec.dst_port)
            app = classify_app(rec.proto, c.local_port, c.remote_port)
            rows.append((rec.ts_start, rec.ts_end, rec.src_ip, rec.dst_ip, rec.src_port,
                         rec.dst_port, rec.proto, rec.bytes, rec.packets, rec.tcp_flags,
                         c.direction, c.local_ip, c.remote_ip, c.local_port, c.remote_port,
                         app, rec.source, rec.exporter))
            self.stats["by_source"][rec.source] += 1
            if self.reverse_dns and c.direction in ("upload", "download"):
                self._queue_ptr(c.remote_ip)
            if len(live) < 100:
                live.append({
                    "ts": rec.ts_end, "src": rec.src_ip, "dst": rec.dst_ip,
                    "sport": rec.src_port, "dport": rec.dst_port,
                    "proto": proto_name(rec.proto), "bytes": rec.bytes,
                    "packets": rec.packets, "direction": c.direction, "app": app,
                    "local": c.local_ip, "remote": c.remote_ip,
                    "remote_name": self.names.get(c.remote_ip),
                })
        await self.db.aexecutemany(INSERT_SQL, rows)
        self.stats["stored"] += len(rows)
        self.stats["last_flush"] = now
        if self.hub.subscriber_count:
            self.hub.publish("flows", {"count": len(rows), "sample": live})
        return len(rows)

    def _queue_ptr(self, ip: str) -> None:
        if ip in self.names or ip in self._ptr_seen or self._ptr_queue is None:
            return
        self._ptr_seen.add(ip)
        if not self._ptr_queue.full():
            self._ptr_queue.put_nowait(ip)

    async def _ptr_worker(self) -> None:
        assert self._ptr_queue is not None
        while True:
            ip = await self._ptr_queue.get()
            try:
                name, _, _ = await asyncio.wait_for(
                    asyncio.to_thread(socket.gethostbyaddr, ip), timeout=3)
                self.learn_names({ip: name}, "ptr")
            except (OSError, asyncio.TimeoutError):
                pass
