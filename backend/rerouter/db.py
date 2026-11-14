"""SQLite persistence.

A single writer connection and a single reader connection are used, each
guarded by its own lock; WAL mode lets analytic reads proceed while flows are
being written. All blocking calls are pushed to a worker thread via the
``run``/``read``/``write`` helpers so they never stall the event loop.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Iterable, TypeVar

T = TypeVar("T")

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY,
    ts_start    REAL NOT NULL,
    ts_end      REAL NOT NULL,
    src_ip      TEXT NOT NULL,
    dst_ip      TEXT NOT NULL,
    src_port    INTEGER NOT NULL DEFAULT 0,
    dst_port    INTEGER NOT NULL DEFAULT 0,
    proto       INTEGER NOT NULL,
    bytes       INTEGER NOT NULL,
    packets     INTEGER NOT NULL,
    tcp_flags   INTEGER NOT NULL DEFAULT 0,
    direction   TEXT NOT NULL,          -- upload | download | lan | transit
    local_ip    TEXT,
    remote_ip   TEXT,
    local_port  INTEGER,
    remote_port INTEGER,
    app         TEXT NOT NULL,
    source      TEXT NOT NULL,          -- netflow | ipfix | capture | simulated
    exporter    TEXT
);
CREATE INDEX IF NOT EXISTS ix_flows_ts ON flows(ts_end);
CREATE INDEX IF NOT EXISTS ix_flows_local ON flows(local_ip, ts_end);
CREATE INDEX IF NOT EXISTS ix_flows_remote ON flows(remote_ip, ts_end);

CREATE TABLE IF NOT EXISTS iface_samples (
    ts          REAL NOT NULL,
    iface       TEXT NOT NULL,
    rx_rate     REAL NOT NULL,          -- bytes/s
    tx_rate     REAL NOT NULL,
    rx_pps      REAL NOT NULL,
    tx_pps      REAL NOT NULL,
    rx_errors   INTEGER NOT NULL DEFAULT 0,
    tx_errors   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_iface_samples ON iface_samples(iface, ts);

CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT,
    hostname    TEXT,
    alias       TEXT,
    vendor      TEXT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    blocked     INTEGER NOT NULL DEFAULT 0,
    notes       TEXT
);
CREATE INDEX IF NOT EXISTS ix_devices_ip ON devices(ip);

CREATE TABLE IF NOT EXISTS hostnames (
    ip          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    source      TEXT NOT NULL,          -- dns | ptr | simulated
    ts          REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    ts          REAL NOT NULL,
    severity    TEXT NOT NULL,          -- info | warning | serious | critical
    kind        TEXT NOT NULL,
    subject     TEXT,
    message     TEXT NOT NULL,
    details     TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY,
    ts          REAL NOT NULL,
    username    TEXT,
    action      TEXT NOT NULL,
    details     TEXT,
    ok          INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS users (
    username    TEXT PRIMARY KEY,
    password    TEXT NOT NULL,
    created     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    expires     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self._wconn = self._connect()
        self._wconn.executescript(SCHEMA)
        self._rconn = self._connect()
        self._wlock = threading.Lock()
        self._rlock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def close(self) -> None:
        self._wconn.close()
        self._rconn.close()

    # -- synchronous primitives (call from worker threads) -----------------
    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        with self._rlock:
            return [dict(r) for r in self._rconn.execute(sql, tuple(params))]

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: Iterable[Any] = ()) -> int:
        """Run a write statement; returns the number of affected rows."""
        with self._wlock:
            return self._wconn.execute(sql, tuple(params)).rowcount

    def insert(self, sql: str, params: Iterable[Any] = ()) -> int:
        """Run an INSERT; returns the new rowid."""
        with self._wlock:
            return self._wconn.execute(sql, tuple(params)).lastrowid or 0

    def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        with self._wlock:
            self._wconn.execute("BEGIN")
            try:
                self._wconn.executemany(sql, rows)
                self._wconn.execute("COMMIT")
            except Exception:
                self._wconn.execute("ROLLBACK")
                raise

    def transaction(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        with self._wlock:
            self._wconn.execute("BEGIN")
            try:
                result = fn(self._wconn)
                self._wconn.execute("COMMIT")
                return result
            except Exception:
                self._wconn.execute("ROLLBACK")
                raise

    # -- async wrappers ------------------------------------------------------
    async def aquery(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        return await asyncio.to_thread(self.query, sql, params)

    async def aquery_one(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        return await asyncio.to_thread(self.query_one, sql, params)

    async def aexecute(self, sql: str, params: Iterable[Any] = ()) -> int:
        return await asyncio.to_thread(self.execute, sql, params)

    async def ainsert(self, sql: str, params: Iterable[Any] = ()) -> int:
        return await asyncio.to_thread(self.insert, sql, params)

    async def aexecutemany(self, sql: str, rows: list) -> None:
        await asyncio.to_thread(self.executemany, sql, rows)

    async def run(self, fn: Callable[..., T], *args: Any) -> T:
        return await asyncio.to_thread(fn, *args)
