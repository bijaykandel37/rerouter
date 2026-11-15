"""Anomaly detection over recent flows plus a common alert sink.

Detectors (run every minute):

* **inbound scan** - one remote host sending unanswered SYNs to many
  distinct local host:port targets within 5 minutes;
* **outbound scan** - a LAN device doing the same towards the internet
  (typical of compromised IoT devices, e.g. Mirai-style telnet sweeps);
* **risky ports** - LAN devices talking to the internet on telnet/SMB/RDP/...;
* **traffic spike** - a device's last-minute volume far above its own
  baseline (mean + k*sigma of the previous hour);
* **bulk upload** - more than N bytes uploaded by one device in 10 minutes.

Pollers also raise alerts (new device, interface down, interface errors).
"""

from __future__ import annotations

import asyncio
import json
import logging
import statistics
import time

from .db import Database
from .live import LiveHub
from .settings import SettingsStore

log = logging.getLogger(__name__)

SEVERITIES = ("info", "warning", "serious", "critical")


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if abs(n) < 1000:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1000
    return f"{n:.1f} PB"


class AlertEngine:
    COOLDOWN = 1800.0

    def __init__(self, db: Database, hub: LiveHub, settings: SettingsStore):
        self.db = db
        self.hub = hub
        self.settings = settings
        self._last: dict[tuple[str, str], float] = {}
        self.names: dict[str, str] = {}

    async def raise_alert(self, kind: str, severity: str, message: str,
                          subject: str | None = None, details: dict | None = None,
                          cooldown: float | None = None) -> bool:
        key = (kind, subject or "")
        now = time.time()
        if now - self._last.get(key, 0) < (self.COOLDOWN if cooldown is None else cooldown):
            return False
        self._last[key] = now
        alert_id = await self.db.ainsert(
            "INSERT INTO alerts(ts, severity, kind, subject, message, details) "
            "VALUES (?,?,?,?,?,?)",
            (now, severity, kind, subject, message, json.dumps(details or {})))
        payload = {"id": alert_id, "ts": now, "severity": severity, "kind": kind,
                   "subject": subject, "message": message, "details": details or {},
                   "acknowledged": False}
        self.hub.publish("alert", payload)
        log.info("alert [%s] %s", severity, message)
        return True

    async def run(self, interval: float = 60.0) -> None:
        await asyncio.sleep(10)
        while True:
            try:
                await self.check()
            except Exception:
                log.exception("alert check failed")
            await asyncio.sleep(interval)

    def _device_names(self) -> dict[str, str]:
        return {r["ip"]: r["name"] for r in self.db.query(
            "SELECT ip, COALESCE(alias, hostname, mac) AS name FROM devices WHERE ip IS NOT NULL")}

    def _who(self, ip: str) -> str:
        name = self.names.get(ip)
        return f"{name} ({ip})" if name else ip

    async def check(self, now: float | None = None) -> int:
        now = now or time.time()
        cfg = self.settings.current.alerts
        self.names = await self.db.run(self._device_names)
        found = await self.db.run(self._detect, now, cfg)
        raised = 0
        for kind, severity, message, subject, details in found:
            if await self.raise_alert(kind, severity, message, subject, details):
                raised += 1
        return raised

    def _detect(self, now: float, cfg) -> list[tuple]:
        out: list[tuple] = []
        q = self.db.query
        since5 = now - 300

        for r in q("SELECT remote_ip, COUNT(DISTINCT local_ip || ':' || local_port) AS n, "
                   "COUNT(DISTINCT local_ip) AS hosts FROM flows "
                   "WHERE ts_end >= ? AND direction = 'download' AND proto = 6 "
                   "AND (tcp_flags & 18) = 2 GROUP BY remote_ip HAVING n >= ?",
                   (since5, cfg.scan_targets)):
            out.append(("inbound_scan", "serious",
                        f"Port scan from {r['remote_ip']}: {r['n']} ports probed on "
                        f"{r['hosts']} local host(s) in 5 min", r["remote_ip"], r))

        for r in q("SELECT local_ip, COUNT(DISTINCT remote_ip || ':' || remote_port) AS n, "
                   "COUNT(DISTINCT remote_port) AS ports FROM flows "
                   "WHERE ts_end >= ? AND direction = 'upload' AND proto = 6 "
                   "AND (tcp_flags & 18) = 2 GROUP BY local_ip HAVING n >= ?",
                   (since5, cfg.scan_targets)):
            out.append(("outbound_scan", "critical",
                        f"{self._who(r['local_ip'])} is scanning the internet: {r['n']} "
                        f"unanswered connection attempts in 5 min (possible compromise)",
                        r["local_ip"], r))

        if cfg.risky_ports:
            marks = ",".join("?" * len(cfg.risky_ports))
            for r in q(f"SELECT local_ip, remote_port, COUNT(DISTINCT remote_ip) AS hosts, "
                       f"SUM(bytes) AS bytes FROM flows WHERE ts_end >= ? "
                       f"AND direction = 'upload' AND remote_port IN ({marks}) "
                       f"GROUP BY local_ip, remote_port",
                       [since5, *cfg.risky_ports]):
                out.append(("risky_port", "warning",
                            f"{self._who(r['local_ip'])} connected to {r['hosts']} internet "
                            f"host(s) on port {r['remote_port']}",
                            f"{r['local_ip']}:{r['remote_port']}", r))

        if cfg.upload_bytes_10m:
            for r in q("SELECT local_ip, SUM(bytes) AS bytes, COUNT(DISTINCT remote_ip) AS dsts"
                       " FROM flows WHERE ts_end >= ? AND direction = 'upload' "
                       "GROUP BY local_ip HAVING bytes >= ?",
                       (now - 600, cfg.upload_bytes_10m)):
                out.append(("bulk_upload", "warning",
                            f"{self._who(r['local_ip'])} uploaded {_fmt_bytes(r['bytes'])} "
                            f"to {r['dsts']} destination(s) in 10 min", r["local_ip"], r))

        out.extend(self._spikes(now, cfg))
        return out

    def _spikes(self, now: float, cfg) -> list[tuple]:
        current = int(now // 60) - 1  # last complete minute
        rows = self.db.query(
            "SELECT local_ip, CAST(ts_end / 60 AS INTEGER) AS m, SUM(bytes) AS bytes "
            "FROM flows WHERE ts_end >= ? AND ts_end < ? "
            "AND direction IN ('upload', 'download') GROUP BY local_ip, m",
            (current * 60 - 3600, (current + 1) * 60))
        per: dict[str, dict[int, int]] = {}
        for r in rows:
            per.setdefault(r["local_ip"], {})[r["m"]] = r["bytes"]
        out = []
        for ip, minutes in per.items():
            last = minutes.get(current, 0)
            if last < cfg.spike_min_bytes:
                continue
            history = [minutes.get(m, 0) for m in range(current - 60, current)]
            mean = statistics.fmean(history)
            sd = statistics.pstdev(history)
            if last > mean + cfg.spike_sigma * max(sd, mean * 0.1, 1.0):
                out.append(("traffic_spike", "warning",
                            f"Traffic spike on {self._who(ip)}: {_fmt_bytes(last)} in the last "
                            f"minute vs. {_fmt_bytes(mean)}/min average", ip,
                            {"last_minute": last, "mean": mean, "stddev": sd}))
        return out
