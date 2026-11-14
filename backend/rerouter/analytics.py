"""Traffic analytics over the flow store.

All functions are synchronous (they run in a worker thread) and take a
``Query`` describing the time window and filters. Flows are attributed to the
time bucket containing their ``ts_end``; collectors use short active timeouts
(15-60 s) so this is accurate at the bucket sizes used here.
"""

from __future__ import annotations

import csv
import io
import math
import time
from dataclasses import dataclass, field
from typing import Iterator

from .db import Database
from .netutil import proto_name

RANGES = {"5m": 300, "15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800,
          "30d": 2592000}
NICE_BUCKETS = [10, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400]
GROUPABLE = {"direction": "direction", "app": "app", "local_ip": "local_ip",
             "remote_ip": "remote_ip", "proto": "proto", "remote_port": "remote_port",
             "local_port": "local_port", "source": "source"}


@dataclass
class Query:
    start: float
    end: float
    local_ip: str | None = None
    remote_ip: str | None = None
    ip: str | None = None  # either side
    app: str | None = None
    direction: str | None = None
    proto: int | None = None
    port: int | None = None  # either side
    source: str | None = None
    exclude_lan: bool = False
    extra: list[tuple[str, tuple]] = field(default_factory=list)

    @classmethod
    def from_params(cls, range_: str | None = None, start: float | None = None,
                    end: float | None = None, **filters) -> "Query":
        now = time.time()
        end = end or now
        if start is None:
            start = end - RANGES.get(range_ or "1h", 3600)
        clean = {k: v for k, v in filters.items() if v not in (None, "")}
        return cls(start=start, end=end, **clean)

    def where(self) -> tuple[str, list]:
        clauses = ["ts_end >= ?", "ts_end < ?"]
        params: list = [self.start, self.end]
        for col in ("local_ip", "remote_ip", "app", "direction", "proto", "source"):
            value = getattr(self, col)
            if value is not None:
                clauses.append(f"{col} = ?")
                params.append(value)
        if self.ip:
            clauses.append("(local_ip = ? OR remote_ip = ?)")
            params += [self.ip, self.ip]
        if self.port is not None:
            clauses.append("(local_port = ? OR remote_port = ?)")
            params += [self.port, self.port]
        if self.exclude_lan:
            clauses.append("direction IN ('upload', 'download')")
        for clause, p in self.extra:
            clauses.append(clause)
            params += list(p)
        return " AND ".join(clauses), params


def pick_bucket(span: float, points: int = 120) -> int:
    target = span / points
    for b in NICE_BUCKETS:
        if b >= target:
            return b
    return NICE_BUCKETS[-1]


class Labeler:
    """Resolves IPs to friendly names (device alias/hostname, DNS names)."""

    def __init__(self, db: Database):
        self.devices = {r["ip"]: r for r in db.query(
            "SELECT ip, mac, COALESCE(alias, hostname) AS name, vendor FROM devices "
            "WHERE ip IS NOT NULL ORDER BY last_seen")}
        self.hosts = {r["ip"]: r["name"] for r in db.query("SELECT ip, name FROM hostnames")}

    def name(self, ip: str | None) -> str | None:
        if ip is None:
            return None
        dev = self.devices.get(ip)
        if dev and dev["name"]:
            return dev["name"]
        return self.hosts.get(ip)

    def label(self, ip: str | None) -> str:
        return self.name(ip) or (ip or "?")


DIRECTION_SUMS = (
    "SUM(CASE WHEN direction='download' THEN bytes ELSE 0 END) AS download, "
    "SUM(CASE WHEN direction='upload' THEN bytes ELSE 0 END) AS upload, "
    "SUM(CASE WHEN direction='lan' THEN bytes ELSE 0 END) AS lan, "
    "SUM(CASE WHEN direction='transit' THEN bytes ELSE 0 END) AS transit"
)


def summary(db: Database, q: Query) -> dict:
    where, params = q.where()
    row = db.query_one(
        f"SELECT COUNT(*) AS flows, COALESCE(SUM(bytes),0) AS bytes, "
        f"COALESCE(SUM(packets),0) AS packets, {DIRECTION_SUMS}, "
        f"COUNT(DISTINCT CASE WHEN direction IN ('upload','download') THEN local_ip END)"
        f" AS local_hosts, "
        f"COUNT(DISTINCT CASE WHEN direction IN ('upload','download') THEN remote_ip END)"
        f" AS remote_hosts FROM flows WHERE {where}", params) or {}
    for key in ("download", "upload", "lan", "transit"):
        row[key] = row.get(key) or 0
    top_app = db.query_one(
        f"SELECT app, SUM(bytes) AS bytes FROM flows WHERE {where} GROUP BY app "
        f"ORDER BY bytes DESC LIMIT 1", params)
    span = max(1.0, q.end - q.start)
    row.update(start=q.start, end=q.end, top_app=top_app["app"] if top_app else None,
               avg_download_rate=row["download"] / span, avg_upload_rate=row["upload"] / span)
    return row


def timeseries(db: Database, q: Query, group_by: str = "direction", metric: str = "bytes",
               top: int = 7, bucket: int | None = None) -> dict:
    col = GROUPABLE.get(group_by)
    if col is None:
        raise ValueError(f"cannot group by {group_by!r}")
    agg = {"bytes": "SUM(bytes)", "packets": "SUM(packets)", "flows": "COUNT(*)"}.get(metric)
    if agg is None:
        raise ValueError(f"unknown metric {metric!r}")
    bucket = bucket or pick_bucket(q.end - q.start)
    where, params = q.where()

    keys = [r["k"] for r in db.query(
        f"SELECT {col} AS k, {agg} AS v FROM flows WHERE {where} GROUP BY k "
        f"ORDER BY v DESC LIMIT ?", params + [top])]
    rows = db.query(
        f"SELECT CAST(ts_end / ? AS INTEGER) * ? AS b, {col} AS k, {agg} AS v FROM flows "
        f"WHERE {where} GROUP BY b, k", [bucket, bucket] + params)

    first = int(q.start // bucket) * bucket
    n = int(math.ceil((q.end - first) / bucket))
    index = {first + i * bucket: i for i in range(n)}
    series: dict = {k: [0] * n for k in keys}
    other = [0] * n
    for r in rows:
        i = index.get(int(r["b"]))
        if i is None:
            continue
        target = series.get(r["k"])
        if target is not None:
            target[i] += r["v"]
        else:
            other[i] += r["v"]
    labeler = Labeler(db) if col in ("local_ip", "remote_ip") else None
    out = [{"key": _key_str(col, k), "label": _label(col, k, labeler), "values": v}
           for k, v in series.items()]
    if any(other):
        out.append({"key": "__other__", "label": "Other", "values": other})
    return {"bucket": bucket, "metric": metric, "group_by": group_by,
            "timestamps": [first + i * bucket for i in range(n)], "series": out}


def _key_str(col: str, k) -> str:
    return str(k)


def _label(col: str, k, labeler: Labeler | None) -> str:
    if col == "proto":
        return proto_name(int(k))
    if labeler is not None:
        return labeler.label(k)
    return str(k)


def top(db: Database, q: Query, by: str = "remote_ip", limit: int = 20) -> list[dict]:
    if by == "conversation":
        cols, group = "local_ip, remote_ip", "local_ip, remote_ip"
    elif by in GROUPABLE:
        cols, group = f"{GROUPABLE[by]} AS key", "key"
    else:
        raise ValueError(f"cannot rank by {by!r}")
    where, params = q.where()
    rows = db.query(
        f"SELECT {cols}, SUM(bytes) AS bytes, SUM(packets) AS packets, COUNT(*) AS flows, "
        f"{DIRECTION_SUMS}, MIN(ts_start) AS first_seen, MAX(ts_end) AS last_seen, "
        f"COUNT(DISTINCT app) AS apps FROM flows WHERE {where} GROUP BY {group} "
        f"ORDER BY bytes DESC LIMIT ?", params + [limit])
    labeler = Labeler(db)
    for r in rows:
        if by == "conversation":
            r["key"] = f"{r['local_ip']} ↔ {r['remote_ip']}"
            r["label"] = f"{labeler.label(r['local_ip'])} ↔ {labeler.label(r['remote_ip'])}"
        elif by in ("local_ip", "remote_ip"):
            r["label"] = labeler.label(r["key"])
            dev = labeler.devices.get(r["key"])
            if dev:
                r["mac"], r["vendor"] = dev["mac"], dev["vendor"]
        elif by == "proto":
            r["label"] = proto_name(int(r["key"]))
        else:
            r["label"] = str(r["key"])
    return rows


def sankey(db: Database, q: Query, limit_devices: int = 8, limit_apps: int = 8,
           limit_remote: int = 12) -> dict:
    """device -> application -> remote destination, weighted by bytes."""
    q.exclude_lan = True
    where, params = q.where()
    rows = db.query(
        f"SELECT local_ip, app, remote_ip, SUM(bytes) AS bytes FROM flows WHERE {where} "
        f"GROUP BY local_ip, app, remote_ip", params)
    labeler = Labeler(db)

    def topn(key, n):
        totals: dict = {}
        for r in rows:
            totals[key(r)] = totals.get(key(r), 0) + r["bytes"]
        return set(sorted(totals, key=totals.get, reverse=True)[:n])

    dev_top = topn(lambda r: labeler.label(r["local_ip"]), limit_devices)
    app_top = topn(lambda r: r["app"], limit_apps)
    rem_top = topn(lambda r: labeler.label(r["remote_ip"]), limit_remote)
    links: dict[tuple[str, str], int] = {}
    for r in rows:
        d = labeler.label(r["local_ip"])
        d = f"dev:{d if d in dev_top else 'Other devices'}"
        a = f"app:{r['app'] if r['app'] in app_top else 'other apps'}"
        rem = labeler.label(r["remote_ip"])
        rem = f"dst:{rem if rem in rem_top else 'Other destinations'}"
        links[(d, a)] = links.get((d, a), 0) + r["bytes"]
        links[(a, rem)] = links.get((a, rem), 0) + r["bytes"]
    names = sorted({n for pair in links for n in pair})
    return {
        "nodes": [{"id": n, "name": n.split(":", 1)[1], "layer": n.split(":", 1)[0]}
                  for n in names],
        "links": [{"source": s, "target": t, "value": v} for (s, t), v in links.items()],
    }


def graph(db: Database, q: Query, limit: int = 80) -> dict:
    """Host communication graph: local devices and remote endpoints as nodes."""
    where, params = q.where()
    rows = db.query(
        f"SELECT local_ip, remote_ip, direction, SUM(bytes) AS bytes, COUNT(*) AS flows, "
        f"GROUP_CONCAT(DISTINCT app) AS apps FROM flows WHERE {where} "
        f"GROUP BY local_ip, remote_ip ORDER BY bytes DESC LIMIT ?", params + [limit])
    labeler = Labeler(db)
    nodes: dict[str, dict] = {}
    edges = []
    for r in rows:
        for ip, local in ((r["local_ip"], True), (r["remote_ip"], r["direction"] == "lan")):
            n = nodes.setdefault(ip, {"id": ip, "label": labeler.label(ip),
                                      "local": local, "bytes": 0})
            n["bytes"] += r["bytes"]
        edges.append({"source": r["local_ip"], "target": r["remote_ip"], "bytes": r["bytes"],
                      "flows": r["flows"], "apps": (r["apps"] or "").split(",")[:6]})
    return {"nodes": list(nodes.values()), "edges": edges}


def heatmap(db: Database, q: Query) -> dict:
    """Bytes by weekday x hour-of-day (local time) -- reveals usage rhythms."""
    where, params = q.where()
    rows = db.query(
        f"SELECT CAST(strftime('%w', ts_end, 'unixepoch', 'localtime') AS INTEGER) AS dow, "
        f"CAST(strftime('%H', ts_end, 'unixepoch', 'localtime') AS INTEGER) AS hour, "
        f"SUM(bytes) AS bytes FROM flows WHERE {where} GROUP BY dow, hour", params)
    grid = [[0] * 24 for _ in range(7)]
    for r in rows:
        grid[(r["dow"] + 6) % 7][r["hour"]] = r["bytes"]  # Monday first
    return {"days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], "grid": grid}


def distribution(db: Database, q: Query) -> dict:
    """Log-binned histograms of flow size and duration (heavy-tail analysis)."""
    where, params = q.where()
    size = db.query(
        f"SELECT CAST(log10(MAX(bytes,1)) * 2 AS INTEGER) AS bin, COUNT(*) AS flows, "
        f"SUM(bytes) AS bytes FROM flows WHERE {where} GROUP BY bin ORDER BY bin", params) \
        if _has_log10(db) else _size_bins_py(db, where, params)
    dur = db.query(
        f"SELECT CASE WHEN ts_end - ts_start < 1 THEN 0 WHEN ts_end - ts_start < 5 THEN 1 "
        f"WHEN ts_end - ts_start < 15 THEN 2 WHEN ts_end - ts_start < 60 THEN 3 "
        f"WHEN ts_end - ts_start < 300 THEN 4 ELSE 5 END AS bin, COUNT(*) AS flows, "
        f"SUM(bytes) AS bytes FROM flows WHERE {where} GROUP BY bin ORDER BY bin", params)
    dur_labels = ["<1s", "1-5s", "5-15s", "15-60s", "1-5m", ">5m"]
    # Fill empty bins so the x axis stays continuous.
    size_by = {r["bin"]: r for r in size}
    size_bins = range(min(size_by), max(size_by) + 1) if size_by else range(0)
    dur_by = {r["bin"]: r for r in dur}
    empty = {"flows": 0, "bytes": 0}
    return {
        "size": [{"label": _size_label(b), "flows": size_by.get(b, empty)["flows"],
                  "bytes": size_by.get(b, empty)["bytes"]} for b in size_bins],
        "duration": [{"label": label, "flows": dur_by.get(i, empty)["flows"],
                      "bytes": dur_by.get(i, empty)["bytes"]}
                     for i, label in enumerate(dur_labels)] if dur_by else [],
    }


_LOG10: bool | None = None


def _has_log10(db: Database) -> bool:
    global _LOG10
    if _LOG10 is None:
        try:
            db.query("SELECT log10(10)")
            _LOG10 = True
        except Exception:
            _LOG10 = False
    return _LOG10


def _size_bins_py(db: Database, where: str, params: list) -> list[dict]:
    bins: dict[int, dict] = {}
    for r in db.query(f"SELECT bytes FROM flows WHERE {where}", params):
        b = int(math.log10(max(r["bytes"], 1)) * 2)
        e = bins.setdefault(b, {"bin": b, "flows": 0, "bytes": 0})
        e["flows"] += 1
        e["bytes"] += r["bytes"]
    return [bins[k] for k in sorted(bins)]


def _size_label(b: int) -> str:
    lo = 10 ** (b / 2)
    for unit, div in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if lo >= div:
            return f"≥{lo / div:.3g} {unit}"
    return f"≥{lo:.0f} B"


FLOW_COLUMNS = ["id", "ts_start", "ts_end", "src_ip", "dst_ip", "src_port", "dst_port",
                "proto", "bytes", "packets", "tcp_flags", "direction", "local_ip",
                "remote_ip", "local_port", "remote_port", "app", "source", "exporter"]
SORTABLE = {"ts_end", "bytes", "packets", "ts_start"}


def flows(db: Database, q: Query, limit: int = 100, offset: int = 0,
          sort: str = "ts_end", desc: bool = True) -> dict:
    if sort not in SORTABLE:
        sort = "ts_end"
    where, params = q.where()
    total = db.query_one(f"SELECT COUNT(*) AS n FROM flows WHERE {where}", params)["n"]
    rows = db.query(
        f"SELECT {', '.join(FLOW_COLUMNS)} FROM flows WHERE {where} "
        f"ORDER BY {sort} {'DESC' if desc else 'ASC'} LIMIT ? OFFSET ?",
        params + [limit, offset])
    labeler = Labeler(db)
    for r in rows:
        r["proto_name"] = proto_name(r["proto"])
        r["local_name"] = labeler.name(r["local_ip"])
        r["remote_name"] = labeler.name(r["remote_ip"])
    return {"total": total, "rows": rows}


def export_rows(db: Database, q: Query, fmt: str = "csv",
                chunk: int = 5000) -> Iterator[str]:
    """Stream flows as CSV or JSON-lines for offline analysis (pandas, R...)."""
    import json

    where, params = q.where()
    labeler = Labeler(db)
    cols = FLOW_COLUMNS + ["proto_name", "local_name", "remote_name"]
    last_id = 0
    if fmt == "csv":
        buf = io.StringIO()
        csv.writer(buf).writerow(cols)
        yield buf.getvalue()
    while True:
        rows = db.query(
            f"SELECT {', '.join(FLOW_COLUMNS)} FROM flows WHERE {where} AND id > ? "
            f"ORDER BY id LIMIT ?", params + [last_id, chunk])
        if not rows:
            break
        last_id = rows[-1]["id"]
        buf = io.StringIO()
        writer = csv.writer(buf)
        for r in rows:
            r["proto_name"] = proto_name(r["proto"])
            r["local_name"] = labeler.name(r["local_ip"])
            r["remote_name"] = labeler.name(r["remote_ip"])
            if fmt == "csv":
                writer.writerow([r[c] for c in cols])
            else:
                buf.write(json.dumps(r) + "\n")
        yield buf.getvalue()


def interface_history(db: Database, iface: str, start: float, end: float,
                      bucket: int | None = None) -> dict:
    bucket = bucket or pick_bucket(end - start)
    rows = db.query(
        "SELECT CAST(ts / ? AS INTEGER) * ? AS b, AVG(rx_rate) AS rx, AVG(tx_rate) AS tx, "
        "MAX(rx_rate) AS rx_max, MAX(tx_rate) AS tx_max, SUM(rx_errors) AS rx_errors, "
        "SUM(tx_errors) AS tx_errors FROM iface_samples WHERE iface = ? AND ts >= ? AND ts < ? "
        "GROUP BY b ORDER BY b", [bucket, bucket, iface, start, end])
    return {"iface": iface, "bucket": bucket, "points": rows}


def device_traffic(db: Database, ip: str, q: Query) -> dict:
    q.local_ip = ip
    return {
        "summary": summary(db, q),
        "timeseries": timeseries(db, q, group_by="direction"),
        "apps": top(db, q, by="app", limit=10),
        "destinations": top(db, Query(**{**q.__dict__, "exclude_lan": True}),
                            by="remote_ip", limit=15),
    }
