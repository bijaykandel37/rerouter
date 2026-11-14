"""Decrypted-HTTP transactions: a token-authenticated ingest endpoint for the
mitmproxy addon, plus authenticated query/ranking endpoints for the UI.

This data only exists when the operator runs the mitmproxy integration against
devices they control (TLS interception with an installed CA). See
``docs/mitmproxy.md``. The ingest endpoint is disabled unless an ingest token
is configured (``REROUTER_INGEST_TOKEN``).
"""

from __future__ import annotations

import hmac
import time

from fastapi import APIRouter, Depends, Header, HTTPException, Query as Q, Request
from pydantic import BaseModel, Field

from ..analytics import RANGES, Labeler
from ..core import Platform
from .deps import audit, current_user, platform

router = APIRouter(prefix="/api", tags=["http"])


class HttpTxnIn(BaseModel):
    ts: float | None = None
    client_ip: str | None = Field(None, max_length=64)
    client_port: int | None = Field(None, ge=0, le=65535)
    method: str | None = Field(None, max_length=16)
    scheme: str | None = Field(None, max_length=8)
    host: str | None = Field(None, max_length=253)
    path: str | None = Field(None, max_length=4096)
    status: int | None = Field(None, ge=0, le=599)
    req_type: str | None = Field(None, max_length=128)
    req_bytes: int | None = Field(None, ge=0)
    resp_type: str | None = Field(None, max_length=128)
    resp_bytes: int | None = Field(None, ge=0)
    duration_ms: float | None = Field(None, ge=0)
    note: str | None = Field(None, max_length=2048)


class HttpBatch(BaseModel):
    transactions: list[HttpTxnIn] = Field(min_length=1, max_length=2000)


_INGEST_SQL = (
    "INSERT INTO http_transactions(ts, client_ip, client_port, method, scheme, host, path,"
    " status, req_type, req_bytes, resp_type, resp_bytes, duration_ms, note, source)"
    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'mitmproxy')"
)


def _check_token(p: Platform, authorization: str | None, x_ingest_token: str | None) -> None:
    configured = p.cfg.ingest_token
    if not configured:
        raise HTTPException(404, "HTTP ingest is disabled (set REROUTER_INGEST_TOKEN)")
    supplied = x_ingest_token
    if not supplied and authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if not supplied or not hmac.compare_digest(supplied, configured):
        raise HTTPException(401, "invalid ingest token")


@router.post("/ingest/http")
async def ingest_http(batch: HttpBatch, request: Request, p: Platform = Depends(platform),
                      authorization: str | None = Header(None),
                      x_ingest_token: str | None = Header(None)):
    _check_token(p, authorization, x_ingest_token)
    now = time.time()
    client_fallback = request.client.host if request.client else None
    rows = []
    for t in batch.transactions:
        rows.append((t.ts or now, t.client_ip or client_fallback, t.client_port, t.method,
                     t.scheme, (t.host or "").lower() or None, t.path, t.status, t.req_type,
                     t.req_bytes, t.resp_type, t.resp_bytes, t.duration_ms, t.note))
    await p.db.aexecutemany(_INGEST_SQL, rows)
    p.ingest["received"] += len(rows)
    p.ingest["last_ts"] = now
    return {"stored": len(rows)}


_HTTP_COLUMNS = ["id", "ts", "client_ip", "client_port", "method", "scheme", "host", "path",
                 "status", "req_type", "req_bytes", "resp_type", "resp_bytes", "duration_ms",
                 "note", "source"]
_HTTP_SORT = {"ts", "duration_ms", "resp_bytes", "req_bytes"}


def _window(range_: str | None, start: float | None, end: float | None) -> tuple[float, float]:
    end = end or time.time()
    if start is None:
        start = end - RANGES.get(range_ or "1h", 3600)
    return start, end


@router.get("/http", dependencies=[Depends(current_user)])
async def list_http(range: str = Q("6h", pattern=r"^(5m|15m|1h|6h|24h|7d|30d)$"),
                    start: float | None = None, end: float | None = None,
                    client_ip: str | None = None, host: str | None = None,
                    method: str | None = None, status: int | None = Q(None, ge=0, le=599),
                    q: str | None = None, limit: int = Q(100, ge=1, le=1000),
                    offset: int = Q(0, ge=0), sort: str = "ts", desc: bool = True,
                    p: Platform = Depends(platform)):
    start, end = _window(range, start, end)
    if sort not in _HTTP_SORT:
        sort = "ts"
    clauses = ["ts >= ?", "ts < ?"]
    params: list = [start, end]
    for col, val in (("client_ip", client_ip), ("host", host), ("method", method),
                     ("status", status)):
        if val not in (None, ""):
            clauses.append(f"{col} = ?")
            params.append(val)
    if q:
        clauses.append("(path LIKE ? OR host LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    where = " AND ".join(clauses)

    def run():
        db = p.db
        total = db.query_one(f"SELECT COUNT(*) AS n FROM http_transactions WHERE {where}",
                             params)["n"]
        rows = db.query(
            f"SELECT {', '.join(_HTTP_COLUMNS)} FROM http_transactions WHERE {where} "
            f"ORDER BY {sort} {'DESC' if desc else 'ASC'} LIMIT ? OFFSET ?",
            params + [limit, offset])
        labeler = Labeler(db)
        for r in rows:
            r["client_name"] = labeler.name(r["client_ip"])
        return {"total": total, "rows": rows}

    return await p.db.run(run)


@router.get("/http/top", dependencies=[Depends(current_user)])
async def top_http(range: str = Q("6h", pattern=r"^(5m|15m|1h|6h|24h|7d|30d)$"),
                   start: float | None = None, end: float | None = None,
                   by: str = Q("host", pattern=r"^(host|client_ip|status|method|resp_type)$"),
                   limit: int = Q(25, ge=1, le=200), p: Platform = Depends(platform)):
    start, end = _window(range, start, end)

    def run():
        db = p.db
        rows = db.query(
            f"SELECT {by} AS key, COUNT(*) AS requests, COALESCE(SUM(resp_bytes),0) AS bytes, "
            f"COUNT(DISTINCT client_ip) AS clients FROM http_transactions "
            f"WHERE ts >= ? AND ts < ? AND {by} IS NOT NULL GROUP BY key "
            f"ORDER BY requests DESC LIMIT ?", [start, end, limit])
        labeler = Labeler(db)
        for r in rows:
            r["label"] = labeler.label(r["key"]) if by == "client_ip" else str(r["key"])
        return rows

    return await p.db.run(run)


@router.get("/http/status", dependencies=[Depends(current_user)])
async def http_status(p: Platform = Depends(platform)):
    row = await p.db.aquery_one(
        "SELECT COUNT(*) AS stored, MAX(ts) AS last_ts, COUNT(DISTINCT client_ip) AS clients "
        "FROM http_transactions")
    return {"enabled": bool(p.cfg.ingest_token), "received_this_run": p.ingest["received"],
            **(row or {})}


@router.delete("/http", dependencies=[Depends(current_user)])
async def clear_http(before: float | None = None, p: Platform = Depends(platform),
                     user: str = Depends(current_user)):
    cutoff = before if before is not None else time.time()
    n = await p.db.aexecute("DELETE FROM http_transactions WHERE ts <= ?", (cutoff,))
    await audit(p, user, "http_clear", {"before": cutoff, "deleted": n})
    return {"deleted": n}
