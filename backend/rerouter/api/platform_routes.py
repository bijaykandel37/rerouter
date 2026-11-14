"""Platform endpoints: status, devices, alerts, settings, audit log, live stream."""

from __future__ import annotations

import asyncio
import json
import time
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query as Q, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from .. import analytics
from ..analytics import Query
from ..core import Platform
from ..models import normalize_mac
from ..netutil import mac_vendor
from ..settings import RuntimeSettings
from .deps import audit, call_driver, current_user, platform, token_from, traffic_query

router = APIRouter(prefix="/api", tags=["platform"])


@router.get("/status")
async def status(p: Platform = Depends(platform), _: str = Depends(current_user)):
    counts = await p.db.aquery_one(
        "SELECT (SELECT COUNT(*) FROM devices) AS devices, "
        "(SELECT COUNT(*) FROM alerts WHERE acknowledged = 0) AS open_alerts, "
        "(SELECT COUNT(*) FROM flows WHERE ts_end >= ?) AS flows_last_hour",
        (time.time() - 3600,))
    return {**p.status(), "counts": counts, "system": p.poller.system,
            "rates": p.poller.rates, "router_ips": p.poller.router_ips}


# -- devices -------------------------------------------------------------------
def _mac(mac: str) -> str:
    try:
        return normalize_mac(mac)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/devices")
async def devices(range: str = Q("24h", pattern=r"^(1h|6h|24h|7d|30d)$"),
                  p: Platform = Depends(platform), _: str = Depends(current_user)):
    now = time.time()
    since = now - analytics.RANGES[range]
    devs = await p.db.aquery("SELECT * FROM devices ORDER BY last_seen DESC")
    totals = {r["local_ip"]: r for r in await p.db.aquery(
        f"SELECT local_ip, {analytics.DIRECTION_SUMS}, COUNT(*) AS flows, "
        f"COUNT(DISTINCT remote_ip) AS peers, MAX(ts_end) AS last_flow FROM flows "
        f"WHERE ts_end >= ? GROUP BY local_ip", (since,))}
    online_window = max(3 * p.cfg.device_refresh_interval, 300)
    out = []
    for d in devs:
        t = totals.get(d["ip"], {})
        out.append({
            **d, "name": d["alias"] or d["hostname"] or d["mac"],
            "online": now - d["last_seen"] < online_window,
            "download": t.get("download") or 0, "upload": t.get("upload") or 0,
            "lan": t.get("lan") or 0, "flows": t.get("flows") or 0,
            "peers": t.get("peers") or 0, "last_flow": t.get("last_flow"),
        })
    return out


@router.get("/devices/{mac}")
async def device(mac: str, q: Query = Depends(traffic_query), p: Platform = Depends(platform),
                 _: str = Depends(current_user)):
    d = await p.db.aquery_one("SELECT * FROM devices WHERE mac = ?", (_mac(mac),))
    if not d:
        raise HTTPException(404, "unknown device")
    traffic = await p.db.run(analytics.device_traffic, p.db, d["ip"], q) if d["ip"] else None
    return {**d, "name": d["alias"] or d["hostname"] or d["mac"], "traffic": traffic}


class DeviceUpdate(BaseModel):
    alias: str | None = Field(default=None, max_length=64)
    notes: str | None = Field(default=None, max_length=2000)


@router.patch("/devices/{mac}")
async def update_device(mac: str, body: DeviceUpdate, p: Platform = Depends(platform),
                        user: str = Depends(current_user)):
    mac = _mac(mac)
    fields = body.model_dump(exclude_unset=True)
    if not fields:
        return {"ok": True}
    sets = ", ".join(f"{k} = ?" for k in fields)
    n = await p.db.aexecute(f"UPDATE devices SET {sets} WHERE mac = ?",
                            [v or None for v in fields.values()] + [mac])
    if not n:
        raise HTTPException(404, "unknown device")
    await audit(p, user, "device_update", {"mac": mac, **fields})
    return {"ok": True}


class BlockIn(BaseModel):
    blocked: bool


@router.post("/devices/{mac}/block")
async def block_device(mac: str, body: BlockIn, p: Platform = Depends(platform),
                       user: str = Depends(current_user)):
    mac = _mac(mac)
    await call_driver(p, user, "device_block" if body.blocked else "device_unblock",
                      p.driver.block_device(mac, body.blocked), {"mac": mac})
    now = time.time()
    await p.db.aexecute(
        "INSERT INTO devices(mac, vendor, first_seen, last_seen, blocked) VALUES (?,?,?,?,?) "
        "ON CONFLICT(mac) DO UPDATE SET blocked = excluded.blocked",
        (mac, mac_vendor(mac), now, now, 1 if body.blocked else 0))
    return {"ok": True}


@router.delete("/devices/{mac}")
async def forget_device(mac: str, p: Platform = Depends(platform),
                        user: str = Depends(current_user)):
    await p.db.aexecute("DELETE FROM devices WHERE mac = ?", (_mac(mac),))
    await audit(p, user, "device_forget", {"mac": mac})
    return {"ok": True}


# -- alerts --------------------------------------------------------------------
@router.get("/alerts")
async def alerts(unacked: bool = False, limit: int = Q(200, ge=1, le=2000),
                 severity: str | None = None, p: Platform = Depends(platform),
                 _: str = Depends(current_user)):
    sql = "SELECT * FROM alerts WHERE 1=1"
    params: list = []
    if unacked:
        sql += " AND acknowledged = 0"
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    rows = await p.db.aquery(sql + " ORDER BY ts DESC LIMIT ?", params + [limit])
    for r in rows:
        r["details"] = json.loads(r["details"] or "{}")
        r["acknowledged"] = bool(r["acknowledged"])
    return rows


@router.post("/alerts/{alert_id}/ack")
async def ack(alert_id: int, p: Platform = Depends(platform), _: str = Depends(current_user)):
    await p.db.aexecute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
    return {"ok": True}


@router.post("/alerts/ack-all")
async def ack_all(p: Platform = Depends(platform), user: str = Depends(current_user)):
    await p.db.aexecute("UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")
    await audit(p, user, "alerts_ack_all")
    return {"ok": True}


# -- settings & audit ----------------------------------------------------------
@router.get("/settings")
async def get_settings(p: Platform = Depends(platform), _: str = Depends(current_user)):
    cfg = p.cfg
    return {
        "runtime": p.settings.current,
        "static": {  # read-only, from config file / environment (no secrets)
            "driver": cfg.router.driver, "router_host": cfg.router.host or None,
            "netflow": {"enabled": cfg.netflow_enabled, "bind": cfg.netflow_bind,
                        "port": cfg.netflow_port},
            "capture_interface": cfg.capture_interface,
            "simulation": cfg.simulation_enabled, "poll_interval": cfg.poll_interval,
            "data_dir": str(cfg.data_dir),
        },
    }


@router.put("/settings")
async def put_settings(body: RuntimeSettings, p: Platform = Depends(platform),
                       user: str = Depends(current_user)):
    await p.settings.save(body)
    await audit(p, user, "settings_update", body.model_dump())
    return body


@router.get("/audit")
async def audit_log(limit: int = Q(200, ge=1, le=5000), p: Platform = Depends(platform),
                    _: str = Depends(current_user)):
    rows = await p.db.aquery("SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,))
    for r in rows:
        r["details"] = json.loads(r["details"] or "{}")
        r["ok"] = bool(r["ok"])
    return rows


# -- live stream ---------------------------------------------------------------
@router.websocket("/live")
async def live(ws: WebSocket):
    p: Platform = ws.app.state.platform
    origin = ws.headers.get("origin")
    if origin and urlparse(origin).netloc != ws.headers.get("host"):
        await ws.close(code=4403)
        return
    if await p.auth.user_for(token_from(ws) or ws.query_params.get("token")) is None:
        await ws.close(code=4401)
        return
    await ws.accept()
    await ws.send_json({"topic": "hello", "data": {
        "rates": p.poller.rates, "system": p.poller.system, "status": p.status()}})
    async with p.hub.subscribe() as queue:
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=20)
                except asyncio.TimeoutError:
                    msg = {"topic": "ping", "data": time.time()}
                await ws.send_json(msg)
        except (WebSocketDisconnect, RuntimeError):
            pass
