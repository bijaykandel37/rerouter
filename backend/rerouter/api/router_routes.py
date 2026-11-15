"""Router configuration, diagnostics and system endpoints (via the driver)."""

from __future__ import annotations

import asyncio
import socket
import time

from fastapi import APIRouter, Depends, HTTPException, Query as Q, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from .. import analytics
from ..core import Platform
from ..models import (DiagnosticRequest, DnsConfigIn, FirewallRuleIn, InterfaceUpdate,
                      PortForwardIn, RouteIn, StaticLeaseIn, WifiUpdate, validate_host,
                      validate_ip)
from .deps import call_driver, current_user, platform, read_driver

router = APIRouter(prefix="/api", tags=["router"])


# -- interfaces ----------------------------------------------------------------
@router.get("/interfaces")
async def interfaces(p: Platform = Depends(platform), _: str = Depends(current_user)):
    ifaces = await read_driver(p, p.driver.interfaces())
    rates = p.poller.rates
    return [{**i.model_dump(), "rate": rates.get(i.name)} for i in ifaces]


@router.patch("/interfaces/{name}")
async def set_interface(name: str, body: InterfaceUpdate, p: Platform = Depends(platform),
                        user: str = Depends(current_user)):
    await call_driver(p, user, "interface_toggle", p.driver.set_interface_enabled(
        name, body.enabled), {"interface": name, "enabled": body.enabled})
    return {"ok": True}


@router.get("/interfaces/{name}/history")
async def interface_history(name: str, range: str = Q("24h", pattern=r"^(1h|6h|24h|7d|30d)$"),
                            p: Platform = Depends(platform), _: str = Depends(current_user)):
    end = time.time()
    start = end - analytics.RANGES[range]
    return await p.db.run(analytics.interface_history, p.db, name, start, end)


# -- DHCP / ARP ----------------------------------------------------------------
@router.get("/dhcp/leases")
async def leases(p: Platform = Depends(platform), _: str = Depends(current_user)):
    return await read_driver(p, p.driver.leases())


@router.post("/dhcp/static")
async def add_static(body: StaticLeaseIn, p: Platform = Depends(platform),
                     user: str = Depends(current_user)):
    return await call_driver(p, user, "static_lease_add", p.driver.add_static_lease(body),
                             body.model_dump())


@router.delete("/dhcp/static/{lease_id}")
async def delete_static(lease_id: str, p: Platform = Depends(platform),
                        user: str = Depends(current_user)):
    await call_driver(p, user, "static_lease_delete", p.driver.delete_static_lease(lease_id),
                      {"id": lease_id})
    return {"ok": True}


@router.get("/arp")
async def arp(p: Platform = Depends(platform), _: str = Depends(current_user)):
    return await read_driver(p, p.driver.arp())


# -- routes --------------------------------------------------------------------
@router.get("/routes")
async def routes(p: Platform = Depends(platform), _: str = Depends(current_user)):
    return await read_driver(p, p.driver.routes())


@router.post("/routes")
async def add_route(body: RouteIn, p: Platform = Depends(platform),
                    user: str = Depends(current_user)):
    return await call_driver(p, user, "route_add", p.driver.add_route(body), body.model_dump())


@router.delete("/routes/{route_id}")
async def delete_route(route_id: str, p: Platform = Depends(platform),
                       user: str = Depends(current_user)):
    await call_driver(p, user, "route_delete", p.driver.delete_route(route_id), {"id": route_id})
    return {"ok": True}


# -- firewall ------------------------------------------------------------------
@router.get("/firewall/rules")
async def rules(p: Platform = Depends(platform), _: str = Depends(current_user)):
    return await read_driver(p, p.driver.firewall_rules())


@router.post("/firewall/rules")
async def add_rule(body: FirewallRuleIn, p: Platform = Depends(platform),
                   user: str = Depends(current_user)):
    return await call_driver(p, user, "firewall_rule_add", p.driver.add_firewall_rule(body),
                             body.model_dump())


class EnabledIn(BaseModel):
    enabled: bool


@router.patch("/firewall/rules/{rule_id}")
async def toggle_rule(rule_id: str, body: EnabledIn, p: Platform = Depends(platform),
                      user: str = Depends(current_user)):
    await call_driver(p, user, "firewall_rule_toggle",
                      p.driver.set_firewall_rule_enabled(rule_id, body.enabled),
                      {"id": rule_id, "enabled": body.enabled})
    return {"ok": True}


@router.delete("/firewall/rules/{rule_id}")
async def delete_rule(rule_id: str, p: Platform = Depends(platform),
                      user: str = Depends(current_user)):
    await call_driver(p, user, "firewall_rule_delete", p.driver.delete_firewall_rule(rule_id),
                      {"id": rule_id})
    return {"ok": True}


@router.get("/firewall/forwards")
async def forwards(p: Platform = Depends(platform), _: str = Depends(current_user)):
    return await read_driver(p, p.driver.port_forwards())


@router.post("/firewall/forwards")
async def add_forward(body: PortForwardIn, p: Platform = Depends(platform),
                      user: str = Depends(current_user)):
    return await call_driver(p, user, "port_forward_add", p.driver.add_port_forward(body),
                             body.model_dump())


@router.delete("/firewall/forwards/{fwd_id}")
async def delete_forward(fwd_id: str, p: Platform = Depends(platform),
                         user: str = Depends(current_user)):
    await call_driver(p, user, "port_forward_delete", p.driver.delete_port_forward(fwd_id),
                      {"id": fwd_id})
    return {"ok": True}


# -- wifi / dns ----------------------------------------------------------------
@router.get("/wifi")
async def wifi(p: Platform = Depends(platform), _: str = Depends(current_user)):
    return await read_driver(p, p.driver.wifi())


@router.patch("/wifi/{net_id}")
async def update_wifi(net_id: str, body: WifiUpdate, p: Platform = Depends(platform),
                      user: str = Depends(current_user)):
    details = body.model_dump(exclude_none=True)
    if "key" in details:
        details["key"] = "********"
    return await call_driver(p, user, "wifi_update", p.driver.update_wifi(net_id, body),
                             {"id": net_id, **details})


@router.get("/dns")
async def dns(p: Platform = Depends(platform), _: str = Depends(current_user)):
    return await read_driver(p, p.driver.dns())


@router.put("/dns")
async def set_dns(body: DnsConfigIn, p: Platform = Depends(platform),
                  user: str = Depends(current_user)):
    return await call_driver(p, user, "dns_update", p.driver.set_dns(body), body.model_dump())


# -- diagnostics ---------------------------------------------------------------
@router.post("/diagnostics/ping")
async def ping(body: DiagnosticRequest, p: Platform = Depends(platform),
               user: str = Depends(current_user)):
    return await call_driver(p, user, "ping", p.driver.ping(body.host, body.count),
                             audited=False)


@router.post("/diagnostics/traceroute")
async def traceroute(body: DiagnosticRequest, p: Platform = Depends(platform),
                     user: str = Depends(current_user)):
    return await call_driver(p, user, "traceroute", p.driver.traceroute(body.host),
                             audited=False)


class LookupIn(BaseModel):
    host: str


@router.post("/diagnostics/lookup")
async def lookup(body: LookupIn, p: Platform = Depends(platform), _: str = Depends(current_user)):
    """Forward/reverse DNS from the rerouter host, plus what rerouter learned."""
    try:
        host = validate_host(body.host)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    result: dict = {"query": host, "addresses": [], "reverse": None, "observed_name": None}
    try:
        ip = validate_ip(host)
        result["observed_name"] = p.sink.name_for(ip)
        try:
            result["reverse"] = (await asyncio.wait_for(
                asyncio.to_thread(socket.gethostbyaddr, ip), 5))[0]
        except (OSError, asyncio.TimeoutError):
            pass
    except ValueError:
        try:
            infos = await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, host, None), 5)
            result["addresses"] = sorted({i[4][0] for i in infos})
        except (OSError, asyncio.TimeoutError) as exc:
            result["error"] = str(exc)
    return result


@router.get("/logs")
async def logs(limit: int = Q(200, ge=1, le=2000), p: Platform = Depends(platform),
               _: str = Depends(current_user)):
    return await read_driver(p, p.driver.logs(limit))


# -- system --------------------------------------------------------------------
@router.get("/system")
async def system(p: Platform = Depends(platform), _: str = Depends(current_user)):
    info = await read_driver(p, p.driver.system_info())
    return info


@router.post("/system/reboot")
async def reboot(p: Platform = Depends(platform), user: str = Depends(current_user)):
    await call_driver(p, user, "reboot", p.driver.reboot())
    return {"ok": True}


@router.get("/system/backup")
async def backup(p: Platform = Depends(platform), user: str = Depends(current_user)):
    name, data = await call_driver(p, user, "backup", p.driver.backup())
    return Response(data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


class FlowExportIn(BaseModel):
    collector_ip: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)


@router.post("/system/flow-export")
async def flow_export(body: FlowExportIn, request: Request, p: Platform = Depends(platform),
                      user: str = Depends(current_user)):
    """Configure the router to export NetFlow to this rerouter instance."""
    collector = body.collector_ip or _guess_collector_ip(request, p)
    try:
        collector = validate_ip(collector)
    except ValueError:
        raise HTTPException(422, "collector_ip must be an IP address reachable from the router")
    port = body.port or p.cfg.netflow_port
    return await call_driver(p, user, "flow_export", p.driver.configure_flow_export(
        collector, port), {"collector": collector, "port": port})


def _guess_collector_ip(request: Request, p: Platform) -> str:
    """The local address the router would use to reach us."""
    host = p.cfg.router.host
    if host:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((host, 9))
                return s.getsockname()[0]
        except OSError:
            pass
    return request.url.hostname or ""
