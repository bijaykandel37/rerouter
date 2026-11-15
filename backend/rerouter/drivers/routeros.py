"""MikroTik RouterOS v7 driver using the REST API (``/rest``).

Enable it on the router with ``/ip service enable www-ssl`` (recommended, with
a certificate) or ``www``, and create a dedicated user with the ``full`` (or a
custom read/write) group for rerouter.
"""

from __future__ import annotations

import re
import time
from urllib.parse import quote

import httpx

from ..config import RouterConfig
from ..models import (ArpEntry, CommandResult, DnsConfig, DnsConfigIn, FirewallRule,
                      FirewallRuleIn, Interface, Lease, LogEntry, PortForward,
                      PortForwardIn, Route, RouteIn, StaticLeaseIn, SystemInfo,
                      WifiNetwork, WifiUpdate)
from .base import ALL_CAPABILITIES, DriverError, RouterDriver

_DUR = re.compile(r"(\d+)(w|d|h|ms|m|s)")
_DUR_MULT = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001}


def parse_duration(value: str | None) -> float:
    """RouterOS durations: '1w2d3h4m5s', '9m50s', '00:01:02', '120ms'."""
    if not value:
        return 0.0
    if ":" in value:
        parts = [float(p) for p in value.split(":")]
        while len(parts) < 3:
            parts.insert(0, 0)
        return parts[-3] * 3600 + parts[-2] * 60 + parts[-1]
    return sum(int(n) * _DUR_MULT[u] for n, u in _DUR.findall(value))


def _b(value) -> bool:
    return str(value).lower() in ("true", "yes")


def _i(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


_KIND = {"ether": "ethernet", "bridge": "bridge", "wlan": "wireless", "wifi": "wireless",
         "vlan": "vlan", "pppoe-out": "ppp", "wg": "tunnel", "loopback": "loopback"}


class RouterOSRouter(RouterDriver):
    name = "routeros"
    capabilities = set(ALL_CAPABILITIES)

    def __init__(self, cfg: RouterConfig, transport: httpx.AsyncBaseTransport | None = None):
        self.cfg = cfg
        scheme = "https" if cfg.use_https else "http"
        port = f":{cfg.port}" if cfg.port else ""
        self.client = httpx.AsyncClient(
            base_url=f"{scheme}://{cfg.host}{port}/rest/",
            auth=(cfg.username, cfg.password or ""), verify=cfg.verify_tls,
            timeout=cfg.timeout, transport=transport)
        self._wifi_api: str | None = None

    async def close(self) -> None:
        await self.client.aclose()

    async def _req(self, method: str, path: str, json=None, timeout: float | None = None):
        try:
            resp = await self.client.request(method, path, json=json,
                                             timeout=timeout or self.cfg.timeout)
        except httpx.HTTPError as exc:
            raise DriverError(f"RouterOS request failed: {exc}") from exc
        if resp.status_code >= 400:
            try:
                body = resp.json()
                msg = body.get("detail") or body.get("message") or resp.text
            except ValueError:
                msg = resp.text
            raise DriverError(f"RouterOS {method} {path}: {msg}")
        if not resp.content:
            return None
        return resp.json()

    async def get(self, path: str):
        return await self._req("GET", path)

    @staticmethod
    def _id(item_id: str) -> str:
        if not re.fullmatch(r"\*[0-9A-Fa-f]+", item_id):
            raise DriverError(f"invalid RouterOS id: {item_id!r}")
        return quote(item_id, safe="")

    # -- read ------------------------------------------------------------------
    async def system_info(self) -> SystemInfo:
        res = await self.get("system/resource")
        ident = await self.get("system/identity")
        temp = None
        try:
            for item in await self.get("system/health") or []:
                if item.get("name") in ("temperature", "cpu-temperature"):
                    temp = float(item.get("value"))
                    break
        except (DriverError, ValueError, TypeError):
            pass
        cpu = float(res.get("cpu-load", 0))
        return SystemInfo(
            hostname=ident.get("name", "MikroTik"),
            model=res.get("board-name", "RouterOS"),
            firmware=f"RouterOS {res.get('version', '?')}",
            uptime_s=int(parse_duration(res.get("uptime"))), cpu_percent=cpu,
            load=[round(cpu / 100, 2)], mem_total=_i(res.get("total-memory")) or None,
            mem_free=_i(res.get("free-memory")) or None, temperature_c=temp,
            extra={"architecture": res.get("architecture-name", ""),
                   "cpu": res.get("cpu", "")},
        )

    async def interfaces(self) -> list[Interface]:
        items = await self.get("interface")
        addrs: dict[str, list[str]] = {}
        for a in await self.get("ip/address") or []:
            addrs.setdefault(a.get("interface", ""), []).append(a.get("address", ""))
        try:
            for a in await self.get("ipv6/address") or []:
                if not _b(a.get("link-local")):
                    addrs.setdefault(a.get("interface", ""), []).append(a.get("address", ""))
        except DriverError:
            pass
        roles: dict[str, str] = {}
        try:
            for m in await self.get("interface/list/member") or []:
                roles.setdefault(m.get("interface", ""), m.get("list", "").lower())
        except DriverError:
            pass
        out = []
        for it in items:
            if it.get("type") == "loopback":
                continue
            name = it.get("name", "")
            out.append(Interface(
                name=name, kind=_KIND.get(it.get("type", ""), it.get("type", "ethernet")),
                role=roles.get(name), mac=(it.get("mac-address") or "").lower() or None,
                mtu=_i(it.get("actual-mtu") or it.get("mtu")) or None,
                up=_b(it.get("running")), enabled=not _b(it.get("disabled")),
                addresses=addrs.get(name, []), comment=it.get("comment"),
                rx_bytes=_i(it.get("rx-byte")), tx_bytes=_i(it.get("tx-byte")),
                rx_packets=_i(it.get("rx-packet")), tx_packets=_i(it.get("tx-packet")),
                rx_errors=_i(it.get("rx-error")), tx_errors=_i(it.get("tx-error")),
                rx_dropped=_i(it.get("rx-drop")), tx_dropped=_i(it.get("tx-drop")),
            ))
        return out

    async def _find_id(self, path: str, key: str, value: str) -> str:
        for it in await self.get(path):
            if it.get(key) == value:
                return it[".id"]
        raise DriverError(f"{path}: no item with {key}={value}")

    async def set_interface_enabled(self, name: str, enabled: bool) -> None:
        iid = await self._find_id("interface", "name", name)
        await self._req("PATCH", f"interface/{self._id(iid)}",
                        {"disabled": "false" if enabled else "true"})

    async def leases(self) -> list[Lease]:
        now = time.time()
        out = []
        for it in await self.get("ip/dhcp-server/lease") or []:
            exp = it.get("expires-after")
            out.append(Lease(
                id=it.get(".id"), mac=(it.get("mac-address") or "").lower(),
                ip=it.get("address", ""), hostname=it.get("host-name") or it.get("comment"),
                static=not _b(it.get("dynamic")),
                expires=now + parse_duration(exp) if exp else None))
        return out

    async def arp(self) -> list[ArpEntry]:
        return [ArpEntry(ip=it.get("address", ""), mac=(it.get("mac-address") or "").lower(),
                         iface=it.get("interface"))
                for it in await self.get("ip/arp") or [] if it.get("mac-address")]

    async def routes(self) -> list[Route]:
        out = []
        for it in await self.get("ip/route") or []:
            gw = it.get("gateway")
            imm = it.get("immediate-gw", "")
            out.append(Route(
                id=it.get(".id"), dst=it.get("dst-address", ""), gateway=gw,
                iface=imm.split("%")[-1] if "%" in imm else (it.get("interface") or None),
                metric=_i(it.get("distance"), None), static=_b(it.get("static")),
                active=_b(it.get("active", "true")), comment=it.get("comment")))
        return out

    @staticmethod
    def _rule(it: dict) -> FirewallRule:
        action = it.get("action", "accept")
        proto = it.get("protocol") or "any"
        return FirewallRule(
            id=it.get(".id"), name=it.get("comment") or f"{it.get('chain')}/{action}",
            enabled=not _b(it.get("disabled")),
            chain=it.get("chain") if it.get("chain") in ("input", "forward", "output")
            else "forward",
            action=action if action in ("accept", "drop", "reject") else "accept",
            proto=proto if proto in ("tcp", "udp", "icmp") else "any",
            src=it.get("src-address"), dst=it.get("dst-address"),
            src_port=it.get("src-port"), dst_port=it.get("dst-port"),
            src_mac=(it.get("src-mac-address") or "").lower() or None,
            managed=(it.get("comment") or "").startswith("rerouter-"))

    async def firewall_rules(self) -> list[FirewallRule]:
        return [self._rule(it) for it in await self.get("ip/firewall/filter") or []
                if not _b(it.get("dynamic"))]

    async def port_forwards(self) -> list[PortForward]:
        out = []
        for it in await self.get("ip/firewall/nat") or []:
            if it.get("chain") != "dstnat" or it.get("action") != "dst-nat":
                continue
            proto = it.get("protocol", "tcp")
            out.append(PortForward(
                id=it.get(".id"), name=it.get("comment") or f"dstnat {it.get('dst-port', '')}",
                enabled=not _b(it.get("disabled")),
                proto=proto if proto in ("tcp", "udp") else "tcp+udp",
                ext_port=it.get("dst-port", ""), int_ip=it.get("to-addresses", ""),
                int_port=it.get("to-ports") or it.get("dst-port", ""),
                src=it.get("src-address")))
        return out

    async def _wifi_path(self) -> str:
        if self._wifi_api is None:
            try:
                await self.get("interface/wifi")
                self._wifi_api = "interface/wifi"
            except DriverError:
                self._wifi_api = "interface/wireless"
        return self._wifi_api

    async def wifi(self) -> list[WifiNetwork]:
        path = await self._wifi_path()
        try:
            items = await self.get(path) or []
        except DriverError:
            return []
        clients: dict[str, int] = {}
        try:
            for reg in await self.get(f"{path}/registration-table") or []:
                clients[reg.get("interface", "")] = clients.get(reg.get("interface", ""), 0) + 1
        except DriverError:
            pass
        out = []
        for it in items:
            new = path == "interface/wifi"
            ssid = it.get("configuration.ssid") if new else it.get("ssid")
            band = it.get("channel.band") if new else it.get("band")
            out.append(WifiNetwork(
                id=it.get(".id"), ssid=ssid or it.get("name", ""),
                band=("5 GHz" if band and band.startswith("5") else
                      "2.4 GHz" if band and band.startswith("2") else band),
                channel=(it.get("channel.frequency") if new else it.get("frequency")),
                encryption=(it.get("security.authentication-types") if new
                            else it.get("security-profile")),
                enabled=not _b(it.get("disabled")),
                hidden=_b(it.get("configuration.hide-ssid") if new else it.get("hide-ssid")),
                clients=clients.get(it.get("name", ""), 0)))
        return out

    async def dns(self) -> DnsConfig:
        d = await self.get("ip/dns")
        servers = [s for s in (d.get("servers") or "").split(",") if s]
        return DnsConfig(servers=servers)

    async def logs(self, limit: int = 200) -> list[LogEntry]:
        items = await self.get("log") or []
        out = []
        today = time.strftime("%Y-%m-%d")
        for it in items[-limit:]:
            t = it.get("time", "")
            ts = None
            for fmt, val in (("%Y-%m-%d %H:%M:%S", t), ("%Y-%m-%d %H:%M:%S", f"{today} {t}"),
                             ("%b/%d/%Y %H:%M:%S", t)):
                try:
                    ts = time.mktime(time.strptime(val, fmt))
                    break
                except ValueError:
                    continue
            topics = (it.get("topics") or "").split(",")
            level = next((x for x in topics if x in ("debug", "info", "warning", "error",
                                                      "critical")), "info")
            out.append(LogEntry(ts=ts, level=level, source=topics[0] if topics else None,
                                message=it.get("message", "")))
        return list(reversed(out))

    # -- write -----------------------------------------------------------------
    async def add_static_lease(self, lease: StaticLeaseIn) -> Lease:
        body = {"address": lease.ip, "mac-address": lease.mac.upper()}
        if lease.hostname:
            body["comment"] = lease.hostname
        res = await self._req("PUT", "ip/dhcp-server/lease", body)
        return Lease(id=res.get(".id"), mac=lease.mac, ip=lease.ip, hostname=lease.hostname,
                     static=True)

    async def delete_static_lease(self, lease_id: str) -> None:
        await self._req("DELETE", f"ip/dhcp-server/lease/{self._id(lease_id)}")

    async def add_route(self, route: RouteIn) -> Route:
        body = {"dst-address": route.dst, "gateway": route.gateway or route.iface or ""}
        if route.metric is not None:
            body["distance"] = str(route.metric)
        if route.comment:
            body["comment"] = route.comment
        res = await self._req("PUT", "ip/route", body)
        return Route(id=res.get(".id"), dst=route.dst, gateway=route.gateway, iface=route.iface,
                     metric=route.metric, static=True, comment=route.comment)

    async def delete_route(self, route_id: str) -> None:
        await self._req("DELETE", f"ip/route/{self._id(route_id)}")

    async def add_firewall_rule(self, rule: FirewallRuleIn) -> FirewallRule:
        protos = ["tcp", "udp"] if rule.proto == "tcp+udp" else [rule.proto]
        first = None
        existing = await self.get("ip/firewall/filter") or []
        for proto in protos:
            body = {"chain": rule.chain, "action": rule.action, "comment": rule.name,
                    "disabled": "false" if rule.enabled else "true"}
            if proto != "any":
                body["protocol"] = proto
            for key, value in (("src-address", rule.src), ("dst-address", rule.dst),
                               ("src-port", rule.src_port), ("dst-port", rule.dst_port),
                               ("src-mac-address", rule.src_mac.upper() if rule.src_mac
                                else None)):
                if value:
                    body[key] = value
            if rule.action != "accept":
                # Block rules go to the top so fasttrack/established-accept can't bypass them.
                static = [it for it in existing if not _b(it.get("dynamic"))]
                if static:
                    body["place-before"] = static[0][".id"]
            res = await self._req("PUT", "ip/firewall/filter", body)
            first = first or res
        return self._rule(first)

    async def delete_firewall_rule(self, rule_id: str) -> None:
        await self._req("DELETE", f"ip/firewall/filter/{self._id(rule_id)}")

    async def set_firewall_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        await self._req("PATCH", f"ip/firewall/filter/{self._id(rule_id)}",
                        {"disabled": "false" if enabled else "true"})

    async def add_port_forward(self, fwd: PortForwardIn) -> PortForward:
        protos = ["tcp", "udp"] if fwd.proto == "tcp+udp" else [fwd.proto]
        first = None
        for proto in protos:
            body = {"chain": "dstnat", "action": "dst-nat", "protocol": proto,
                    "dst-port": fwd.ext_port, "to-addresses": fwd.int_ip,
                    "to-ports": fwd.int_port, "in-interface-list": "WAN",
                    "comment": fwd.name, "disabled": "false" if fwd.enabled else "true"}
            if fwd.src:
                body["src-address"] = fwd.src
            res = await self._req("PUT", "ip/firewall/nat", body)
            first = first or res
        return PortForward(id=first.get(".id"), **fwd.model_dump())

    async def delete_port_forward(self, fwd_id: str) -> None:
        await self._req("DELETE", f"ip/firewall/nat/{self._id(fwd_id)}")

    async def update_wifi(self, net_id: str, update: WifiUpdate) -> WifiNetwork:
        path = await self._wifi_path()
        new = path == "interface/wifi"
        body: dict[str, str] = {}
        if update.ssid is not None:
            body["configuration.ssid" if new else "ssid"] = update.ssid
        if update.enabled is not None:
            body["disabled"] = "false" if update.enabled else "true"
        if update.hidden is not None:
            body["configuration.hide-ssid" if new else "hide-ssid"] = (
                "yes" if update.hidden else "no")
        if update.channel is not None and update.channel != "auto":
            body["channel.frequency" if new else "frequency"] = update.channel
        if update.key is not None:
            if new:
                body["security.passphrase"] = update.key
            else:
                item = await self._req("GET", f"{path}/{self._id(net_id)}")
                profile = item.get("security-profile", "default")
                pid = await self._find_id("interface/wireless/security-profiles", "name", profile)
                await self._req("PATCH",
                                f"interface/wireless/security-profiles/{self._id(pid)}",
                                {"wpa2-pre-shared-key": update.key})
        if body:
            await self._req("PATCH", f"{path}/{self._id(net_id)}", body)
        return next(w for w in await self.wifi() if w.id == net_id)

    async def set_dns(self, cfg: DnsConfigIn) -> DnsConfig:
        await self._req("POST", "ip/dns/set", {"servers": ",".join(cfg.servers)})
        return await self.dns()

    async def ping(self, host: str, count: int = 4) -> CommandResult:
        res = await self._req("POST", "ping", {"address": host, "count": str(count)},
                              timeout=count * 3 + 5) or []
        lines, received = [], 0
        for r in res:
            if r.get("time"):
                received += 1
                lines.append(f"seq={r.get('seq')} from {r.get('host')} size={r.get('size')} "
                             f"ttl={r.get('ttl')} time={r.get('time')}")
            elif r.get("status"):
                lines.append(f"seq={r.get('seq')} {r.get('status')}")
        last = res[-1] if res else {}
        lines.append(f"\n{last.get('sent', count)} sent, {last.get('received', received)} "
                     f"received, {last.get('packet-loss', '?')}% loss, "
                     f"avg {last.get('avg-rtt', '?')}")
        return CommandResult(ok=received > 0, output="\n".join(lines))

    async def traceroute(self, host: str) -> CommandResult:
        res = await self._req("POST", "tool/traceroute", {"address": host, "count": "1"},
                              timeout=60) or []
        hops: dict[str, dict] = {}
        for r in res:  # the API returns one row per hop per round; keep the last
            hops[r.get(".section", str(len(hops)))] = r
        lines = [f"traceroute to {host}"]
        for i, r in enumerate(hops.values(), 1):
            lines.append(f"{i:2}  {r.get('address') or '*':<18} loss={r.get('loss', '?')}% "
                         f"last={r.get('last', '?')} avg={r.get('avg', '?')}")
        return CommandResult(ok=bool(hops), output="\n".join(lines))

    async def reboot(self) -> None:
        try:
            await self._req("POST", "system/reboot", {})
        except DriverError:
            pass  # the router may drop the connection while rebooting

    async def backup(self) -> tuple[str, bytes]:
        res = await self._req("POST", "execute", {"script": "/export", "as-string": ""},
                              timeout=60)
        text = res.get("ret", "") if isinstance(res, dict) else ""
        if not text:
            raise DriverError("export returned no data")
        return f"backup-routeros-{time.strftime('%Y%m%d-%H%M%S')}.rsc", text.encode()

    async def configure_flow_export(self, collector_ip: str, port: int) -> CommandResult:
        await self._req("POST", "ip/traffic-flow/set", {
            "enabled": "yes", "interfaces": "all", "active-flow-timeout": "1m",
            "inactive-flow-timeout": "15s"})
        targets = await self.get("ip/traffic-flow/target") or []
        if not any(t.get("dst-address") == collector_ip and _i(t.get("port")) == port
                   for t in targets):
            await self._req("PUT", "ip/traffic-flow/target", {
                "dst-address": collector_ip, "port": str(port), "version": "9"})
        return CommandResult(ok=True, output=(
            f"Traffic Flow enabled on all interfaces; exporting NetFlow v9 to "
            f"{collector_ip}:{port}"))
