"""OpenWrt driver: SSH + uci/ubus.

Requirements on the router: SSH (dropbear) access as root, which is the
default. Configuration changes go through ``uci`` and are committed + the
relevant service reloaded, exactly as LuCI does. Every user-supplied value is
validated by the API models *and* shell-quoted here.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import shlex
import time
from typing import Awaitable, Callable

from ..config import RouterConfig
from ..models import (ArpEntry, CommandResult, DnsConfig, DnsConfigIn, FirewallRule,
                      FirewallRuleIn, Interface, Lease, LogEntry, PortForward,
                      PortForwardIn, Route, RouteIn, StaticLeaseIn, SystemInfo,
                      WifiNetwork, WifiUpdate)
from .base import ALL_CAPABILITIES, DriverError, RouterDriver

q = shlex.quote

Runner = Callable[[str], Awaitable[tuple[int, bytes]]]


# ---------------------------------------------------------------------------
# Parsers (pure functions, unit tested)
# ---------------------------------------------------------------------------
def parse_uci(text: str) -> dict[str, dict]:
    """Parse ``uci -X show <config>`` output into {section: {option: value}}.
    Section type is stored under ``.type``; list options become lists."""
    sections: dict[str, dict] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, raw = line.partition("=")
        parts = key.split(".")
        if len(parts) == 2:
            sections.setdefault(parts[1], {})[".type"] = raw.strip()
            continue
        if len(parts) != 3:
            continue
        try:
            values = shlex.split(raw)
        except ValueError:
            values = [raw.strip("'")]
        section = sections.setdefault(parts[1], {})
        section[parts[2]] = values if len(values) != 1 else values[0]
    return sections


def as_list(value) -> list[str]:
    if value is None:
        return []
    return value if isinstance(value, list) else str(value).split()


def parse_proc_net_dev(text: str) -> dict[str, dict[str, int]]:
    out = {}
    for line in text.splitlines():
        if ":" not in line or "|" in line:
            continue
        name, _, rest = line.partition(":")
        f = rest.split()
        if len(f) < 16:
            continue
        n = [int(x) for x in f[:16]]
        out[name.strip()] = {
            "rx_bytes": n[0], "rx_packets": n[1], "rx_errors": n[2], "rx_dropped": n[3],
            "tx_bytes": n[8], "tx_packets": n[9], "tx_errors": n[10], "tx_dropped": n[11],
        }
    return out


def parse_dhcp_leases(text: str) -> list[Lease]:
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 4 or ":" not in f[1]:
            continue
        expires = float(f[0]) if f[0].isdigit() and f[0] != "0" else None
        out.append(Lease(mac=f[1].lower(), ip=f[2], hostname=None if f[3] == "*" else f[3],
                         expires=expires))
    return out


def parse_proc_arp(text: str) -> list[ArpEntry]:
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and f[2] != "0x0" and f[3] != "00:00:00:00:00:00":
            out.append(ArpEntry(ip=f[0], mac=f[3].lower(), iface=f[5]))
    return out


def parse_ip_route(text: str) -> list[Route]:
    out = []
    for i, line in enumerate(text.splitlines()):
        f = line.split()
        if not f or f[0] in ("broadcast", "local", "unreachable", "multicast"):
            continue
        dst = "0.0.0.0/0" if f[0] == "default" else f[0]
        r = Route(id=f"k{i}", dst=dst)
        for key, attr in (("via", "gateway"), ("dev", "iface"), ("metric", "metric")):
            if key in f and f.index(key) + 1 < len(f):
                val = f[f.index(key) + 1]
                setattr(r, attr, int(val) if attr == "metric" else val)
        r.active = "linkdown" not in f
        out.append(r)
    return out


def parse_logread(text: str) -> list[LogEntry]:
    out = []
    for line in text.splitlines():
        # "Sat Nov 14 10:00:01 2026 daemon.info dnsmasq[1234]: message"
        parts = line.split(None, 7)
        if len(parts) < 8:
            if line.strip():
                out.append(LogEntry(message=line.strip()))
            continue
        try:
            ts = time.mktime(time.strptime(" ".join(parts[:5]), "%a %b %d %H:%M:%S %Y"))
        except ValueError:
            out.append(LogEntry(message=line.strip()))
            continue
        level = parts[5].split(".")[-1]
        source = parts[6].rstrip(":").split("[")[0]
        out.append(LogEntry(ts=ts, level=level, source=source, message=parts[7]))
    return out


def _chain_for(sec: dict) -> str:
    if sec.get("dest"):
        return "forward" if sec.get("src") else "output"
    return "input"


def uci_to_rule(sid: str, sec: dict) -> FirewallRule:
    target = str(sec.get("target", "DROP")).lower()
    proto_list = as_list(sec.get("proto"))
    proto = "any"
    if set(proto_list) == {"tcp", "udp"} or proto_list == ["tcpudp"]:
        proto = "tcp+udp"
    elif len(proto_list) == 1 and proto_list[0] in ("tcp", "udp", "icmp"):
        proto = proto_list[0]
    name = sec.get("name") or sid
    return FirewallRule(
        id=sid, name=name, enabled=sec.get("enabled", "1") != "0", chain=_chain_for(sec),
        action=target if target in ("accept", "drop", "reject") else "drop", proto=proto,
        src=(as_list(sec.get("src_ip")) or [None])[0], src_port=sec.get("src_port"),
        dst=(as_list(sec.get("dest_ip")) or [None])[0], dst_port=sec.get("dest_port"),
        src_mac=(as_list(sec.get("src_mac")) or [None])[0],
        managed=str(name).startswith("rerouter-"),
    )


def uci_to_forward(sid: str, sec: dict) -> PortForward:
    proto_list = as_list(sec.get("proto")) or ["tcp", "udp"]
    proto = "tcp+udp" if len(proto_list) > 1 else proto_list[0]
    ext = sec.get("src_dport", "")
    return PortForward(
        id=sid, name=sec.get("name") or sid, enabled=sec.get("enabled", "1") != "0",
        proto=proto if proto in ("tcp", "udp") else "tcp+udp", ext_port=ext,
        int_ip=sec.get("dest_ip", ""), int_port=sec.get("dest_port", ext),
        src=sec.get("src_ip"),
    )


def _uci_proto(proto: str) -> str:
    return {"any": "all", "tcp+udp": "tcp udp"}.get(proto, proto)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
class OpenWrtRouter(RouterDriver):
    name = "openwrt"
    capabilities = set(ALL_CAPABILITIES)

    def __init__(self, cfg: RouterConfig, runner: Runner | None = None):
        self.cfg = cfg
        self._runner = runner
        self._conn = None
        self._lock = asyncio.Lock()
        self._prev_cpu: tuple[int, int] | None = None

    async def connect(self) -> None:
        if self._runner is not None:
            return
        import asyncssh  # imported lazily so the simulator works without it

        async with self._lock:
            if self._conn is not None:
                return
            keys = [self.cfg.key_file] if self.cfg.key_file else None
            self._conn = await asyncio.wait_for(asyncssh.connect(
                self.cfg.host, port=self.cfg.port or 22, username=self.cfg.username,
                password=self.cfg.password, client_keys=keys,
                known_hosts=self.cfg.known_hosts or None,
            ), timeout=self.cfg.timeout)

    async def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    async def _exec(self, cmd: str, timeout: float | None = None) -> tuple[int, bytes]:
        if self._runner is not None:
            return await self._runner(cmd)
        await self.connect()
        try:
            res = await asyncio.wait_for(self._conn.run(cmd, encoding=None, check=False),
                                         timeout=timeout or self.cfg.timeout * 3)
        except (OSError, asyncio.TimeoutError) as exc:
            await self.close()  # force reconnect next time
            raise DriverError(f"ssh command failed: {exc}") from exc
        out = (res.stdout or b"") + ((res.stderr or b"") if res.exit_status else b"")
        return res.exit_status or 0, out

    async def sh(self, cmd: str, check: bool = True, timeout: float | None = None) -> str:
        status, out = await self._exec(cmd, timeout)
        text = out.decode("utf-8", "replace")
        if check and status != 0:
            raise DriverError(text.strip() or f"command failed ({status})")
        return text

    async def uci(self, config: str) -> dict[str, dict]:
        return parse_uci(await self.sh(f"uci -X show {q(config)} 2>/dev/null", check=False))

    async def _apply(self, commands: list[str], config: str, reload: str) -> None:
        script = " && ".join(commands + [f"uci commit {q(config)}", reload])
        await self.sh(script)

    # -- read ------------------------------------------------------------------
    async def system_info(self) -> SystemInfo:
        out = await self.sh(
            "ubus call system board; echo '@@'; ubus call system info; echo '@@';"
            " cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null; echo '@@';"
            " head -1 /proc/stat", check=False)
        board_s, info_s, temp_s, stat_s = (out.split("@@") + ["", "", "", ""])[:4]
        board = json.loads(board_s) if board_s.strip() else {}
        info = json.loads(info_s) if info_s.strip() else {}
        mem = info.get("memory", {})
        release = board.get("release", {})
        cpu = None
        f = stat_s.split()
        if len(f) > 5 and f[0] == "cpu":
            vals = [int(x) for x in f[1:]]
            total, idle = sum(vals), vals[3] + (vals[4] if len(vals) > 4 else 0)
            if self._prev_cpu and total > self._prev_cpu[0]:
                cpu = 100.0 * (1 - (idle - self._prev_cpu[1]) / (total - self._prev_cpu[0]))
            self._prev_cpu = (total, idle)
        return SystemInfo(
            hostname=board.get("hostname", self.cfg.host), model=board.get("model", "OpenWrt"),
            firmware=release.get("description") or release.get("version", "unknown"),
            uptime_s=int(info.get("uptime", 0)),
            load=[round(x / 65536, 2) for x in info.get("load", [])],
            cpu_percent=round(cpu, 1) if cpu is not None else None,
            mem_total=mem.get("total"), mem_free=(mem.get("available") or mem.get("free")),
            temperature_c=round(int(temp_s.strip()) / 1000, 1) if temp_s.strip().isdigit()
            else None,
            extra={"kernel": board.get("kernel", ""), "target": release.get("target", "")},
        )

    async def interfaces(self) -> list[Interface]:
        script = (
            "for d in /sys/class/net/*; do n=${d##*/}; t=other;"
            " [ -d $d/bridge ] && t=bridge; [ -d $d/wireless -o -d $d/phy80211 ] && t=wireless;"
            " echo \"$n $(cat $d/address 2>/dev/null || echo -) $(cat $d/mtu) "
            "$(cat $d/operstate) $(cat $d/flags) $(cat $d/speed 2>/dev/null || echo -) $t\";"
            " done; echo '@@'; cat /proc/net/dev; echo '@@'; ip -o addr show; echo '@@';"
            " ubus call network.interface dump 2>/dev/null"
        )
        out = await self.sh(script, check=False)
        links_s, dev_s, addr_s, dump_s = (out.split("@@") + ["", "", "", ""])[:4]
        counters = parse_proc_net_dev(dev_s)
        addrs: dict[str, list[str]] = {}
        for line in addr_s.splitlines():
            f = line.split()
            if len(f) >= 4 and f[2] in ("inet", "inet6"):
                addrs.setdefault(f[1].rstrip(":").split("@")[0], []).append(f[3])
        roles: dict[str, str] = {}
        try:
            for item in json.loads(dump_s).get("interface", []):
                dev = item.get("l3_device") or item.get("device")
                if dev and item.get("interface") != "loopback":
                    roles.setdefault(dev, item["interface"])
        except (ValueError, AttributeError):
            pass
        result = []
        for line in links_s.splitlines():
            f = line.split()
            if len(f) < 7 or f[0] == "lo":
                continue
            name, mac, mtu, oper, flags, speed, kind = f[:7]
            if kind == "other":
                kind = ("tunnel" if name.startswith(("wg", "tun", "tap")) else
                        "vlan" if "." in name else "ppp" if name.startswith("ppp") else "ethernet")
            iface = Interface(
                name=name, kind=kind, role=roles.get(name), mac=None if mac == "-" else mac,
                mtu=int(mtu) if mtu.isdigit() else None,
                up=oper in ("up", "unknown"), enabled=bool(int(flags, 16) & 1),
                speed_mbps=int(speed) if speed.lstrip("-").isdigit() and int(speed) > 0
                else None,
                addresses=addrs.get(name, []), **counters.get(name, {}),
            )
            result.append(iface)
        return result

    async def set_interface_enabled(self, name: str, enabled: bool) -> None:
        net = await self.uci("network")
        logical = [sid for sid, s in net.items() if s.get(".type") == "interface"
                   and (s.get("device") == name or sid == name)]
        if logical:
            await self.sh(f"{'ifup' if enabled else 'ifdown'} {q(logical[0])}")
        else:
            await self.sh(f"ip link set dev {q(name)} {'up' if enabled else 'down'}")

    async def leases(self) -> list[Lease]:
        out = await self.sh("cat /tmp/dhcp.leases 2>/dev/null", check=False)
        leases = parse_dhcp_leases(out)
        static = await self._static_leases()
        by_mac = {s.mac: s for s in static}
        for lease in leases:
            if lease.mac in by_mac:
                lease.static = True
                lease.id = by_mac[lease.mac].id
        seen = {lease.mac for lease in leases}
        return leases + [s for s in static if s.mac not in seen]

    async def _static_leases(self) -> list[Lease]:
        out = []
        for sid, sec in (await self.uci("dhcp")).items():
            if sec.get(".type") != "host":
                continue
            for mac in as_list(sec.get("mac")):
                out.append(Lease(id=sid, mac=mac.lower(), ip=sec.get("ip", ""),
                                 hostname=sec.get("name"), static=True))
        return out

    async def arp(self) -> list[ArpEntry]:
        return parse_proc_arp(await self.sh("cat /proc/net/arp", check=False))

    async def routes(self) -> list[Route]:
        kernel = parse_ip_route(await self.sh("ip -4 route show table main", check=False))
        static = []
        for sid, sec in (await self.uci("network")).items():
            if sec.get(".type") not in ("route", "route6"):
                continue
            target = sec.get("target", "")
            if sec.get("netmask") and "/" not in target:
                target = str(ipaddress.ip_network(f"{target}/{sec['netmask']}", strict=False))
            static.append(Route(id=sid, dst=target, gateway=sec.get("gateway"),
                                iface=sec.get("interface"), static=True,
                                metric=int(sec["metric"]) if sec.get("metric", "").isdigit()
                                else None, comment=sec.get("comment")))
        static_dsts = {r.dst for r in static}
        return static + [r for r in kernel if r.dst not in static_dsts]

    async def firewall_rules(self) -> list[FirewallRule]:
        fw = await self.uci("firewall")
        return [uci_to_rule(sid, s) for sid, s in fw.items() if s.get(".type") == "rule"]

    async def port_forwards(self) -> list[PortForward]:
        fw = await self.uci("firewall")
        return [uci_to_forward(sid, s) for sid, s in fw.items()
                if s.get(".type") == "redirect" and s.get("target", "DNAT") == "DNAT"]

    async def wifi(self) -> list[WifiNetwork]:
        cfg = await self.uci("wireless")
        out = []
        for sid, sec in cfg.items():
            if sec.get(".type") != "wifi-iface":
                continue
            radio = cfg.get(sec.get("device", ""), {})
            band = radio.get("band") or radio.get("hwmode", "")
            band = {"2g": "2.4 GHz", "5g": "5 GHz", "6g": "6 GHz", "11g": "2.4 GHz",
                    "11a": "5 GHz"}.get(band, band or None)
            out.append(WifiNetwork(
                id=sid, ssid=sec.get("ssid", ""), band=band, channel=radio.get("channel"),
                encryption=sec.get("encryption"),
                enabled=sec.get("disabled", "0") != "1" and radio.get("disabled", "0") != "1",
                hidden=sec.get("hidden", "0") == "1"))
        return out

    async def dns(self) -> DnsConfig:
        cfg = await self.uci("dhcp")
        for sec in cfg.values():
            if sec.get(".type") == "dnsmasq":
                return DnsConfig(servers=as_list(sec.get("server")),
                                 local_domain=sec.get("domain"))
        return DnsConfig()

    async def logs(self, limit: int = 200) -> list[LogEntry]:
        out = await self.sh(f"logread -l {int(limit)}", check=False)
        return list(reversed(parse_logread(out)))

    # -- write -----------------------------------------------------------------
    async def add_static_lease(self, lease: StaticLeaseIn) -> Lease:
        sid = (await self.sh("uci add dhcp host")).strip()
        cmds = [f"uci set dhcp.{sid}.mac={q(lease.mac)}", f"uci set dhcp.{sid}.ip={q(lease.ip)}"]
        if lease.hostname:
            cmds.append(f"uci set dhcp.{sid}.name={q(lease.hostname)}")
        await self._apply(cmds, "dhcp", "/etc/init.d/dnsmasq reload")
        return Lease(id=sid, mac=lease.mac, ip=lease.ip, hostname=lease.hostname, static=True)

    async def delete_static_lease(self, lease_id: str) -> None:
        await self._delete_section("dhcp", lease_id, "host", "/etc/init.d/dnsmasq reload")

    async def add_route(self, route: RouteIn) -> Route:
        sid = (await self.sh("uci add network route")).strip()
        cmds = [f"uci set network.{sid}.interface={q(route.iface or 'lan')}",
                f"uci set network.{sid}.target={q(route.dst)}"]
        if route.gateway:
            cmds.append(f"uci set network.{sid}.gateway={q(route.gateway)}")
        if route.metric is not None:
            cmds.append(f"uci set network.{sid}.metric={int(route.metric)}")
        if route.comment:
            cmds.append(f"uci set network.{sid}.comment={q(route.comment)}")
        await self._apply(cmds, "network", "/etc/init.d/network reload")
        return Route(id=sid, dst=route.dst, gateway=route.gateway, iface=route.iface or "lan",
                     metric=route.metric, static=True, comment=route.comment)

    async def delete_route(self, route_id: str) -> None:
        await self._delete_section("network", route_id, ("route", "route6"),
                                   "/etc/init.d/network reload")

    async def add_firewall_rule(self, rule: FirewallRuleIn) -> FirewallRule:
        sid = (await self.sh("uci add firewall rule")).strip()
        p = f"firewall.{sid}"
        cmds = [f"uci set {p}.name={q(rule.name)}", f"uci set {p}.target={rule.action.upper()}",
                f"uci set {p}.enabled={'1' if rule.enabled else '0'}"]
        if rule.chain == "forward":
            cmds += [f"uci set {p}.src='*'", f"uci set {p}.dest='*'"]
        elif rule.chain == "input":
            cmds.append(f"uci set {p}.src='*'")
        else:
            cmds.append(f"uci set {p}.dest='*'")
        if rule.proto != "any":
            for proto in _uci_proto(rule.proto).split():
                cmds.append(f"uci add_list {p}.proto={q(proto)}")
        else:
            cmds.append(f"uci set {p}.proto=all")
        for opt, value in (("src_ip", rule.src), ("dest_ip", rule.dst),
                           ("src_port", rule.src_port), ("dest_port", rule.dst_port),
                           ("src_mac", rule.src_mac)):
            if value:
                cmds.append(f"uci set {p}.{opt}={q(value)}")
        await self._apply(cmds, "firewall", "/etc/init.d/firewall reload")
        return FirewallRule(id=sid, managed=rule.name.startswith("rerouter-"), **rule.model_dump())

    async def delete_firewall_rule(self, rule_id: str) -> None:
        await self._delete_section("firewall", rule_id, "rule", "/etc/init.d/firewall reload")

    async def set_firewall_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        await self._check_section("firewall", rule_id, "rule")
        await self._apply([f"uci set firewall.{rule_id}.enabled={'1' if enabled else '0'}"],
                          "firewall", "/etc/init.d/firewall reload")

    async def add_port_forward(self, fwd: PortForwardIn) -> PortForward:
        sid = (await self.sh("uci add firewall redirect")).strip()
        p = f"firewall.{sid}"
        cmds = [f"uci set {p}.name={q(fwd.name)}", f"uci set {p}.target=DNAT",
                f"uci set {p}.src=wan", f"uci set {p}.dest=lan",
                f"uci set {p}.src_dport={q(fwd.ext_port)}", f"uci set {p}.dest_ip={q(fwd.int_ip)}",
                f"uci set {p}.dest_port={q(fwd.int_port)}",
                f"uci set {p}.enabled={'1' if fwd.enabled else '0'}"]
        for proto in _uci_proto(fwd.proto).split():
            cmds.append(f"uci add_list {p}.proto={q(proto)}")
        if fwd.src:
            cmds.append(f"uci set {p}.src_ip={q(fwd.src)}")
        await self._apply(cmds, "firewall", "/etc/init.d/firewall reload")
        return PortForward(id=sid, **fwd.model_dump())

    async def delete_port_forward(self, fwd_id: str) -> None:
        await self._delete_section("firewall", fwd_id, "redirect", "/etc/init.d/firewall reload")

    async def update_wifi(self, net_id: str, update: WifiUpdate) -> WifiNetwork:
        cfg = await self.uci("wireless")
        sec = cfg.get(net_id)
        if not sec or sec.get(".type") != "wifi-iface":
            raise DriverError(f"no such wifi network: {net_id}")
        p = f"wireless.{net_id}"
        cmds = []
        if update.ssid is not None:
            cmds.append(f"uci set {p}.ssid={q(update.ssid)}")
        if update.key is not None:
            cmds.append(f"uci set {p}.key={q(update.key)}")
        if update.enabled is not None:
            cmds.append(f"uci set {p}.disabled={'0' if update.enabled else '1'}")
        if update.hidden is not None:
            cmds.append(f"uci set {p}.hidden={'1' if update.hidden else '0'}")
        if update.channel is not None and sec.get("device"):
            cmds.append(f"uci set wireless.{q(sec['device'])}.channel={q(update.channel)}")
        if cmds:
            await self._apply(cmds, "wireless", "wifi reload")
        return next(w for w in await self.wifi() if w.id == net_id)

    async def set_dns(self, cfg: DnsConfigIn) -> DnsConfig:
        p = "dhcp.@dnsmasq[0]"
        cmds = [f"(uci -q delete {p}.server || true)"]
        cmds += [f"uci add_list {p}.server={q(s)}" for s in cfg.servers]
        cmds.append(f"uci set {p}.noresolv=1" if cfg.servers else f"(uci -q delete {p}.noresolv || true)")
        await self._apply(cmds, "dhcp", "/etc/init.d/dnsmasq reload")
        return await self.dns()

    async def ping(self, host: str, count: int = 4) -> CommandResult:
        status, out = await self._exec(f"ping -c {int(count)} -W 2 {q(host)} 2>&1",
                                       timeout=count * 3 + 5)
        return CommandResult(ok=status == 0, output=out.decode("utf-8", "replace"))

    async def traceroute(self, host: str) -> CommandResult:
        status, out = await self._exec(f"traceroute -n -w 2 -q 1 -m 20 {q(host)} 2>&1",
                                       timeout=60)
        return CommandResult(ok=status == 0, output=out.decode("utf-8", "replace"))

    async def reboot(self) -> None:
        await self.sh("(sleep 1; reboot) >/dev/null 2>&1 &", check=False)
        await self.close()

    async def backup(self) -> tuple[str, bytes]:
        path = "/tmp/rerouter-backup.tar.gz"
        status, data = await self._exec(
            f"sysupgrade -b {path} >/dev/null 2>&1 && cat {path}; rm -f {path}", timeout=60)
        if status != 0 or not data:
            raise DriverError("sysupgrade -b failed")
        return f"backup-openwrt-{time.strftime('%Y%m%d-%H%M%S')}.tar.gz", data

    async def configure_flow_export(self, collector_ip: str, port: int) -> CommandResult:
        target = q(f"{collector_ip}:{int(port)}")
        script = (
            "command -v softflowd >/dev/null || { echo 'softflowd is not installed. Install it"
            " with: opkg update && opkg install softflowd (or apk add softflowd)'; exit 1; }; "
            "[ -n \"$(uci -q get softflowd.@softflowd[0])\" ] || uci add softflowd softflowd; "
            "uci set softflowd.@softflowd[0].enabled=1 && "
            "uci set softflowd.@softflowd[0].interface=br-lan && "
            f"uci set softflowd.@softflowd[0].host_port={target} && "
            "uci set softflowd.@softflowd[0].export_version=9 && "
            "uci commit softflowd && /etc/init.d/softflowd enable && "
            "/etc/init.d/softflowd restart && echo 'softflowd exporting NetFlow v9 to' "
            f"{target}"
        )
        status, out = await self._exec(script)
        return CommandResult(ok=status == 0, output=out.decode("utf-8", "replace"))

    # -- helpers ---------------------------------------------------------------
    async def _check_section(self, config: str, sid: str, types) -> None:
        types = (types,) if isinstance(types, str) else types
        sec = (await self.uci(config)).get(sid)
        if not sec or sec.get(".type") not in types:
            raise DriverError(f"{config}: no such section {sid!r}")

    async def _delete_section(self, config: str, sid: str, types, reload: str) -> None:
        await self._check_section(config, sid, types)
        await self._apply([f"uci delete {q(config)}.{q(sid)}"], config, reload)
