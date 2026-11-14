"""Periodic polling of the router: interface counters -> rates, device
inventory (DHCP leases + ARP), system health, and data retention."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time

from ..alerts import AlertEngine
from ..db import Database
from ..drivers import NotSupported, RouterDriver
from ..drivers.base import block_rule_name
from ..live import LiveHub
from ..models import Interface
from ..netutil import NetworkClassifier, mac_vendor
from ..settings import SettingsStore

log = logging.getLogger(__name__)

SAMPLE_EVERY = 30.0  # seconds between persisted interface samples


class Poller:
    def __init__(self, driver: RouterDriver, db: Database, hub: LiveHub, alerts: AlertEngine,
                 settings: SettingsStore, classifier: NetworkClassifier,
                 interval: float = 5.0, device_interval: float = 60.0,
                 on_router_names=None):
        self.driver = driver
        self.db = db
        self.hub = hub
        self.alerts = alerts
        self.settings = settings
        self.classifier = classifier
        self.interval = interval
        self.device_interval = device_interval
        self.router_ips: list[str] = []
        self.on_router_names = on_router_names
        self.rates: dict[str, dict] = {}
        self.system: dict | None = None
        self.interfaces: list[Interface] = []
        self.online: bool | None = None
        self.last_error: str | None = None
        self._prev: dict[str, tuple[float, Interface]] = {}
        self._stored: dict[str, tuple[float, Interface]] = {}
        self._up: dict[str, bool] = {}

    # -- loops -------------------------------------------------------------------
    async def run(self) -> None:
        last_devices = last_system = last_maint = 0.0
        while True:
            now = time.time()
            try:
                await self.poll_interfaces(now)
                if now - last_system >= 15:
                    last_system = now
                    await self.poll_system()
                if now - last_devices >= self.device_interval:
                    last_devices = now
                    await self.poll_devices(now)
                if self.online is False:
                    log.info("router reachable again")
                self.online = True
                self.last_error = None
            except NotSupported:
                pass
            except Exception as exc:  # router unreachable etc.
                self.last_error = str(exc) or type(exc).__name__
                if self.online is not False:
                    log.warning("router poll failed: %s", self.last_error)
                await self.alerts.raise_alert(
                    "router_unreachable", "critical",
                    f"Router is not responding: {self.last_error}", "router")
                self.online = False
            if now - last_maint >= 3600:
                last_maint = now
                try:
                    await self.maintenance()
                except Exception:
                    log.exception("maintenance failed")
            await asyncio.sleep(self.interval)

    async def poll_interfaces(self, now: float) -> None:
        ifaces = await self.driver.interfaces()
        self.interfaces = ifaces
        rates, samples = {}, []
        thresholds = self.settings.current.alerts
        for iface in ifaces:
            prev = self._prev.get(iface.name)
            rate = {"rx_rate": 0.0, "tx_rate": 0.0, "rx_pps": 0.0, "tx_pps": 0.0}
            if prev:
                rate = _rates(prev, (now, iface))
                errs = (iface.rx_errors - prev[1].rx_errors) + (iface.tx_errors - prev[1].tx_errors)
                if thresholds.interface_errors and errs >= thresholds.interface_errors:
                    await self.alerts.raise_alert(
                        "interface_errors", "warning",
                        f"Interface {iface.name}: {errs} errors in {now - prev[0]:.0f}s",
                        iface.name, {"errors": errs})
            self._prev[iface.name] = (now, iface)
            rates[iface.name] = {**rate, "up": iface.up, "role": iface.role}

            was_up = self._up.get(iface.name)
            if was_up is not None and was_up != iface.up and iface.enabled:
                await self.alerts.raise_alert(
                    "interface_state", "serious" if not iface.up else "info",
                    f"Interface {iface.name} is {'up' if iface.up else 'DOWN'}",
                    iface.name, cooldown=0)
            self._up[iface.name] = iface.up

            stored = self._stored.get(iface.name)
            if stored is None:
                self._stored[iface.name] = (now, iface)
            elif now - stored[0] >= SAMPLE_EVERY:
                r = _rates(stored, (now, iface))
                samples.append((now, iface.name, r["rx_rate"], r["tx_rate"], r["rx_pps"],
                                r["tx_pps"], max(0, iface.rx_errors - stored[1].rx_errors),
                                max(0, iface.tx_errors - stored[1].tx_errors)))
                self._stored[iface.name] = (now, iface)
        self.rates = rates
        if samples:
            await self.db.aexecutemany(
                "INSERT INTO iface_samples(ts, iface, rx_rate, tx_rate, rx_pps, tx_pps, "
                "rx_errors, tx_errors) VALUES (?,?,?,?,?,?,?,?)", samples)
        self._update_router_ips(ifaces)
        self.hub.publish("rates", {"ts": now, "interfaces": rates})

    def _update_router_ips(self, ifaces: list[Interface]) -> None:
        ips, names = [], {}
        for iface in ifaces:
            for addr in iface.addresses:
                try:
                    ip = str(ipaddress.ip_interface(addr).ip)
                except ValueError:
                    continue
                ips.append(ip)
                names[ip] = f"router ({iface.name})"
        if sorted(ips) != sorted(self.router_ips):
            self.router_ips = ips
            if self.on_router_names:
                self.on_router_names(names)
            s = self.settings.current
            self.classifier.update(s.lan_networks, s.router_ips + ips)

    async def poll_system(self) -> None:
        info = await self.driver.system_info()
        self.system = info.model_dump()
        self.hub.publish("system", self.system)

    async def poll_devices(self, now: float) -> None:
        try:
            leases = await self.driver.leases()
        except NotSupported:
            leases = []
        try:
            arp = await self.driver.arp()
        except NotSupported:
            arp = []
        try:
            blocked = {r.name for r in await self.driver.firewall_rules() if r.enabled}
        except NotSupported:
            blocked = set()

        seen: dict[str, dict] = {}
        own = set(self.router_ips)
        for entry in arp:
            # only LAN-side neighbours are devices (skip the ISP gateway etc.)
            if entry.ip not in own and self.classifier.is_local(entry.ip):
                seen[entry.mac] = {"ip": entry.ip, "hostname": None}
        for lease in leases:
            seen[lease.mac] = {"ip": lease.ip, "hostname": lease.hostname}

        existing = {r["mac"]: r for r in await self.db.aquery("SELECT * FROM devices")}
        new_devices = []

        def write(conn):
            for mac, info in seen.items():
                is_blocked = 1 if block_rule_name(mac) in blocked else 0
                if mac in existing:
                    conn.execute(
                        "UPDATE devices SET ip=?, hostname=COALESCE(?, hostname), last_seen=?,"
                        " blocked=? WHERE mac=?",
                        (info["ip"], info["hostname"], now, is_blocked, mac))
                else:
                    conn.execute(
                        "INSERT INTO devices(mac, ip, hostname, vendor, first_seen, last_seen,"
                        " blocked) VALUES (?,?,?,?,?,?,?)",
                        (mac, info["ip"], info["hostname"], mac_vendor(mac), now, now,
                         is_blocked))
                    new_devices.append((mac, info))
            # devices blocked by us are offline, keep their flag in sync
            for mac in existing:
                if mac not in seen:
                    conn.execute("UPDATE devices SET blocked=? WHERE mac=?",
                                 (1 if block_rule_name(mac) in blocked else 0, mac))

        await self.db.run(self.db.transaction, write)
        first_run = not existing
        if self.settings.current.alerts.new_device and not first_run:
            for mac, info in new_devices:
                await self.alerts.raise_alert(
                    "new_device", "info",
                    f"New device joined: {info['hostname'] or 'unknown'} {mac} "
                    f"({mac_vendor(mac) or 'unknown vendor'}) at {info['ip']}", mac)
        if new_devices or not existing:
            self.hub.publish("devices", {"count": len(seen)})

    async def maintenance(self) -> None:
        s = self.settings.current
        now = time.time()
        n = await self.db.aexecute("DELETE FROM flows WHERE ts_end < ?",
                                   (now - s.flow_retention_days * 86400,))
        await self.db.aexecute("DELETE FROM iface_samples WHERE ts < ?",
                               (now - s.sample_retention_days * 86400,))
        await self.db.aexecute("DELETE FROM sessions WHERE expires < ?", (now,))
        await self.db.aexecute("DELETE FROM alerts WHERE ts < ?", (now - 180 * 86400,))
        await self.db.aexecute("PRAGMA optimize")
        if n:
            log.info("retention: purged %s old flows", n)


def _rates(a: tuple[float, Interface], b: tuple[float, Interface]) -> dict:
    dt = max(b[0] - a[0], 1e-6)
    ia, ib = a[1], b[1]

    def d(x: int, y: int) -> float:
        return max(0, y - x) / dt  # counter reset/wrap -> 0

    return {"rx_rate": d(ia.rx_bytes, ib.rx_bytes), "tx_rate": d(ia.tx_bytes, ib.tx_bytes),
            "rx_pps": d(ia.rx_packets, ib.rx_packets), "tx_pps": d(ia.tx_packets, ib.tx_packets)}
