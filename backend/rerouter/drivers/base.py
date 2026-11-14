"""Router driver interface.

A driver translates rerouter's vendor-neutral model into a specific router's
management interface. Methods a driver cannot support raise
``NotSupported``; the API reports the driver's ``capabilities`` so the UI can
hide features that are unavailable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import (ArpEntry, CommandResult, DnsConfig, DnsConfigIn, FirewallRule,
                      FirewallRuleIn, Interface, Lease, LogEntry, PortForward,
                      PortForwardIn, Route, RouteIn, StaticLeaseIn, SystemInfo,
                      WifiNetwork, WifiUpdate)

ALL_CAPABILITIES = {
    "system", "interfaces", "interface_toggle", "leases", "static_leases", "arp",
    "routes", "firewall", "port_forwards", "wifi", "dns", "block_device",
    "ping", "traceroute", "logs", "reboot", "backup", "flow_export",
}


class NotSupported(Exception):
    pass


class DriverError(Exception):
    """The router rejected or failed an operation."""


class RouterDriver(ABC):
    name = "base"
    capabilities: set[str] = set()

    async def connect(self) -> None:  # pragma: no cover - optional
        pass

    async def close(self) -> None:  # pragma: no cover - optional
        pass

    # -- read ----------------------------------------------------------------
    @abstractmethod
    async def system_info(self) -> SystemInfo: ...

    @abstractmethod
    async def interfaces(self) -> list[Interface]: ...

    async def set_interface_enabled(self, name: str, enabled: bool) -> None:
        raise NotSupported

    @abstractmethod
    async def leases(self) -> list[Lease]: ...

    async def arp(self) -> list[ArpEntry]:
        raise NotSupported

    async def routes(self) -> list[Route]:
        raise NotSupported

    async def firewall_rules(self) -> list[FirewallRule]:
        raise NotSupported

    async def port_forwards(self) -> list[PortForward]:
        raise NotSupported

    async def wifi(self) -> list[WifiNetwork]:
        raise NotSupported

    async def dns(self) -> DnsConfig:
        raise NotSupported

    async def logs(self, limit: int = 200) -> list[LogEntry]:
        raise NotSupported

    # -- write ---------------------------------------------------------------
    async def add_static_lease(self, lease: StaticLeaseIn) -> Lease:
        raise NotSupported

    async def delete_static_lease(self, lease_id: str) -> None:
        raise NotSupported

    async def add_route(self, route: RouteIn) -> Route:
        raise NotSupported

    async def delete_route(self, route_id: str) -> None:
        raise NotSupported

    async def add_firewall_rule(self, rule: FirewallRuleIn) -> FirewallRule:
        raise NotSupported

    async def delete_firewall_rule(self, rule_id: str) -> None:
        raise NotSupported

    async def set_firewall_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        raise NotSupported

    async def add_port_forward(self, fwd: PortForwardIn) -> PortForward:
        raise NotSupported

    async def delete_port_forward(self, fwd_id: str) -> None:
        raise NotSupported

    async def update_wifi(self, net_id: str, update: WifiUpdate) -> WifiNetwork:
        raise NotSupported

    async def set_dns(self, cfg: DnsConfigIn) -> DnsConfig:
        raise NotSupported

    async def block_device(self, mac: str, blocked: bool) -> None:
        """Default implementation: a managed forward-chain reject rule by MAC."""
        name = block_rule_name(mac)
        existing = [r for r in await self.firewall_rules() if r.name == name]
        if blocked and not existing:
            await self.add_firewall_rule(FirewallRuleIn(
                name=name, chain="forward", action="reject", src_mac=mac))
        elif not blocked:
            for rule in existing:
                await self.delete_firewall_rule(rule.id)

    async def ping(self, host: str, count: int = 4) -> CommandResult:
        raise NotSupported

    async def traceroute(self, host: str) -> CommandResult:
        raise NotSupported

    async def reboot(self) -> None:
        raise NotSupported

    async def backup(self) -> tuple[str, bytes]:
        """Return (filename, content)."""
        raise NotSupported

    async def configure_flow_export(self, collector_ip: str, port: int) -> CommandResult:
        raise NotSupported


def block_rule_name(mac: str) -> str:
    return "rerouter-block-" + mac.replace(":", "")
