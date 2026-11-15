"""Pydantic models shared by drivers and the HTTP API."""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-\.]{0,251}[A-Za-z0-9])?$")
NAME_RE = re.compile(r"^[\w .\-]{1,64}$")


def normalize_mac(value: str) -> str:
    mac = value.strip().lower().replace("-", ":")
    if not MAC_RE.match(mac):
        raise ValueError(f"invalid MAC address: {value!r}")
    return mac


def validate_host(value: str) -> str:
    """An IP address or DNS name; rejects anything shell-meaningful."""
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not HOST_RE.match(value):
        raise ValueError(f"invalid host: {value!r}")
    return value


def validate_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def validate_cidr(value: str) -> str:
    return str(ipaddress.ip_network(value.strip(), strict=False))


def validate_ports(value: str) -> str:
    """Single port or range "a-b"."""
    value = value.strip()
    if not value:
        return value
    parts = value.split("-")
    if len(parts) > 2 or not all(p.isdigit() and 0 < int(p) < 65536 for p in parts):
        raise ValueError(f"invalid port or port range: {value!r}")
    return value


def validate_name(value: str) -> str:
    if not NAME_RE.match(value):
        raise ValueError("names may contain letters, digits, space, '.', '-', '_' (max 64)")
    return value


# --------------------------------------------------------------------------
# Router state
# --------------------------------------------------------------------------
class SystemInfo(BaseModel):
    hostname: str
    model: str
    firmware: str
    uptime_s: int
    load: list[float] = Field(default_factory=list)
    cpu_percent: float | None = None
    mem_total: int | None = None
    mem_free: int | None = None
    temperature_c: float | None = None
    extra: dict[str, str] = Field(default_factory=dict)


class InterfaceCounters(BaseModel):
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    tx_packets: int = 0
    rx_errors: int = 0
    tx_errors: int = 0
    rx_dropped: int = 0
    tx_dropped: int = 0


class Interface(InterfaceCounters):
    name: str
    kind: str = "ethernet"  # ethernet | bridge | wireless | vlan | ppp | tunnel | loopback
    role: str | None = None  # wan | lan | guest ...
    mac: str | None = None
    mtu: int | None = None
    up: bool = True
    enabled: bool = True
    addresses: list[str] = Field(default_factory=list)
    speed_mbps: int | None = None
    comment: str | None = None


class Lease(BaseModel):
    mac: str
    ip: str
    hostname: str | None = None
    expires: float | None = None
    static: bool = False
    id: str | None = None


class ArpEntry(BaseModel):
    ip: str
    mac: str
    iface: str | None = None


class Route(BaseModel):
    id: str
    dst: str
    gateway: str | None = None
    iface: str | None = None
    metric: int | None = None
    static: bool = False
    active: bool = True
    comment: str | None = None


class FirewallRule(BaseModel):
    id: str
    name: str
    enabled: bool = True
    chain: Literal["input", "forward", "output"] = "forward"
    action: Literal["accept", "drop", "reject"] = "drop"
    proto: Literal["any", "tcp", "udp", "icmp", "tcp+udp"] = "any"
    src: str | None = None
    src_port: str | None = None
    dst: str | None = None
    dst_port: str | None = None
    src_mac: str | None = None
    managed: bool = False  # created by rerouter (e.g. a device block)


class PortForward(BaseModel):
    id: str
    name: str
    enabled: bool = True
    proto: Literal["tcp", "udp", "tcp+udp"] = "tcp"
    ext_port: str
    int_ip: str
    int_port: str
    src: str | None = None


class WifiNetwork(BaseModel):
    id: str
    ssid: str
    band: str | None = None
    channel: str | None = None
    encryption: str | None = None
    enabled: bool = True
    hidden: bool = False
    clients: int | None = None


class DnsConfig(BaseModel):
    servers: list[str] = Field(default_factory=list)
    local_domain: str | None = None


class LogEntry(BaseModel):
    ts: float | None = None
    level: str = "info"
    source: str | None = None
    message: str


class CommandResult(BaseModel):
    ok: bool
    output: str


# --------------------------------------------------------------------------
# Write requests
# --------------------------------------------------------------------------
class FirewallRuleIn(BaseModel):
    name: str
    enabled: bool = True
    chain: Literal["input", "forward", "output"] = "forward"
    action: Literal["accept", "drop", "reject"] = "drop"
    proto: Literal["any", "tcp", "udp", "icmp", "tcp+udp"] = "any"
    src: str | None = None
    src_port: str | None = None
    dst: str | None = None
    dst_port: str | None = None
    src_mac: str | None = None

    _name = field_validator("name")(classmethod(lambda cls, v: validate_name(v)))

    @field_validator("src", "dst")
    @classmethod
    def _cidr(cls, v: str | None) -> str | None:
        return validate_cidr(v) if v else None

    @field_validator("src_port", "dst_port")
    @classmethod
    def _ports(cls, v: str | None) -> str | None:
        return validate_ports(v) or None if v else None

    @field_validator("src_mac")
    @classmethod
    def _mac(cls, v: str | None) -> str | None:
        return normalize_mac(v) if v else None


class PortForwardIn(BaseModel):
    name: str
    enabled: bool = True
    proto: Literal["tcp", "udp", "tcp+udp"] = "tcp"
    ext_port: str
    int_ip: str
    int_port: str
    src: str | None = None

    _name = field_validator("name")(classmethod(lambda cls, v: validate_name(v)))
    _ip = field_validator("int_ip")(classmethod(lambda cls, v: validate_ip(v)))
    _ports = field_validator("ext_port", "int_port")(
        classmethod(lambda cls, v: validate_ports(v))
    )

    @field_validator("src")
    @classmethod
    def _src(cls, v: str | None) -> str | None:
        return validate_cidr(v) if v else None


class RouteIn(BaseModel):
    dst: str
    gateway: str | None = None
    iface: str | None = None
    metric: int | None = Field(default=None, ge=0, le=65535)
    comment: str | None = None

    _dst = field_validator("dst")(classmethod(lambda cls, v: validate_cidr(v)))

    @field_validator("gateway")
    @classmethod
    def _gw(cls, v: str | None) -> str | None:
        return validate_ip(v) if v else None

    @field_validator("iface")
    @classmethod
    def _iface(cls, v: str | None) -> str | None:
        if v and not re.match(r"^[\w.\-@]{1,32}$", v):
            raise ValueError("invalid interface name")
        return v or None

    @field_validator("comment")
    @classmethod
    def _comment(cls, v: str | None) -> str | None:
        return validate_name(v) if v else None


class StaticLeaseIn(BaseModel):
    mac: str
    ip: str
    hostname: str | None = None

    _mac = field_validator("mac")(classmethod(lambda cls, v: normalize_mac(v)))
    _ip = field_validator("ip")(classmethod(lambda cls, v: validate_ip(v)))

    @field_validator("hostname")
    @classmethod
    def _host(cls, v: str | None) -> str | None:
        if v and not re.match(r"^[A-Za-z0-9\-]{1,63}$", v):
            raise ValueError("hostname may contain letters, digits and '-'")
        return v or None


class WifiUpdate(BaseModel):
    ssid: str | None = Field(default=None, min_length=1, max_length=32)
    key: str | None = Field(default=None, min_length=8, max_length=63)
    enabled: bool | None = None
    hidden: bool | None = None
    channel: str | None = None

    @field_validator("ssid")
    @classmethod
    def _ssid(cls, v: str | None) -> str | None:
        if v is not None and any(ord(c) < 32 or c in "'\"\\`$" for c in v):
            raise ValueError("SSID contains unsupported characters")
        return v

    @field_validator("key")
    @classmethod
    def _key(cls, v: str | None) -> str | None:
        if v is not None and any(ord(c) < 32 or ord(c) > 126 for c in v):
            raise ValueError("Wi-Fi key must be printable ASCII")
        return v

    @field_validator("channel")
    @classmethod
    def _channel(cls, v: str | None) -> str | None:
        if v is not None and not (v == "auto" or v.isdigit()):
            raise ValueError("channel must be a number or 'auto'")
        return v


class DnsConfigIn(BaseModel):
    servers: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("servers")
    @classmethod
    def _servers(cls, v: list[str]) -> list[str]:
        return [validate_ip(s) for s in v]


class InterfaceUpdate(BaseModel):
    enabled: bool


class DiagnosticRequest(BaseModel):
    host: str
    count: int = Field(default=4, ge=1, le=20)

    _host = field_validator("host")(classmethod(lambda cls, v: validate_host(v)))
