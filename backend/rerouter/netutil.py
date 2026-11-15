"""Traffic classification helpers: direction, application and MAC vendor."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache

PROTO_NAMES = {1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 41: "ipv6", 47: "gre",
               50: "esp", 51: "ah", 58: "icmpv6", 89: "ospf", 132: "sctp"}

# (proto, port) -> application label. proto 0 means "tcp or udp".
_SERVICES: dict[tuple[int, int], str] = {}


def _svc(name: str, *ports: int, proto: int = 0) -> None:
    for port in ports:
        _SERVICES[(proto, port)] = name


_svc("https", 443, 8443, proto=6)
_svc("quic", 443, proto=17)
_svc("http", 80, 8080, 8000, 8008)
_svc("dns", 53)
_svc("dns-over-tls", 853)
_svc("dhcp", 67, 68, 546, 547)
_svc("ntp", 123)
_svc("ssh", 22)
_svc("telnet", 23)
_svc("ftp", 20, 21)
_svc("smtp", 25, 465, 587)
_svc("pop3", 110, 995)
_svc("imap", 143, 993)
_svc("smb", 137, 138, 139, 445)
_svc("snmp", 161, 162)
_svc("syslog", 514)
_svc("ldap", 389, 636)
_svc("rdp", 3389)
_svc("vnc", 5900, 5901)
_svc("ssdp", 1900)
_svc("mdns", 5353)
_svc("llmnr", 5355)
_svc("openvpn", 1194)
_svc("wireguard", 51820)
_svc("ipsec", 500, 4500)
_svc("stun/webrtc", 3478, 3479, 3480, 19302, 19303, 19305)
_svc("xmpp", 5222, 5223)
_svc("mqtt", 1883, 8883)
_svc("rtsp", 554)
_svc("sip", 5060, 5061)
_svc("mysql", 3306)
_svc("postgres", 5432)
_svc("redis", 6379)
_svc("mongodb", 27017)
_svc("printing", 515, 631, 9100)
_svc("netflow", 2055, 4739, 6343)
_svc("bittorrent", *range(6881, 6890))
_svc("google-push", 5228)
_svc("plex", 32400)
_svc("steam", 27015, 27036)
_svc("xbox-live", 3074)
_svc("tor", 9001, 9030)
_svc("airplay", 7000, 7100)


def proto_name(proto: int) -> str:
    return PROTO_NAMES.get(proto, str(proto))


def service_for(proto: int, port: int | None) -> str | None:
    if not port:
        return None
    return _SERVICES.get((proto, port)) or _SERVICES.get((0, port))


def classify_app(proto: int, local_port: int | None, remote_port: int | None) -> str:
    """Guess the application. The remote (server) port wins for outbound flows;
    for inbound connections to a local service the local port is the hint."""
    if proto in (1, 58):
        return "icmp"
    app = service_for(proto, remote_port) or service_for(proto, local_port)
    if app:
        return app
    if proto in (6, 17):
        ports = [p for p in (local_port, remote_port) if p]
        lo = min(ports) if ports else 0
        return f"{proto_name(proto)}/{'ephemeral' if lo >= 49152 else 'other'}"
    return proto_name(proto)


@dataclass(frozen=True)
class Classified:
    direction: str  # upload | download | lan | transit
    local_ip: str
    remote_ip: str
    local_port: int
    remote_port: int


class NetworkClassifier:
    """Decides which side of a flow is "ours" based on the configured LAN
    networks plus the router's own addresses."""

    def __init__(self, lan_networks: list[str], router_ips: list[str] | None = None):
        self.update(lan_networks, router_ips or [])

    def update(self, lan_networks: list[str], router_ips: list[str]) -> None:
        self.networks = [ipaddress.ip_network(n, strict=False) for n in lan_networks]
        self.router_ips = {str(ipaddress.ip_address(i)) for i in router_ips}
        self.is_local.cache_clear()

    @lru_cache(maxsize=65536)
    def is_local(self, ip: str) -> bool:
        if ip in self.router_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.is_link_local or addr.is_multicast or addr.is_loopback:
            return True
        return any(addr in net for net in self.networks)

    def classify(self, src: str, dst: str, sport: int, dport: int) -> Classified:
        s_local, d_local = self.is_local(src), self.is_local(dst)
        if s_local and d_local:
            return Classified("lan", src, dst, sport, dport)
        if s_local:
            return Classified("upload", src, dst, sport, dport)
        if d_local:
            return Classified("download", dst, src, dport, sport)
        return Classified("transit", src, dst, sport, dport)


# A small table of common OUIs, enough to label typical home/lab devices.
_OUI = {
    "00:03:93": "Apple", "00:1b:63": "Apple", "3c:22:fb": "Apple", "a4:83:e7": "Apple",
    "f0:18:98": "Apple", "ac:bc:32": "Apple", "d0:81:7a": "Apple", "88:66:5a": "Apple",
    "00:12:fb": "Samsung", "8c:77:12": "Samsung", "f4:7b:09": "Samsung", "5c:0a:5b": "Samsung",
    "3c:5a:b4": "Google", "f4:f5:d8": "Google", "54:60:09": "Google", "1c:f2:9a": "Google",
    "44:65:0d": "Amazon", "74:c2:46": "Amazon", "fc:65:de": "Amazon", "68:54:fd": "Amazon",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "00:50:56": "VMware", "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "00:1a:11": "Google", "18:b4:30": "Nest", "64:16:66": "Nest",
    "00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue",
    "d8:eb:46": "Google", "70:ee:50": "Netatmo", "24:0a:c4": "Espressif",
    "84:f3:eb": "Espressif", "a4:cf:12": "Espressif", "cc:50:e3": "Espressif",
    "50:c7:bf": "TP-Link", "ac:84:c6": "TP-Link", "98:da:c4": "TP-Link",
    "00:0c:42": "MikroTik", "4c:5e:0c": "MikroTik", "64:d1:54": "MikroTik",
    "00:11:32": "Synology", "00:08:9b": "QNAP", "00:1e:06": "Wibrain",
    "3c:52:82": "HP", "00:21:5a": "HP", "f8:b4:6a": "HP",
    "00:24:e4": "Withings", "00:04:4b": "NVIDIA", "48:b0:2d": "NVIDIA",
    "00:1d:d8": "Microsoft", "28:18:78": "Microsoft", "7c:1e:52": "Microsoft",
    "00:15:5d": "Microsoft Hyper-V", "a0:ce:c8": "CE Link", "fc:ec:da": "Ubiquiti",
    "24:a4:3c": "Ubiquiti", "78:8a:20": "Ubiquiti", "00:e0:4c": "Realtek",
    "3c:7c:3f": "ASUS", "04:d9:f5": "ASUS", "2c:fd:a1": "ASUS",
    "9c:8e:cd": "Amcrest", "e0:62:67": "Xiaomi", "64:09:80": "Xiaomi",
    "38:f7:3d": "Amazon", "f0:27:2d": "Amazon", "00:fc:8b": "Amazon",
    "b0:be:76": "TP-Link", "c0:c9:e3": "TP-Link", "e8:48:b8": "TP-Link",
    "00:04:20": "Slim Devices", "00:0e:58": "Sonos", "5c:aa:fd": "Sonos",
    "b8:e9:37": "Sonos", "e4:f0:42": "Google", "30:fd:38": "Google",
}


def mac_vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    mac = mac.lower()
    vendor = _OUI.get(mac[:8])
    if vendor:
        return vendor
    try:
        if int(mac[:2], 16) & 0x02:
            return "Randomized (private) MAC"
    except ValueError:
        return None
    return None
