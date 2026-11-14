"""A self-contained simulated home/lab router.

It keeps full configuration state in memory and, when traffic simulation is
on, generates realistic flows for a set of household devices (diurnal usage
patterns, long-lived sessions, DNS lookups) plus occasional anomalies (port
scans, a camera exfiltrating data, Mirai-style telnet probing) so every
dashboard and alert can be exercised without real hardware.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import math
import random
import tarfile
import time
from dataclasses import dataclass, field

from ..collectors.flowstore import FlowRecord, FlowSink
from ..models import (ArpEntry, CommandResult, DnsConfig, DnsConfigIn, FirewallRule,
                      FirewallRuleIn, Interface, Lease, LogEntry, PortForward,
                      PortForwardIn, Route, RouteIn, StaticLeaseIn, SystemInfo,
                      WifiNetwork, WifiUpdate)
from .base import ALL_CAPABILITIES, DriverError, RouterDriver

LAN_PREFIX = "192.168.1."
ROUTER_LAN = "192.168.1.1"
ROUTER_WAN = "203.0.113.45"
WAN_GW = "203.0.113.1"
_TLS_PORTS = {443, 8443, 8883, 993, 995, 465, 853, 5223, 4070, 8801}


@dataclass(frozen=True)
class Service:
    name: str
    ips: tuple[str, ...]
    ports: tuple[tuple[int, int], ...]  # (proto, port)
    up_ratio: float  # upload bytes per download byte
    rate: float  # typical download bytes/sec while active


SERVICES: dict[str, Service] = {s.name: s for s in [
    Service("youtube.com", ("142.250.191.14", "142.250.72.206", "172.217.14.110"),
            ((17, 443), (6, 443)), 0.03, 450_000),
    Service("nflxvideo.net", ("45.57.40.1", "45.57.41.1", "198.38.120.10"),
            ((6, 443),), 0.02, 650_000),
    Service("google.com", ("142.250.80.46", "142.250.80.100"), ((6, 443), (17, 443)), 0.25, 40_000),
    Service("facebook.com", ("157.240.22.35", "157.240.3.35"), ((6, 443),), 0.15, 60_000),
    Service("instagram.com", ("157.240.22.174", "157.240.3.63"), ((6, 443),), 0.1, 120_000),
    Service("icloud.com", ("17.253.144.10", "17.248.137.70"), ((6, 443),), 0.6, 80_000),
    Service("cloudflare.com", ("104.16.132.229", "104.16.133.229"), ((6, 443),), 0.2, 50_000),
    Service("amazonaws.com", ("52.94.236.248", "54.239.28.85"), ((6, 443),), 0.3, 70_000),
    Service("spotify.com", ("35.186.224.25", "35.186.224.47"), ((6, 443), (6, 4070)), 0.03, 40_000),
    Service("github.com", ("140.82.112.3", "140.82.114.4"), ((6, 443), (6, 22)), 0.35, 120_000),
    Service("zoom.us", ("170.114.52.2", "170.114.10.77"), ((17, 8801), (6, 443)), 0.9, 300_000),
    Service("steampowered.com", ("155.133.248.34", "23.62.40.10"), ((6, 443), (17, 27015)),
            0.04, 900_000),
    Service("windowsupdate.com", ("13.107.4.50", "13.107.4.52"), ((6, 443), (6, 80)), 0.01, 700_000),
    Service("tuyaus.com", ("52.58.212.8", "3.120.181.6"), ((6, 8883),), 0.7, 300),
    Service("ring.com", ("3.226.18.20", "52.200.71.9"), ((6, 443),), 12.0, 6_000),
    Service("pool.ntp.org", ("162.159.200.1", "162.159.200.123"), ((17, 123),), 1.0, 90),
    Service("push.apple.com", ("17.57.144.20", "17.57.146.52"), ((6, 5223),), 0.8, 150),
    Service("backblazeb2.com", ("45.11.36.1", "45.11.37.12"), ((6, 443),), 40.0, 9_000),
    Service("slack.com", ("3.95.117.96", "34.226.36.32"), ((6, 443),), 0.4, 15_000),
    Service("teams.microsoft.com", ("52.113.194.132", "52.112.0.10"), ((17, 3478), (6, 443)),
            0.85, 250_000),
]}

# Curves give relative activity per hour of day (0..23).
_HUMAN = [.15, .08, .05, .04, .04, .06, .25, .55, .7, .6, .55, .6, .7, .6, .55, .6, .7, .85,
          1.0, 1.0, .95, .9, .7, .4]
_TV = [.1, .03, 0, 0, 0, 0, 0, .05, .1, .05, .05, .1, .15, .1, .1, .15, .3, .5, .8, 1, 1, .95,
       .7, .3]
_FLAT = [1.0] * 24
_NIGHTLY = [.6, 1, 1, 1, .8, .2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, .1, .3]
_WORK = [0, 0, 0, 0, 0, 0, .05, .3, .9, 1, 1, .9, .6, .9, 1, 1, .9, .6, .2, .1, .1, .05, 0, 0]


@dataclass
class SimDevice:
    mac: str
    ip: str
    hostname: str
    wireless: bool
    curve: list[float]
    services: dict[str, float]  # service -> weight
    max_sessions: int = 3
    intensity: float = 1.0
    lan_peers: list[tuple[str, int, int, float]] = field(default_factory=list)  # ip, proto, port, Bps


def _devices() -> list[SimDevice]:
    p = LAN_PREFIX
    return [
        SimDevice("3c:22:fb:4a:10:01", p + "20", "alex-macbook", True, _WORK,
                  {"google.com": 3, "github.com": 3, "zoom.us": 1, "slack.com": 3,
                   "youtube.com": 1, "icloud.com": 1, "cloudflare.com": 2, "spotify.com": 2},
                  max_sessions=4, lan_peers=[(p + "10", 6, 445, 400_000)]),
        SimDevice("28:18:78:5b:22:02", p + "21", "sam-desktop", False, _HUMAN,
                  {"steampowered.com": .3, "youtube.com": 3, "google.com": 2,
                   "windowsupdate.com": .3, "teams.microsoft.com": 1, "amazonaws.com": 1},
                  max_sessions=4),
        SimDevice("7a:4c:91:0e:33:03", p + "30", "iphone", True, _HUMAN,
                  {"instagram.com": 3, "facebook.com": 2, "youtube.com": 1, "icloud.com": 1,
                   "push.apple.com": 2, "spotify.com": 1}, max_sessions=3, intensity=.6),
        SimDevice("8c:77:12:6f:44:04", p + "31", "galaxy-s24", True, _HUMAN,
                  {"google.com": 2, "youtube.com": 2, "instagram.com": 2, "spotify.com": 1},
                  max_sessions=3, intensity=.5),
        SimDevice("f4:f5:d8:21:55:05", p + "40", "living-room-tv", True, _TV,
                  {"nflxvideo.net": 3, "youtube.com": 2}, max_sessions=1, intensity=1.4),
        SimDevice("38:f7:3d:9c:66:06", p + "50", "doorbell-cam", True, _FLAT,
                  {"ring.com": 1}, max_sessions=1),
        SimDevice("24:0a:c4:a1:77:07", p + "51", "smart-plug-1", True, _FLAT,
                  {"tuyaus.com": 1, "pool.ntp.org": .1}, max_sessions=1),
        SimDevice("24:0a:c4:a1:77:08", p + "52", "smart-plug-2", True, _FLAT,
                  {"tuyaus.com": 1, "pool.ntp.org": .1}, max_sessions=1),
        SimDevice("00:11:32:0b:88:09", p + "10", "nas", False, _NIGHTLY,
                  {"backblazeb2.com": 1}, max_sessions=2),
        SimDevice("f8:b4:6a:3e:99:0a", p + "60", "office-printer", False, _WORK,
                  {"pool.ntp.org": 1}, max_sessions=1, intensity=.2),
        SimDevice("b8:27:eb:7c:aa:0b", p + "70", "raspberrypi", False, _FLAT,
                  {"github.com": 1, "pool.ntp.org": 1, "amazonaws.com": 1},
                  max_sessions=1, intensity=.3, lan_peers=[(p + "10", 6, 1883, 200)]),
    ]


@dataclass
class Session:
    device: SimDevice
    service: Service
    remote_ip: str
    proto: int
    remote_port: int
    local_port: int
    rate: float
    ends: float
    started: float
    down: int = 0
    up: int = 0
    down_pkts: int = 0
    up_pkts: int = 0
    last_report: float = 0.0


class TrafficSimulator:
    REPORT_INTERVAL = 15.0

    def __init__(self, router: "SimulatedRouter", rng: random.Random | None = None,
                 live: bool = True):
        self.router = router
        self.rng = rng or random.Random()
        # Live simulators drive the router's interface counters; the history
        # backfill only accumulates totals so it doesn't distort live rates.
        self.live = live
        self.totals = {"down": 0, "up": 0, "lan": 0}
        self.sessions: list[Session] = []
        self.pending: list[FlowRecord] = []
        self.anomaly: dict | None = None
        self._fingerprints: dict[str, str] = {}

    # A tick advances the world by dt seconds ending at `now`.
    def tick(self, now: float, dt: float) -> list[FlowRecord]:
        rng = self.rng
        hour = time.localtime(now).tm_hour + time.localtime(now).tm_min / 60
        out: list[FlowRecord] = []
        r = self.router
        blocked = r.blocked_macs()
        wan_up = r.interface_enabled("wan")

        for dev in r.devices:
            if dev.mac in blocked or not wan_up:
                continue
            activity = _curve_at(dev.curve, hour) * dev.intensity
            active = [s for s in self.sessions if s.device is dev]
            # Expected new sessions per second grows with activity.
            if len(active) < dev.max_sessions and rng.random() < 1 - math.exp(
                    -activity * dt / 40):
                sess = self._new_session(dev, now, activity)
                self.sessions.append(sess)
                out.extend(self._dns_lookup(dev, sess.service, now))
            for peer_ip, proto, port, bps in dev.lan_peers:
                if rng.random() < activity * min(1.0, dt / 30):
                    nbytes = int(bps * dt * rng.uniform(.2, 1.5))
                    out.append(self._flow(now - dt, now, dev.ip, peer_ip,
                                          rng.randint(49152, 65535), port, proto, nbytes))
                    self._lan(nbytes, dev.wireless)

        for s in list(self.sessions):
            jitter = rng.lognormvariate(0, 0.35)
            down = int(s.rate * dt * jitter)
            up = int(down * s.service.up_ratio * rng.uniform(.7, 1.3)) + 60 * int(dt)
            s.down += down
            s.up += up
            s.down_pkts += max(1, down // 1300)
            s.up_pkts += max(1, up // 400)
            self._wan(down, up, s.device.wireless)
            if now >= s.ends or now - s.last_report >= self.REPORT_INTERVAL:
                out.extend(self._report(s, now))
            if now >= s.ends:
                self.sessions.remove(s)

        out.extend(self._anomalies(now, dt))
        return out

    def _wan(self, down: int, up: int, wireless: bool) -> None:
        self.totals["down"] += down
        self.totals["up"] += up
        if self.live:
            self.router.counters_wan(down, up, wireless)

    def _lan(self, nbytes: int, wireless: bool) -> None:
        self.totals["lan"] += nbytes
        if self.live:
            self.router.counters_lan(nbytes, wireless)

    def _new_session(self, dev: SimDevice, now: float, activity: float) -> Session:
        rng = self.rng
        names = list(dev.services)
        svc = SERVICES[rng.choices(names, weights=[dev.services[n] for n in names])[0]]
        proto, port = rng.choice(svc.ports)
        heavy = svc.rate > 200_000
        duration = rng.uniform(240, 1500) if heavy else rng.uniform(20, 600)
        return Session(dev, svc, rng.choice(svc.ips), proto, port, rng.randint(49152, 65535),
                       rate=svc.rate * rng.uniform(.5, 1.5) * max(.3, activity),
                       ends=now + duration, started=now, last_report=now)

    def _report(self, s: Session, now: float) -> list[FlowRecord]:
        dev = s.device
        start = max(s.started, s.last_report)
        tls = s.remote_port in _TLS_PORTS or (s.proto == 17 and s.remote_port == 443)
        meta = dict(host=s.service.name,
                    fingerprint=self._fingerprint(dev) if tls else None,
                    tls_version="TLS 1.3" if tls else None)
        out = [
            self._flow(start, now, s.remote_ip, dev.ip, s.remote_port, s.local_port, s.proto,
                       s.down, s.down_pkts, **meta),
            self._flow(start, now, dev.ip, s.remote_ip, s.local_port, s.remote_port, s.proto,
                       s.up, s.up_pkts, **meta),
        ]
        s.down = s.up = s.down_pkts = s.up_pkts = 0
        s.last_report = now
        return [f for f in out if f.bytes > 0]

    def _fingerprint(self, dev: SimDevice) -> str:
        """A stable, device-specific JA3-style client fingerprint."""
        fp = self._fingerprints.get(dev.mac)
        if fp is None:
            fp = hashlib.md5(dev.mac.encode(), usedforsecurity=False).hexdigest()
            self._fingerprints[dev.mac] = fp
        return fp

    def _dns_lookup(self, dev: SimDevice, svc: Service, now: float) -> list[FlowRecord]:
        rng = self.rng
        port = rng.randint(1024, 65535)
        flows = [
            self._flow(now, now, dev.ip, ROUTER_LAN, port, 53, 17, rng.randint(60, 90), 1),
            self._flow(now, now, ROUTER_LAN, dev.ip, 53, port, 17, rng.randint(90, 300), 1),
        ]
        if rng.random() < 0.3:  # cache miss -> upstream query
            up_port = rng.randint(1024, 65535)
            upstream = self.router.dns_servers[0] if self.router.dns_servers else "1.1.1.1"
            flows += [
                self._flow(now, now, ROUTER_WAN, upstream, up_port, 53, 17, 80, 1),
                self._flow(now, now, upstream, ROUTER_WAN, 53, up_port, 17, 220, 1),
            ]
        return flows

    def _anomalies(self, now: float, dt: float) -> list[FlowRecord]:
        rng = self.rng
        if self.anomaly is None:
            if rng.random() < dt / 2400:  # roughly one every 40 minutes
                kind = rng.choice(["port_scan", "exfil", "telnet_probe"])
                self.anomaly = {"kind": kind, "until": now + rng.uniform(60, 240), "step": 0,
                                "src": f"185.220.101.{rng.randint(2, 250)}"}
                self.router.log("warning", "sim", f"anomaly injected: {kind}")
            return []
        a = self.anomaly
        if now > a["until"]:
            self.anomaly = None
            return []
        out = []
        if a["kind"] == "port_scan":
            for _ in range(int(25 * dt)):
                a["step"] += 1
                out.append(self._flow(now, now, a["src"], ROUTER_WAN, rng.randint(40000, 60000),
                                      (a["step"] * 7) % 10000 + 1, 6, 60, 1, flags=0x02))
        elif a["kind"] == "exfil":
            nbytes = int(10_000_000 * dt * rng.uniform(.8, 1.2))
            cam = self.router.devices[5]
            out.append(self._flow(now - dt, now, cam.ip, "45.137.21.9", 51515, 443, 6,
                                  nbytes, nbytes // 1400))
            self._wan(0, nbytes, True)
        elif a["kind"] == "telnet_probe":
            plug = self.router.devices[6]
            for _ in range(int(3 * dt)):
                dst = f"{rng.randint(11, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}." \
                      f"{rng.randint(1, 254)}"
                out.append(self._flow(now, now, plug.ip, dst, rng.randint(30000, 60000),
                                      rng.choice([23, 2323]), 6, 60, 1, flags=0x02))
        return out

    @staticmethod
    def _flow(start, end, src, dst, sport, dport, proto, nbytes, pkts=None, flags=0x18,
              host=None, fingerprint=None, tls_version=None):
        return FlowRecord(start, end, src, dst, sport, dport, proto, nbytes,
                          pkts if pkts is not None else max(1, nbytes // 1200),
                          flags if proto == 6 else 0, source="simulated", exporter="simulator",
                          host=host, fingerprint=fingerprint, tls_version=tls_version)


def _curve_at(curve: list[float], hour: float) -> float:
    i = int(hour) % 24
    frac = hour - int(hour)
    return curve[i] * (1 - frac) + curve[(i + 1) % 24] * frac


class SimulatedRouter(RouterDriver):
    name = "simulated"
    capabilities = set(ALL_CAPABILITIES)

    def __init__(self, seed: int | None = None):
        self.rng = random.Random(seed)
        self.boot_time = time.time() - 6 * 86400 - 3 * 3600
        self.devices = _devices()
        self.dns_servers = ["1.1.1.1", "9.9.9.9"]
        self._id = 100
        self._ifaces = {
            "wan": Interface(name="wan", kind="ethernet", role="wan", mac="64:d1:54:00:00:01",
                             mtu=1500, addresses=[f"{ROUTER_WAN}/24"], speed_mbps=1000),
            "br-lan": Interface(name="br-lan", kind="bridge", role="lan",
                                mac="64:d1:54:00:00:02", mtu=1500,
                                addresses=[f"{ROUTER_LAN}/24", "fd12:3456:789a::1/64"]),
            "lan1": Interface(name="lan1", kind="ethernet", role="lan", mac="64:d1:54:00:00:03",
                              mtu=1500, speed_mbps=1000),
            "lan2": Interface(name="lan2", kind="ethernet", role="lan", mac="64:d1:54:00:00:04",
                              mtu=1500, speed_mbps=1000),
            "wlan0": Interface(name="wlan0", kind="wireless", role="lan", mac="64:d1:54:00:00:05",
                               mtu=1500, comment="2.4 GHz"),
            "wlan1": Interface(name="wlan1", kind="wireless", role="lan", mac="64:d1:54:00:00:06",
                               mtu=1500, comment="5 GHz"),
            "wg0": Interface(name="wg0", kind="tunnel", role="vpn", mtu=1420,
                             addresses=["10.8.0.1/24"]),
        }
        # pre-load plausible lifetime counters
        for i, iface in enumerate(self._ifaces.values()):
            iface.rx_bytes = int(4e11 / (i + 1))
            iface.tx_bytes = int(9e10 / (i + 1))
            iface.rx_packets = iface.rx_bytes // 900
            iface.tx_packets = iface.tx_bytes // 700
        self._firewall: list[FirewallRule] = [
            FirewallRule(id="1", name="Allow-DHCP-Renew", chain="input", action="accept",
                         proto="udp", dst_port="68"),
            FirewallRule(id="2", name="Allow-Ping", chain="input", action="accept", proto="icmp"),
            FirewallRule(id="3", name="Block-IoT-to-LAN", chain="forward", action="reject",
                         src="192.168.1.50/31", dst="192.168.1.0/27"),
            FirewallRule(id="4", name="Drop-WAN-input", chain="input", action="drop"),
        ]
        self._forwards: list[PortForward] = [
            PortForward(id="1", name="plex", proto="tcp", ext_port="32400",
                        int_ip=LAN_PREFIX + "10", int_port="32400"),
            PortForward(id="2", name="wireguard", proto="udp", ext_port="51820",
                        int_ip=ROUTER_LAN, int_port="51820"),
        ]
        self._routes: list[Route] = [
            Route(id="r0", dst="0.0.0.0/0", gateway=WAN_GW, iface="wan", metric=0),
            Route(id="r1", dst="203.0.113.0/24", iface="wan", metric=0),
            Route(id="r2", dst="192.168.1.0/24", iface="br-lan", metric=0),
            Route(id="r3", dst="10.8.0.0/24", iface="wg0", metric=0),
            Route(id="s1", dst="10.20.0.0/16", gateway="192.168.1.70", iface="br-lan",
                  metric=10, static=True, comment="lab network via pi"),
        ]
        self._static: list[Lease] = [
            Lease(id="h1", mac="00:11:32:0b:88:09", ip=LAN_PREFIX + "10", hostname="nas",
                  static=True),
            Lease(id="h2", mac="f8:b4:6a:3e:99:0a", ip=LAN_PREFIX + "60",
                  hostname="office-printer", static=True),
        ]
        self._wifi: list[WifiNetwork] = [
            WifiNetwork(id="default_radio0", ssid="HomeNet", band="2.4 GHz", channel="6",
                        encryption="WPA2/WPA3"),
            WifiNetwork(id="default_radio1", ssid="HomeNet-5G", band="5 GHz", channel="36",
                        encryption="WPA3"),
            WifiNetwork(id="guest_radio1", ssid="HomeNet-Guest", band="5 GHz", channel="36",
                        encryption="WPA2", enabled=False),
        ]
        self._wifi_keys = {w.id: "correct-horse-battery" for w in self._wifi}
        self._logs: list[LogEntry] = []
        self.log("info", "kernel", "Linux version 6.6.73 (simulated)")
        self.log("info", "netifd", "Interface 'wan' is now up")
        self.log("info", "dnsmasq", "started, version 2.90 cachesize 1000")
        self.sim = TrafficSimulator(self, self.rng)
        self._cpu = 4.0

    # -- simulation hooks ----------------------------------------------------
    def log(self, level: str, source: str, message: str) -> None:
        self._logs.append(LogEntry(ts=time.time(), level=level, source=source, message=message))
        del self._logs[:-1000]

    def blocked_macs(self) -> set[str]:
        return {r.src_mac for r in self._firewall
                if r.enabled and r.src_mac and r.action != "accept"}

    def interface_enabled(self, name: str) -> bool:
        return self._ifaces[name].enabled

    def counters_wan(self, down: int, up: int, wireless: bool) -> None:
        wan, lan = self._ifaces["wan"], self._ifaces["br-lan"]
        wan.rx_bytes += down
        wan.tx_bytes += up
        wan.rx_packets += down // 1300 + 1
        wan.tx_packets += up // 400 + 1
        lan.tx_bytes += down
        lan.rx_bytes += up
        lan.tx_packets += down // 1300 + 1
        lan.rx_packets += up // 400 + 1
        radio = self._ifaces["wlan1" if wireless else "lan1"]
        radio.tx_bytes += down
        radio.rx_bytes += up
        radio.tx_packets += down // 1300 + 1
        radio.rx_packets += up // 400 + 1

    def counters_lan(self, nbytes: int, wireless: bool) -> None:
        lan = self._ifaces["br-lan"]
        lan.rx_bytes += nbytes
        lan.tx_bytes += nbytes
        port = self._ifaces["wlan1" if wireless else "lan2"]
        port.rx_bytes += nbytes
        port.rx_packets += nbytes // 1300 + 1

    async def run_traffic(self, sink: FlowSink, backfill_hours: float = 0) -> None:
        if backfill_hours:
            await asyncio.to_thread(self._backfill, sink, backfill_hours)
        names = {ip: s.name for s in SERVICES.values() for ip in s.ips}
        names.update({"1.1.1.1": "one.one.one.one", "9.9.9.9": "dns.quad9.net",
                      "8.8.8.8": "dns.google"})
        sink.learn_names(names, "simulated")
        last = time.time()
        while True:
            await asyncio.sleep(1.0)
            now = time.time()
            flows = self.sim.tick(now, now - last)
            last = now
            if flows:
                sink.submit(flows)

    def _backfill(self, sink: FlowSink, hours: float) -> None:
        """Synthesize history so dashboards are populated on first start."""
        sim = TrafficSimulator(self, random.Random(42), live=False)
        sim.REPORT_INTERVAL = 300
        now = time.time()
        t = now - hours * 3600
        samples = []
        while t < now:
            sink.submit(sim.tick(t, 60))
            down, up, lan = sim.totals["down"] / 60, sim.totals["up"] / 60, sim.totals["lan"] / 60
            samples.append((t, "wan", down, up, down / 1300, up / 400, 0, 0))
            samples.append((t, "br-lan", up + lan, down + lan, (up + lan) / 400,
                            (down + lan) / 1300, 0, 0))
            sim.totals = {"down": 0, "up": 0, "lan": 0}
            t += 60
        sink.db.executemany(
            "INSERT INTO iface_samples(ts, iface, rx_rate, tx_rate, rx_pps, tx_pps, rx_errors,"
            " tx_errors) VALUES (?,?,?,?,?,?,?,?)", samples)

    # -- read ------------------------------------------------------------------
    async def system_info(self) -> SystemInfo:
        self._cpu = max(1.0, min(95.0, self._cpu + self.rng.uniform(-3, 3) + (6 - self._cpu) * .1))
        return SystemInfo(
            hostname="sim-router", model="Simulated AX3600 (rerouter)",
            firmware="OpenWrt 24.10.0 (simulated)", uptime_s=int(time.time() - self.boot_time),
            load=[round(self._cpu / 40, 2), round(self._cpu / 45, 2), round(self._cpu / 50, 2)],
            cpu_percent=round(self._cpu, 1), mem_total=1_048_576_000,
            mem_free=int(612_000_000 + self.rng.uniform(-2e7, 2e7)),
            temperature_c=round(52 + self._cpu / 5, 1),
            extra={"architecture": "aarch64_cortex-a53", "wan_ip": ROUTER_WAN},
        )

    async def interfaces(self) -> list[Interface]:
        out = []
        for iface in self._ifaces.values():
            copy = iface.model_copy()
            copy.up = iface.enabled
            out.append(copy)
        return out

    async def set_interface_enabled(self, name: str, enabled: bool) -> None:
        if name not in self._ifaces:
            raise DriverError(f"no such interface: {name}")
        self._ifaces[name].enabled = enabled
        self.log("notice", "netifd", f"Interface '{name}' is now {'up' if enabled else 'down'}")

    async def leases(self) -> list[Lease]:
        now = time.time()
        static = {s.mac: s for s in self._static}
        return [Lease(mac=d.mac, ip=d.ip, hostname=d.hostname, static=d.mac in static,
                      expires=None if d.mac in static else now + 3600 + i * 517)
                for i, d in enumerate(self.devices)]

    async def arp(self) -> list[ArpEntry]:
        return [ArpEntry(ip=d.ip, mac=d.mac, iface="br-lan") for d in self.devices] + [
            ArpEntry(ip=WAN_GW, mac="00:00:5e:00:01:01", iface="wan")]

    async def routes(self) -> list[Route]:
        return [r.model_copy() for r in self._routes]

    async def firewall_rules(self) -> list[FirewallRule]:
        return [r.model_copy() for r in self._firewall]

    async def port_forwards(self) -> list[PortForward]:
        return [f.model_copy() for f in self._forwards]

    async def wifi(self) -> list[WifiNetwork]:
        out = []
        for w in self._wifi:
            copy = w.model_copy()
            radio = "5" if "5" in (w.band or "") else "2.4"
            copy.clients = sum(1 for d in self.devices if d.wireless and (
                (radio == "5") == (d.mac[-1] in "13579bd"))) if w.enabled else 0
            out.append(copy)
        return out

    async def dns(self) -> DnsConfig:
        return DnsConfig(servers=list(self.dns_servers), local_domain="lan")

    async def logs(self, limit: int = 200) -> list[LogEntry]:
        return list(reversed(self._logs[-limit:]))

    # -- write -----------------------------------------------------------------
    def _next_id(self) -> str:
        self._id += 1
        return str(self._id)

    async def add_static_lease(self, lease: StaticLeaseIn) -> Lease:
        new = Lease(id="h" + self._next_id(), mac=lease.mac, ip=lease.ip,
                    hostname=lease.hostname, static=True)
        self._static.append(new)
        self.log("info", "uci", f"static lease {lease.mac} -> {lease.ip}")
        return new

    async def delete_static_lease(self, lease_id: str) -> None:
        self._remove(self._static, lease_id)

    async def add_route(self, route: RouteIn) -> Route:
        new = Route(id="s" + self._next_id(), dst=route.dst, gateway=route.gateway,
                    iface=route.iface, metric=route.metric, static=True, comment=route.comment)
        self._routes.append(new)
        self.log("info", "netifd", f"route added {route.dst} via {route.gateway or route.iface}")
        return new

    async def delete_route(self, route_id: str) -> None:
        route = next((r for r in self._routes if r.id == route_id), None)
        if route and not route.static:
            raise DriverError("only static routes can be removed")
        self._remove(self._routes, route_id)

    async def add_firewall_rule(self, rule: FirewallRuleIn) -> FirewallRule:
        new = FirewallRule(id=self._next_id(), managed=rule.name.startswith("rerouter-"),
                           **rule.model_dump())
        self._firewall.insert(0 if new.action != "accept" else len(self._firewall), new)
        self.log("info", "firewall", f"rule '{rule.name}' added")
        return new

    async def delete_firewall_rule(self, rule_id: str) -> None:
        self._remove(self._firewall, rule_id)
        self.log("info", "firewall", f"rule {rule_id} removed")

    async def set_firewall_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        self._find(self._firewall, rule_id).enabled = enabled

    async def add_port_forward(self, fwd: PortForwardIn) -> PortForward:
        new = PortForward(id=self._next_id(), **fwd.model_dump())
        self._forwards.append(new)
        return new

    async def delete_port_forward(self, fwd_id: str) -> None:
        self._remove(self._forwards, fwd_id)

    async def update_wifi(self, net_id: str, update: WifiUpdate) -> WifiNetwork:
        net = self._find(self._wifi, net_id)
        for key in ("ssid", "enabled", "hidden", "channel"):
            value = getattr(update, key)
            if value is not None:
                setattr(net, key, value)
        if update.key:
            self._wifi_keys[net_id] = update.key
        self.log("info", "hostapd", f"{net.ssid}: configuration reloaded")
        return net.model_copy()

    async def set_dns(self, cfg: DnsConfigIn) -> DnsConfig:
        self.dns_servers = list(cfg.servers)
        self.log("info", "dnsmasq", f"using nameservers {', '.join(cfg.servers) or 'ISP'}")
        return await self.dns()

    async def ping(self, host: str, count: int = 4) -> CommandResult:
        base = 1.2 if host.startswith(LAN_PREFIX) else self.rng.uniform(8, 40)
        lines = [f"PING {host} ({host}): 56 data bytes"]
        rtts = []
        for seq in range(count):
            rtt = base * self.rng.uniform(.8, 1.4)
            rtts.append(rtt)
            lines.append(f"64 bytes from {host}: seq={seq} ttl=57 time={rtt:.3f} ms")
        lines += ["", f"--- {host} ping statistics ---",
                  f"{count} packets transmitted, {count} packets received, 0% packet loss",
                  f"round-trip min/avg/max = {min(rtts):.3f}/{sum(rtts)/len(rtts):.3f}/"
                  f"{max(rtts):.3f} ms"]
        await asyncio.sleep(min(count, 4) * 0.2)
        return CommandResult(ok=True, output="\n".join(lines))

    async def traceroute(self, host: str) -> CommandResult:
        hops = [WAN_GW, "198.51.100.17", "198.51.100.94", "192.0.2.33", host]
        lines = [f"traceroute to {host}, 30 hops max, 46 byte packets"]
        t = 0.8
        for i, hop in enumerate(hops, 1):
            t += self.rng.uniform(1, 6)
            lines.append(f" {i}  {hop}  {t:.3f} ms  {t * 1.05:.3f} ms  {t * .97:.3f} ms")
        await asyncio.sleep(0.5)
        return CommandResult(ok=True, output="\n".join(lines))

    async def reboot(self) -> None:
        self.log("warning", "procd", "reboot requested (simulated: uptime reset)")
        self.boot_time = time.time()

    async def backup(self) -> tuple[str, bytes]:
        state = {
            "firewall": [r.model_dump() for r in self._firewall],
            "port_forwards": [f.model_dump() for f in self._forwards],
            "routes": [r.model_dump() for r in self._routes if r.static],
            "static_leases": [s.model_dump() for s in self._static],
            "wifi": [w.model_dump() for w in self._wifi],
            "dns": self.dns_servers,
        }
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = json.dumps(state, indent=2).encode()
            info = tarfile.TarInfo("etc/config/rerouter-sim.json")
            info.size = len(data)
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(data))
        return f"backup-sim-router-{time.strftime('%Y%m%d-%H%M%S')}.tar.gz", buf.getvalue()

    async def configure_flow_export(self, collector_ip: str, port: int) -> CommandResult:
        return CommandResult(ok=True, output=(
            "The simulated router feeds flows to rerouter directly; no exporter is needed.\n"
            f"(A real router would now export NetFlow v9 to {collector_ip}:{port}.)"))

    # -- helpers ---------------------------------------------------------------
    @staticmethod
    def _find(items: list, item_id: str):
        for item in items:
            if item.id == item_id:
                return item
        raise DriverError(f"not found: {item_id}")

    def _remove(self, items: list, item_id: str) -> None:
        items.remove(self._find(items, item_id))
