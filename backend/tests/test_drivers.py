import json

import httpx
import pytest

from rerouter.config import RouterConfig
from rerouter.drivers.openwrt import (OpenWrtRouter, parse_dhcp_leases, parse_ip_route,
                                      parse_logread, parse_proc_arp, parse_proc_net_dev,
                                      parse_uci)
from rerouter.drivers.routeros import RouterOSRouter, parse_duration
from rerouter.models import FirewallRuleIn, WifiUpdate

UCI_FIREWALL = """firewall.cfg01e63d=defaults
firewall.cfg01e63d.input='REJECT'
firewall.cfg0a92bd=rule
firewall.cfg0a92bd.name='Allow-DHCP-Renew'
firewall.cfg0a92bd.src='wan'
firewall.cfg0a92bd.proto='udp'
firewall.cfg0a92bd.dest_port='68'
firewall.cfg0a92bd.target='ACCEPT'
firewall.cfg0b92bd=rule
firewall.cfg0b92bd.name='rerouter-block-aabbccddeeff'
firewall.cfg0b92bd.src='*'
firewall.cfg0b92bd.dest='*'
firewall.cfg0b92bd.src_mac='aa:bb:cc:dd:ee:ff'
firewall.cfg0b92bd.target='REJECT'
firewall.cfg0c92bd=redirect
firewall.cfg0c92bd.name='plex'
firewall.cfg0c92bd.target='DNAT'
firewall.cfg0c92bd.proto='tcp' 'udp'
firewall.cfg0c92bd.src_dport='32400'
firewall.cfg0c92bd.dest_ip='192.168.1.10'
firewall.cfg0c92bd.dest_port='32400'
firewall.cfg0d92bd=rule
firewall.cfg0d92bd.name='It'\\''s quoted'
"""


def test_parse_uci_lists_and_quotes():
    cfg = parse_uci(UCI_FIREWALL)
    assert cfg["cfg0a92bd"][".type"] == "rule"
    assert cfg["cfg0c92bd"]["proto"] == ["tcp", "udp"]
    assert cfg["cfg0d92bd"]["name"] == "It's quoted"


def test_proc_parsers():
    dev = parse_proc_net_dev(
        "Inter-|   Receive |  Transmit\n face |bytes packets\n"
        "  eth0: 1000 10 1 0 0 0 0 0 2000 20 2 0 0 0 0 0\n")
    assert dev["eth0"]["rx_bytes"] == 1000 and dev["eth0"]["tx_errors"] == 2
    leases = parse_dhcp_leases("1700000000 AA:BB:CC:DD:EE:FF 192.168.1.5 laptop 01:aa\n"
                               "0 11:22:33:44:55:66 192.168.1.6 * *\n")
    assert leases[0].hostname == "laptop" and leases[0].mac == "aa:bb:cc:dd:ee:ff"
    assert leases[1].hostname is None and leases[1].expires is None
    arp = parse_proc_arp("IP address HW type Flags HW address Mask Device\n"
                         "192.168.1.5 0x1 0x2 aa:bb:cc:dd:ee:ff * br-lan\n"
                         "192.168.1.9 0x1 0x0 00:00:00:00:00:00 * br-lan\n")
    assert [a.ip for a in arp] == ["192.168.1.5"]
    routes = parse_ip_route("default via 203.0.113.1 dev wan proto static metric 10\n"
                            "192.168.1.0/24 dev br-lan proto kernel scope link src 192.168.1.1\n")
    assert routes[0].dst == "0.0.0.0/0" and routes[0].gateway == "203.0.113.1"
    assert routes[0].metric == 10 and routes[1].iface == "br-lan"
    logs = parse_logread("Sat Nov 14 10:00:01 2026 daemon.info dnsmasq[1234]: started\n")
    assert logs[0].source == "dnsmasq" and logs[0].level == "info"


class FakeShell:
    def __init__(self, responses):
        self.responses = responses
        self.commands = []

    async def __call__(self, cmd):
        self.commands.append(cmd)
        for prefix, out in self.responses.items():
            if cmd.startswith(prefix):
                return 0, out.encode()
        return 0, b""


async def test_openwrt_firewall_and_quoting():
    shell = FakeShell({"uci -X show 'firewall'": UCI_FIREWALL, "uci -X show firewall": UCI_FIREWALL,
                       "uci add firewall rule": "cfg99\n"})
    drv = OpenWrtRouter(RouterConfig(driver="openwrt", host="r"), runner=shell)
    rules = await drv.firewall_rules()
    names = {r.name: r for r in rules}
    assert names["Allow-DHCP-Renew"].chain == "input"
    assert names["rerouter-block-aabbccddeeff"].managed
    assert names["rerouter-block-aabbccddeeff"].chain == "forward"
    fwd = await drv.port_forwards()
    assert fwd[0].proto == "tcp+udp" and fwd[0].int_ip == "192.168.1.10"

    await drv.add_firewall_rule(FirewallRuleIn(name="web block", action="reject",
                                               proto="tcp", dst_port="80"))
    script = shell.commands[-1]
    assert "uci set firewall.cfg99.name='web block'" in script
    assert "uci commit firewall" in script and "/etc/init.d/firewall reload" in script


async def test_openwrt_delete_rejects_unknown_section():
    from rerouter.drivers.base import DriverError

    shell = FakeShell({"uci -X show": UCI_FIREWALL})
    drv = OpenWrtRouter(RouterConfig(driver="openwrt", host="r"), runner=shell)
    with pytest.raises(DriverError):
        await drv.delete_firewall_rule("cfg0a92bd; reboot")
    assert not any("reboot" in c for c in shell.commands)


def test_routeros_durations():
    assert parse_duration("1w2d3h4m5s") == 604800 + 2 * 86400 + 3 * 3600 + 245
    assert parse_duration("00:01:02") == 62
    assert parse_duration("9m50s") == 590


async def test_routeros_driver_with_mock_api():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, request.content))
        path = request.url.path.removeprefix("/rest/")
        if path == "interface":
            return httpx.Response(200, json=[
                {".id": "*1", "name": "ether1", "type": "ether", "running": "true",
                 "disabled": "false", "rx-byte": "100", "tx-byte": "200",
                 "mac-address": "AA:BB:CC:00:00:01"}])
        if path == "ip/address":
            return httpx.Response(200, json=[{"address": "203.0.113.2/24", "interface": "ether1"}])
        if path == "interface/list/member":
            return httpx.Response(200, json=[{"interface": "ether1", "list": "WAN"}])
        if path == "ipv6/address":
            return httpx.Response(200, json=[])
        if path == "ip/firewall/filter" and request.method == "GET":
            return httpx.Response(200, json=[{".id": "*A", "chain": "forward", "action":
                                              "fasttrack-connection"}])
        if path == "ip/firewall/filter" and request.method == "PUT":
            body = json.loads(request.content)
            return httpx.Response(201, json={".id": "*B", **body})
        if path == "interface/wifi":
            return httpx.Response(200, json=[{".id": "*5", "name": "wifi1",
                                              "configuration.ssid": "Home",
                                              "channel.band": "5ghz-ax", "disabled": "false"}])
        if path == "interface/wifi/registration-table":
            return httpx.Response(200, json=[{"interface": "wifi1"}, {"interface": "wifi1"}])
        if request.method == "PATCH":
            return httpx.Response(200, json={})
        return httpx.Response(404, json={"error": 404, "message": "Not Found"})

    drv = RouterOSRouter(RouterConfig(driver="routeros", host="r", password="x"),
                         transport=httpx.MockTransport(handler))
    [iface] = await drv.interfaces()
    assert iface.role == "wan" and iface.addresses == ["203.0.113.2/24"] and iface.tx_bytes == 200
    rule = await drv.add_firewall_rule(FirewallRuleIn(name="rerouter-block-x", action="reject",
                                                      src_mac="aa:bb:cc:dd:ee:ff"))
    assert rule.id == "*B" and rule.managed
    put = json.loads(next(c for c in calls if c[0] == "PUT")[2])
    assert put["place-before"] == "*A" and put["src-mac-address"] == "AA:BB:CC:DD:EE:FF"
    [net] = await drv.wifi()
    assert net.ssid == "Home" and net.band == "5 GHz" and net.clients == 2
    await drv.update_wifi("*5", WifiUpdate(ssid="New", key="supersecret"))
    patch = json.loads(next(c for c in calls if c[0] == "PATCH")[2])
    assert patch == {"configuration.ssid": "New", "security.passphrase": "supersecret"}
    with pytest.raises(Exception):
        await drv.delete_firewall_rule("../../system/reboot")
    await drv.close()
