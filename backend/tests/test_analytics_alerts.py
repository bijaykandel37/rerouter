import time

from rerouter.alerts import AlertEngine
from rerouter.analytics import Query, sankey, summary, timeseries, top
from rerouter.collectors.flowstore import FlowRecord, FlowSink
from rerouter.live import LiveHub
from rerouter.netutil import NetworkClassifier
from rerouter.settings import SettingsStore


async def _sink(db):
    sink = FlowSink(db, NetworkClassifier(["192.168.1.0/24"]), LiveHub())
    return sink


async def test_ingest_and_analytics(db):
    sink = await _sink(db)
    now = time.time()
    sink.submit([
        FlowRecord(now - 5, now - 1, "8.8.8.8", "192.168.1.2", 443, 50000, 6, 10_000, 10),
        FlowRecord(now - 5, now - 1, "192.168.1.2", "8.8.8.8", 50000, 443, 6, 1_000, 8),
        FlowRecord(now - 5, now - 1, "192.168.1.3", "192.168.1.2", 50001, 445, 6, 500, 2),
    ])
    sink.learn_names({"8.8.8.8": "dns.google"}, "dns")
    assert await sink.flush() == 3
    q = Query.from_params(range_="1h")
    s = summary(db, q)
    assert (s["download"], s["upload"], s["lan"], s["flows"]) == (10_000, 1_000, 500, 3)
    ts = timeseries(db, Query.from_params(range_="1h"), group_by="direction")
    assert sum(sum(x["values"]) for x in ts["series"]) == 11_500
    remote = top(db, Query.from_params(range_="1h", exclude_lan=True), by="remote_ip")
    assert remote[0]["label"] == "dns.google" and remote[0]["download"] == 10_000
    sk = sankey(db, Query.from_params(range_="1h"))
    assert {n["id"] for n in sk["nodes"]} >= {"app:https", "dst:dns.google"}


async def test_scan_detection(db):
    sink = await _sink(db)
    now = time.time()
    sink.submit([FlowRecord(now - 1, now - 1, "185.220.101.7", "192.168.1.2", 40000, port, 6,
                            60, 1, tcp_flags=0x02) for port in range(1, 60)])
    await sink.flush()
    settings = SettingsStore(db)
    engine = AlertEngine(db, LiveHub(), settings)
    assert await engine.check() == 1
    alert = db.query_one("SELECT * FROM alerts")
    assert alert["kind"] == "inbound_scan" and alert["subject"] == "185.220.101.7"
    assert await engine.check() == 0  # cooldown dedups
