# rerouter

A self-hosted platform to **administer and monitor your router**, built around
**complete visibility of the traffic to, from and through it**. That makes it useful
both as a day-to-day admin console and as a data source for network research.

- **Configure**: interfaces, firewall rules, port forwarding, static routes,
  DHCP reservations, upstream DNS, Wi-Fi (SSID, key, channel, on/off), reboot and
  config backup. Every change is validated, applied on the router and written to an
  audit log.
- **Monitor**: live WAN/LAN throughput, router health (CPU, memory, temperature,
  uptime), device inventory with vendor lookup and one-click internet blocking,
  router logs, ping/traceroute/DNS tools.
- **Visualize traffic**: per-flow data from NetFlow v5/v9, IPFIX or packet capture,
  shown in several views:
  - stacked time series grouped by direction, application, device, destination, **host (SNI)**, protocol or port;
  - a **device → application → destination Sankey**;
  - a **host communication graph**;
  - a **weekday × hour heatmap**;
  - **flow-size and duration distributions**, to show where the volume sits in the heavy tail;
  - ranked tables of top devices, destinations, apps, ports, conversations, **hosts and client fingerprints**;
  - a searchable flow-record table and a live flow stream.
- **Inspect without decrypting**: the packet-capture collector passively reads the
  cleartext parts of connections — **TLS SNI** (the destination hostname), **HTTP
  Host/User-Agent**, offered TLS version/ALPN, and a **JA3 client fingerprint** that
  identifies the client software — and attaches them to flows. Nothing is decrypted.
- **Decrypt, for devices you control**: an opt-in [mitmproxy integration](docs/mitmproxy.md)
  feeds full HTTP request detail from TLS-intercepted devices into a **Decrypted HTTP**
  view. This works only on devices where you install the proxy CA; see the doc for the
  consent and scope rules.
- **Detect anomalies**: inbound port scans, LAN devices scanning the internet
  (e.g. Mirai-style IoT compromise), connections on risky ports (telnet/SMB/RDP…),
  per-device traffic spikes against their own baseline, bulk uploads, new devices,
  interfaces going down or erroring, and the router becoming unreachable.
- **Export for research**: stream any filtered slice of flows as CSV or JSON-lines
  for pandas/R/Jupyter, or query the REST API directly (OpenAPI docs at `/api/docs`).

Supported routers: **OpenWrt** (SSH + `uci`/`ubus`) and **MikroTik RouterOS v7**
(REST API). A built-in **simulator** models a realistic household network (daily usage
rhythms, streaming, IoT, backups, plus injected port scans, data exfiltration and
telnet probing). You can explore every feature before connecting hardware.

---

## Quick start

### Docker (recommended)

```bash
docker compose up -d --build
```

```bash
docker compose logs rerouter | grep -A1 "initial user"
```

Open <http://localhost:8080> and sign in as `admin` with the password printed in the
log, or set `REROUTER_ADMIN_PASSWORD` in `docker-compose.yml` before the first start.
It starts in **simulated** mode, with 24 hours of synthetic history already loaded.

### From source

Requires Python ≥ 3.11 and Node ≥ 18.

```bash
cd frontend && npm ci && npm run build && cd ..
```

```bash
pip install -e "backend[dev]"
```

```bash
REROUTER_ADMIN_PASSWORD='choose-a-long-password' rerouter --port 8080
```

For UI development, run the backend on :8080 and `npm run dev` in `frontend/`.
Vite proxies `/api` and the WebSocket to it.

---

## Connecting your router

Configuration comes from environment variables (`REROUTER_*`) or a TOML file
(`REROUTER_CONFIG=/path/rerouter.toml`; see [`rerouter.example.toml`](rerouter.example.toml)).
Router credentials live **only** there, never in the database or the API.

### OpenWrt

```bash
REROUTER_ROUTER_DRIVER=openwrt \
REROUTER_ROUTER_HOST=192.168.1.1 \
REROUTER_ROUTER_USERNAME=root \
REROUTER_ROUTER_KEY_FILE=~/.ssh/id_ed25519 \
REROUTER_ROUTER_KNOWN_HOSTS=~/.ssh/known_hosts \
rerouter
```

Password authentication works via `REROUTER_ROUTER_PASSWORD`. Changes go through
`uci` + `commit` + a service reload, exactly as LuCI does. Device blocking creates a
managed firewall rule named `rerouter-block-<mac>`.

### MikroTik RouterOS 7

Enable the REST API (`/ip service enable www-ssl`; HTTPS is strongly recommended)
and create a dedicated user:

```
/user add name=rerouter group=full password=...
```

```bash
REROUTER_ROUTER_DRIVER=routeros REROUTER_ROUTER_HOST=192.168.88.1 \
REROUTER_ROUTER_USERNAME=rerouter REROUTER_ROUTER_PASSWORD=... rerouter
```

Block rules are placed at the top of the filter chain so fasttrack can't bypass them.

---

## Getting traffic data

rerouter needs per-flow records. Choose one source, or combine several.

| Source | When to use | Setup |
|---|---|---|
| **NetFlow v9 / IPFIX** (default, `udp/2055`) | Most routers | Point the router's exporter at `<rerouter-ip>:2055`. **System → Data collection → Configure exporter** does it for you: `softflowd` on OpenWrt (`opkg install softflowd` first), Traffic Flow on MikroTik. |
| **NetFlow v5** | Older gear | Same port; sampling rates are honoured. |
| **Packet capture** | rerouter runs on the router, in-line, or on a switch **mirror/SPAN** port | `REROUTER_CAPTURE_INTERFACE=eth1` (Linux, needs `CAP_NET_RAW`). Also decodes DNS answers, so remote IPs get the hostnames clients actually asked for. |

Traffic is classified using your **LAN networks** (System → Settings; RFC 1918 + ULA
by default) and the router's own addresses, which are detected automatically:

| direction | meaning |
|---|---|
| `download` | remote → local |
| `upload` | local → remote |
| `lan` | local ↔ local |
| `transit` | neither side local |

Applications are inferred from well-known ports (`https`, `quic`, `dns`, `ssh`, `mqtt`,
`stun/webrtc`, …).

> **NAT note:** a flow exporter on the LAN bridge (e.g. `softflowd -i br-lan`) sees
> device addresses before NAT, which is what per-device analytics need. An exporter
> on the WAN interface only sees the router's public IP.

---

## Seeing inside the traffic

Two layers, from least to most invasive. Most monitoring questions are answered by
the first one.

### Passive inspection (no decryption)

When the **packet-capture** collector is running (`REROUTER_CAPTURE_INTERFACE`,
on the router or a mirror/SPAN port), rerouter reads the metadata that endpoints
send in the clear at connection setup and attaches it to flows:

- **TLS SNI** — the hostname the client asked for, so HTTPS flows show their real
  destination (e.g. `telemetry.vendor.com`) even though the payload stays encrypted;
- **HTTP Host / User-Agent** for cleartext HTTP;
- offered **TLS version** and ALPN;
- a **JA3 client fingerprint** — a hash of the TLS ClientHello that identifies the
  client software and is stable across destinations, which is excellent for spotting
  a specific (or rogue) client across the network.

These appear as the **Host (SNI)** column and as group-by / ranking dimensions in the
Traffic explorer, and as live annotations in the flow stream. Nothing is decrypted:
TLS application data is never parsed. For most "what is this device doing / talking
to" questions this is all you need.

### Decryption, per device (mitmproxy)

To read HTTPS payloads you must terminate TLS, which is only possible on a device
where you install a proxy CA. rerouter ships an opt-in integration for this — a
mitmproxy addon that forwards decrypted HTTP transactions to a token-authenticated
ingest endpoint, shown under **Decrypted HTTP**. It applies **only to devices you own
and administer**, with the knowledge of the people who use them, and it is disabled
until you set `REROUTER_INGEST_TOKEN`. Full setup, scope and consent guidance:
**[docs/mitmproxy.md](docs/mitmproxy.md)**.

---

## Using the data for research

- **Explorer → Export CSV / JSONL** streams every flow that matches the current
  filters (time range, device, app, direction, protocol, IP, port).
- The same exports and aggregations are available from the API. Authenticate with
  the token returned by `/api/auth/login`:

  ```bash
  TOKEN=$(curl -s -X POST localhost:8080/api/auth/login -H 'content-type: application/json' \
          -d '{"username":"admin","password":"..."}' | jq -r .token)
  ```

  ```bash
  curl -H "Authorization: Bearer $TOKEN" \
       "localhost:8080/api/traffic/export?range=7d&format=csv" -o flows.csv
  ```

  ```bash
  curl -H "Authorization: Bearer $TOKEN" \
       "localhost:8080/api/traffic/timeseries?range=24h&group_by=app&metric=bytes"
  ```

  Other endpoints: `/api/traffic/{summary,top,sankey,graph,heatmap,distribution,flows}`
  and `/api/interfaces/{name}/history`. The live stream is a WebSocket at `/api/live`
  (topics: `rates`, `flows`, `alert`, `system`).
- **Flow record columns:** `ts_start, ts_end, src_ip, dst_ip, src_port, dst_port, proto,
  bytes, packets, tcp_flags, direction, local_ip, remote_ip, local_port, remote_port,
  app, source, exporter, host, fingerprint, tls_version`. Exports add
  `proto_name, local_name, remote_name`. (`host`/`fingerprint`/`tls_version` are
  populated by the packet-capture collector; `/api/http*` serves the decrypted-HTTP
  table separately.)
- Data lives in a single SQLite file (`data/rerouter.db`, WAL mode), so you can also
  open it directly. Retention is configurable (flows: 30 days by default).
- Analytics attribute each flow to the time bucket containing its end time. With the
  15–60 s active timeouts used by exporters, this is accurate at the bucket sizes shown.

---

## Security

- One local admin account (scrypt-hashed). Sessions are HttpOnly, `SameSite=Strict`
  cookies; login attempts are rate-limited per client.
- Every write is validated: IPs, CIDRs, ports, MACs and names are checked against
  strict patterns. Values sent to the router are additionally shell-quoted (OpenWrt)
  or sent as JSON (RouterOS), and section/rule IDs are checked against the router's
  own config before use.
- All configuration changes, logins and exports are recorded in the audit log
  (Wi-Fi keys are masked).
- Run it on your LAN or behind a VPN. If you expose it via a reverse proxy, terminate
  TLS there and set `REROUTER_COOKIE_SECURE=true`. For OpenWrt, set
  `known_hosts` to enable SSH host-key verification.

---

## Architecture

```
            ┌──────────── router ────────────┐
            │ OpenWrt (SSH/uci) · RouterOS   │
            │ (REST) · simulator             │
            └──┬──────────────────────┬──────┘
   config/state│                      │NetFlow/IPFIX (udp 2055)
               ▼                      ▼            packet capture (AF_PACKET)
        drivers/*  ──►  poller   collectors/netflow, capture
                        │ rates,      │ raw flow records
                        │ devices     ▼
                        │        flowstore: classify (direction, app,
                        │        local/remote) → SQLite (batched)
                        ▼             │
                     alerts ◄─────────┤  analytics (time series, sankey, graph,
                        │             │  heatmap, distributions, top-N, export)
                        ▼             ▼
                  live hub ──► FastAPI REST + WebSocket ──► React + ECharts UI
```

```
backend/rerouter/
  drivers/      simulated.py · openwrt.py · routeros.py · base.py (interface)
  collectors/   netflow.py (v5/v9/IPFIX) · capture.py · flowstore.py · poller.py
  analytics.py  alerts.py  auth.py  settings.py  db.py  netutil.py  core.py  app.py
  api/          REST routes + /api/live WebSocket
frontend/src/   pages/ (dashboard, explorer, live, devices, interfaces,
                network, diagnostics, alerts, system) · components/ (charts, UI)
```

Adding another router family means implementing `RouterDriver`
(`backend/rerouter/drivers/base.py`). Methods you don't implement raise
`NotSupported`, and the UI hides those features.

## Development

```bash
cd backend && pytest -q
```

```bash
cd frontend && npm run typecheck && npm run build
```

The backend tests cover:

- NetFlow v5/v9/IPFIX decoding;
- packet and DNS parsing;
- classification;
- OpenWrt `uci` parsing, including command quoting and injection rejection;
- the RouterOS driver against a mocked REST API;
- analytics and scan detection;
- the authenticated API, including CRUD, validation, audit and the WebSocket.
