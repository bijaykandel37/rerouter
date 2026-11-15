# Decrypting HTTPS for devices you control (mitmproxy integration)

rerouter's default traffic analysis is **passive**: it reads flow metadata and
the parts of TLS/HTTP that travel in the clear (SNI, DNS, HTTP Host, JA3
fingerprints). It never decrypts payloads, because payloads can't be decrypted
by observing the wire.

Sometimes you genuinely need to see *inside* HTTPS — for example to find out
exactly what data a specific IoT device uploads, or to debug an app on a device
you own. The established way to do that is a **man-in-the-middle TLS proxy**
([mitmproxy](https://mitmproxy.org/)) combined with installing the proxy's CA
certificate on the target device, so the device encrypts to the proxy, the
proxy decrypts and inspects, then re-encrypts to the real server.

This integration sends the resulting request metadata into rerouter so it shows
up under **Decrypted HTTP**.

## Read this first — scope and consent

TLS interception only works on a device **where you install the mitmproxy CA**.
That is the boundary, and it is not a technicality:

- Use it **only on devices you own and administer**.
- The people who use those devices should **know** their HTTPS is being
  inspected. On a shared network, do not intercept other people's devices.
- Interception exposes everything those devices send over HTTPS — credentials,
  tokens, personal data. Treat the rerouter database accordingly, keep the
  ingest token secret, and keep the retention window short
  (System → Settings → "Keep decrypted HTTP").
- Many apps use **certificate pinning** and will simply fail to connect through
  the proxy rather than be intercepted. That is expected; don't try to defeat
  pinning on devices or apps that aren't yours to modify.

If what you actually need is "which services is this device talking to," you
usually don't need any of this — the passive **Traffic explorer** (SNI/DNS/JA3)
already answers it without decrypting anything.

## 1. Enable the ingest endpoint on rerouter

Set a shared secret and restart rerouter:

```bash
export REROUTER_INGEST_TOKEN="$(openssl rand -hex 24)"
```

(or add `REROUTER_INGEST_TOKEN` to `docker-compose.yml` / your env). Until this
is set, `POST /api/ingest/http` returns 404 and the **Decrypted HTTP** page
shows a disabled notice.

## 2. Install mitmproxy

```bash
pipx install mitmproxy    # or: pip install mitmproxy
```

## 3. Run the addon

The addon lives at `integrations/rerouter_mitm.py`. Point it at rerouter and
give it the same token:

```bash
export REROUTER_URL="http://127.0.0.1:8080"
export REROUTER_INGEST_TOKEN="<the token from step 1>"
```

```bash
mitmdump --mode transparent -s integrations/rerouter_mitm.py
```

- Use `--mode transparent` when the device's traffic is routed through this host
  (see step 4). Use the default regular mode if you configure the device to use
  this host as an explicit HTTP/HTTPS proxy instead.
- By default the addon sends **metadata only** (method, host, path, status,
  content types, sizes, timing). To also store a short, truncated text snippet
  of each response body, set `REROUTER_MITM_BODIES=1` — only do this when you
  need payload content and accept that it is stored.

## 4. Route the target device through mitmproxy

Pick whichever fits your setup:

- **Explicit proxy** (simplest, per device): in the device's network settings,
  set the HTTP/HTTPS proxy to `this-host:8080` (mitmproxy's default listen
  port). No routing changes needed; run `mitmdump` without `--mode transparent`.
- **Transparent, on the router/gateway**: policy-route the device's traffic to
  this host and redirect ports 80/443 to mitmproxy. mitmproxy's docs cover the
  nftables/pf rules for a Linux or BSD gateway.

## 5. Install the mitmproxy CA on the target device

With the proxy running, browse to <http://mitm.it> **from the target device**
and follow the per-OS instructions to install and trust the certificate. This
is the step that makes interception possible — and the reason it only works on
devices you administer. mitmproxy has per-platform guides (including the extra
"trust" step on iOS/Android).

## 6. View the data

Open **Decrypted HTTP** in rerouter. You'll see per-request rows (client,
method, host, path, status, size, latency) and top hosts, filterable by client,
host, method and status. Transactions are pruned per the retention setting.

## Turning it off

- Stop `mitmdump`.
- **Remove the mitmproxy CA from the device** when you're done.
- Clear stored data with the **Clear all** button on the Decrypted HTTP page, or
  by unsetting `REROUTER_INGEST_TOKEN` (which also disables ingest).
