"""mitmproxy addon that forwards decrypted HTTP transaction *metadata* to
rerouter's ingest endpoint.

This is the decrypting half of rerouter's traffic analysis. It only works for
devices whose traffic you deliberately route through mitmproxy **and** on which
you have installed mitmproxy's CA certificate -- i.e. devices you own and
administer, with the knowledge of the people who use them. It cannot and must
not be used to silently decrypt other people's traffic. See docs/mitmproxy.md.

Usage:

    export REROUTER_URL=http://127.0.0.1:8080
    export REROUTER_INGEST_TOKEN=<the token you set as REROUTER_INGEST_TOKEN on rerouter>
    mitmdump --mode transparent -s integrations/rerouter_mitm.py

By default only metadata is sent (method, host, path, status, content types and
sizes, timing). Set REROUTER_MITM_BODIES=1 to also attach a short, truncated
text snippet of each response to the ``note`` field -- do this only when you
genuinely need payload content and understand you are storing it.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import urllib.request

try:
    from mitmproxy import ctx, http
except ImportError:  # allow importing the module (e.g. for linting) without mitmproxy
    ctx = None
    http = None

_TEXT_TYPES = ("text/", "application/json", "application/xml", "application/x-www-form")


class RerouterExporter:
    def __init__(self) -> None:
        self.url = os.environ.get("REROUTER_URL", "http://127.0.0.1:8080").rstrip("/")
        self.token = os.environ.get("REROUTER_INGEST_TOKEN", "")
        self.note_bodies = os.environ.get("REROUTER_MITM_BODIES", "") in ("1", "true", "yes")
        self.batch_size = int(os.environ.get("REROUTER_MITM_BATCH", "50"))
        self.flush_interval = float(os.environ.get("REROUTER_MITM_INTERVAL", "3"))
        self._q: queue.Queue = queue.Queue(maxsize=10000)
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._run, name="rerouter-export", daemon=True)

    # -- mitmproxy lifecycle hooks -----------------------------------------
    def load(self, loader) -> None:  # noqa: ARG002
        if not self.token:
            if ctx:
                ctx.log.warn("rerouter: REROUTER_INGEST_TOKEN is not set; not exporting")
            return
        self._worker.start()
        if ctx:
            ctx.log.info(f"rerouter: exporting HTTP transactions to {self.url}/api/ingest/http")

    def done(self) -> None:
        self._stop.set()

    def response(self, flow) -> None:
        if not self.token or http is None:
            return
        try:
            self._q.put_nowait(self._record(flow))
        except queue.Full:
            pass  # drop under backpressure rather than stall the proxy

    # -- internals ----------------------------------------------------------
    def _record(self, flow) -> dict:
        req, resp = flow.request, flow.response
        peer = getattr(flow.client_conn, "peername", None) or (None, None)
        note = None
        if self.note_bodies and resp and _is_text(resp.headers.get("content-type", "")):
            try:
                note = resp.get_text(strict=False)[:2000]
            except Exception:
                note = None
        return {
            "ts": getattr(req, "timestamp_start", None) or time.time(),
            "client_ip": peer[0],
            "client_port": peer[1],
            "method": req.method,
            "scheme": req.scheme,
            "host": req.pretty_host,
            "path": req.path,
            "status": resp.status_code if resp else None,
            "req_type": req.headers.get("content-type", "").split(";")[0] or None,
            "req_bytes": len(req.raw_content or b""),
            "resp_type": (resp.headers.get("content-type", "").split(";")[0] or None)
            if resp else None,
            "resp_bytes": len(resp.raw_content or b"") if resp else None,
            "duration_ms": _duration_ms(req, resp),
            "note": note,
        }

    def _run(self) -> None:
        pending: list[dict] = []
        last = time.time()
        while not self._stop.is_set() or not self._q.empty() or pending:
            timeout = max(0.1, self.flush_interval - (time.time() - last))
            try:
                pending.append(self._q.get(timeout=timeout))
            except queue.Empty:
                pass
            if pending and (len(pending) >= self.batch_size
                            or time.time() - last >= self.flush_interval
                            or self._stop.is_set()):
                self._post(pending)
                pending = []
                last = time.time()

    def _post(self, transactions: list[dict]) -> None:
        body = json.dumps({"transactions": transactions}).encode()
        req = urllib.request.Request(
            f"{self.url}/api/ingest/http", data=body, method="POST",
            headers={"Content-Type": "application/json", "X-Ingest-Token": self.token})
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
        except Exception as exc:  # pragma: no cover - network dependent
            if ctx:
                ctx.log.warn(f"rerouter: ingest failed ({exc}); dropping {len(transactions)}")


def _is_text(content_type: str) -> bool:
    return content_type.startswith(_TEXT_TYPES)


def _duration_ms(req, resp) -> float | None:
    start = getattr(req, "timestamp_start", None)
    end = getattr(resp, "timestamp_end", None) if resp else None
    return (end - start) * 1000 if start and end else None


addons = [RerouterExporter()]
