"""Wires all components together and owns their background tasks."""

from __future__ import annotations

import asyncio
import contextlib
import logging

from .alerts import AlertEngine
from .auth import Auth
from .collectors.capture import PacketCapture
from .collectors.flowstore import FlowSink
from .collectors.netflow import NetflowCollector
from .collectors.poller import Poller
from .config import Config
from .db import Database
from .drivers import RouterDriver, create_driver
from .live import LiveHub
from .netutil import NetworkClassifier
from .settings import RuntimeSettings, SettingsStore

log = logging.getLogger(__name__)


class Platform:
    def __init__(self, cfg: Config, driver: RouterDriver | None = None):
        self.cfg = cfg
        self.db = Database(cfg.db_path)
        self.settings = SettingsStore(self.db)
        self.settings.load()
        s = self.settings.current
        self.classifier = NetworkClassifier(s.lan_networks, s.router_ips)
        self.hub = LiveHub()
        self.sink = FlowSink(self.db, self.classifier, self.hub)
        self.sink.reverse_dns = s.reverse_dns
        self.driver = driver or create_driver(cfg.router)
        self.alerts = AlertEngine(self.db, self.hub, self.settings)
        self.poller = Poller(self.driver, self.db, self.hub, self.alerts, self.settings,
                             self.classifier, cfg.poll_interval, cfg.device_refresh_interval,
                             on_router_names=lambda n: self.sink.learn_names(n, "router"))
        self.netflow = (NetflowCollector(self.sink, cfg.netflow_bind, cfg.netflow_port)
                        if cfg.netflow_enabled else None)
        self.capture = (PacketCapture(self.sink, cfg.capture_interface)
                        if cfg.capture_interface else None)
        self.auth = Auth(self.db, cfg.session_ttl_hours)
        self._tasks: list[asyncio.Task] = []
        self.settings.on_change(self._settings_changed)

    def _settings_changed(self, s: RuntimeSettings) -> None:
        self.classifier.update(s.lan_networks, s.router_ips + self.poller.router_ips)
        self.sink.reverse_dns = s.reverse_dns

    async def start(self) -> None:
        generated = self.auth.ensure_admin(self.cfg.admin_password)
        if generated:
            log.warning("=" * 60)
            log.warning("Created initial user 'admin' with password: %s", generated)
            log.warning("Change it in System > Account, or set REROUTER_ADMIN_PASSWORD.")
            log.warning("=" * 60)
        try:
            await asyncio.wait_for(self.driver.connect(), timeout=self.cfg.router.timeout + 5)
        except Exception as exc:  # keep running; the poller will retry and alert
            log.error("could not connect to router: %s", exc)

        self._spawn(self.sink.run(), "flow-sink")
        self._spawn(self.poller.run(), "poller")
        self._spawn(self.alerts.run(), "alerts")
        if self.netflow:
            await self.netflow.start()
        if self.capture:
            self.capture.start()
        if self.cfg.simulation_enabled:
            from .drivers.simulated import SimulatedRouter

            if isinstance(self.driver, SimulatedRouter):
                empty = not self.db.query_one("SELECT 1 FROM flows LIMIT 1")
                self._spawn(self.driver.run_traffic(self.sink, backfill_hours=24 if empty else 0),
                            "simulator")
            else:
                log.warning("simulate_traffic is only available with the simulated driver")

    def _spawn(self, coro, name: str) -> None:
        task = asyncio.create_task(coro, name=name)
        task.add_done_callback(self._task_done)
        self._tasks.append(task)

    @staticmethod
    def _task_done(task: asyncio.Task) -> None:
        if not task.cancelled() and task.exception():
            log.error("background task %s crashed", task.get_name(), exc_info=task.exception())

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        if self.netflow:
            self.netflow.stop()
        if self.capture:
            self.capture.stop()
        with contextlib.suppress(Exception):
            await self.sink.flush()
        with contextlib.suppress(Exception):
            await self.driver.close()
        self.db.close()

    def status(self) -> dict:
        return {
            "driver": self.driver.name,
            "router_host": self.cfg.router.host or None,
            "capabilities": sorted(self.driver.capabilities),
            "online": self.poller.online,
            "last_error": self.poller.last_error,
            "simulation": self.cfg.simulation_enabled,
            "collectors": {
                "netflow": self.netflow.status() if self.netflow else None,
                "capture": self.capture.status() if self.capture else None,
                "sink": {k: (dict(v) if k == "by_source" else v)
                         for k, v in self.sink.stats.items()},
            },
            "live_subscribers": self.hub.subscriber_count,
        }
