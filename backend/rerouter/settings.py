"""Runtime settings, editable from the UI and persisted in the database."""

from __future__ import annotations

import json

from pydantic import BaseModel, Field, field_validator

from .db import Database
from .models import validate_cidr, validate_ip


class AlertThresholds(BaseModel):
    # A device whose per-minute volume exceeds mean + k*stddev of the last hour.
    spike_sigma: float = Field(default=4.0, ge=1.0, le=20.0)
    spike_min_bytes: int = Field(default=250_000_000, ge=0)  # bytes/minute floor
    # Distinct (host, port) targets touched by one source within 5 minutes.
    scan_targets: int = Field(default=40, ge=5)
    # Upload volume (bytes per 10 minutes) from a single device.
    upload_bytes_10m: int = Field(default=1_000_000_000, ge=0)
    # Outbound connections to these remote ports from LAN devices are flagged.
    risky_ports: list[int] = Field(default_factory=lambda: [23, 445, 3389, 5900, 1080, 6667])
    new_device: bool = True
    interface_errors: int = Field(default=100, ge=0)  # errors per poll interval


class RuntimeSettings(BaseModel):
    lan_networks: list[str] = Field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                 "fc00::/7", "100.64.0.0/10"])
    router_ips: list[str] = Field(default_factory=list)
    flow_retention_days: int = Field(default=30, ge=1, le=3650)
    sample_retention_days: int = Field(default=90, ge=1, le=3650)
    reverse_dns: bool = False
    alerts: AlertThresholds = Field(default_factory=AlertThresholds)

    @field_validator("lan_networks")
    @classmethod
    def _nets(cls, v: list[str]) -> list[str]:
        return [validate_cidr(n) for n in v]

    @field_validator("router_ips")
    @classmethod
    def _ips(cls, v: list[str]) -> list[str]:
        return [validate_ip(i) for i in v]


class SettingsStore:
    KEY = "runtime"

    def __init__(self, db: Database):
        self.db = db
        self.current = RuntimeSettings()
        self._listeners: list = []

    def load(self) -> RuntimeSettings:
        row = self.db.query_one("SELECT value FROM settings WHERE key=?", (self.KEY,))
        if row:
            self.current = RuntimeSettings.model_validate(json.loads(row["value"]))
        return self.current

    def on_change(self, fn) -> None:
        self._listeners.append(fn)

    async def save(self, new: RuntimeSettings) -> RuntimeSettings:
        await self.db.aexecute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (self.KEY, new.model_dump_json()),
        )
        self.current = new
        for fn in self._listeners:
            fn(new)
        return new
