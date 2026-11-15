"""Static process configuration.

Configuration is read from (in increasing priority):

1. built-in defaults,
2. a TOML file pointed to by ``REROUTER_CONFIG`` (see ``rerouter.example.toml``),
3. ``REROUTER_*`` environment variables.

Anything an administrator may want to change at runtime (LAN subnets, alert
thresholds, retention...) lives in the database instead -- see ``settings.py``.
Router credentials deliberately stay here, out of the database and the API.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RouterConfig:
    driver: str = "simulated"  # simulated | openwrt | routeros
    host: str = ""
    port: int | None = None
    username: str = "root"
    password: str | None = None
    key_file: str | None = None
    # RouterOS REST only
    use_https: bool = True
    verify_tls: bool = False
    # SSH only: path to a known_hosts file. None disables host-key checking,
    # which is convenient on a LAN but should be set in production.
    known_hosts: str | None = None
    timeout: float = 10.0


@dataclass
class Config:
    data_dir: Path = Path("./data")
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    poll_interval: float = 5.0
    device_refresh_interval: float = 60.0

    netflow_enabled: bool = True
    netflow_bind: str = "0.0.0.0"
    netflow_port: int = 2055

    # Name of a local interface to sniff (AF_PACKET, Linux, needs CAP_NET_RAW).
    capture_interface: str | None = None

    # Generate synthetic traffic. Defaults to on when the simulated driver is used.
    simulate_traffic: bool | None = None

    admin_password: str | None = None
    cookie_secure: bool = False
    session_ttl_hours: int = 12

    # Shared secret for the mitmproxy HTTP-transaction ingest endpoint. When
    # unset the endpoint is disabled. See docs/mitmproxy.md.
    ingest_token: str | None = None

    router: RouterConfig = field(default_factory=RouterConfig)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "rerouter.db"

    @property
    def simulation_enabled(self) -> bool:
        if self.simulate_traffic is None:
            return self.router.driver == "simulated"
        return self.simulate_traffic


_BOOL_TRUE = {"1", "true", "yes", "on"}


def _coerce(value: str, current: object) -> object:
    if isinstance(current, bool):
        return value.strip().lower() in _BOOL_TRUE
    if isinstance(current, int):
        return int(value)
    if isinstance(current, float):
        return float(value)
    if isinstance(current, Path):
        return Path(value)
    return value or None


# Fields whose default is None and that need a type hint for env coercion.
_OPTIONAL_TYPES: dict[str, type] = {
    "port": int,
    "simulate_traffic": bool,
}


def _apply(obj: object, values: dict, prefix: str = "") -> None:
    for key, value in values.items():
        key = key.replace("-", "_")
        if not hasattr(obj, key):
            raise ValueError(f"unknown config key: {prefix}{key}")
        current = getattr(obj, key)
        if isinstance(value, dict):
            _apply(current, value, prefix=f"{prefix}{key}.")
            continue
        if isinstance(value, str) and (current is None or not isinstance(current, str)):
            hint = _OPTIONAL_TYPES.get(key)
            if current is None and hint is not None:
                value = _coerce(value, hint())  # type: ignore[call-arg]
            elif current is not None:
                value = _coerce(value, current)
        if isinstance(current, Path) and not isinstance(value, Path):
            value = Path(value)
        setattr(obj, key, value)


def load_config(env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ if env is None else env)
    cfg = Config()

    path = env.get("REROUTER_CONFIG")
    if path:
        with open(path, "rb") as fh:
            _apply(cfg, tomllib.load(fh))

    for name, value in env.items():
        if not name.startswith("REROUTER_") or name == "REROUTER_CONFIG":
            continue
        key = name[len("REROUTER_"):].lower()
        if key.startswith("router_"):
            _apply(cfg.router, {key[len("router_"):]: value}, prefix="router.")
        elif hasattr(cfg, key):
            _apply(cfg, {key: value})

    for attr in ("key_file", "known_hosts"):
        value = getattr(cfg.router, attr)
        if value:
            setattr(cfg.router, attr, os.path.expanduser(value))
    cfg.data_dir = cfg.data_dir.expanduser()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    return cfg
