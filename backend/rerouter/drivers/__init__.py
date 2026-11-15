from ..config import RouterConfig
from .base import DriverError, NotSupported, RouterDriver

__all__ = ["create_driver", "DriverError", "NotSupported", "RouterDriver"]


def create_driver(cfg: RouterConfig) -> RouterDriver:
    kind = cfg.driver.lower()
    if kind == "simulated":
        from .simulated import SimulatedRouter
        return SimulatedRouter()
    if kind == "openwrt":
        from .openwrt import OpenWrtRouter
        return OpenWrtRouter(cfg)
    if kind in ("routeros", "mikrotik"):
        from .routeros import RouterOSRouter
        return RouterOSRouter(cfg)
    raise ValueError(f"unknown router driver: {cfg.driver!r} (simulated|openwrt|routeros)")
