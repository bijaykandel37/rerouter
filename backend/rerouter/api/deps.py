from __future__ import annotations

import json
import time

from fastapi import Depends, HTTPException, Query as Q, Request

from ..analytics import Query
from ..core import Platform
from ..drivers import DriverError, NotSupported

COOKIE = "rerouter_session"


def platform(request: Request) -> Platform:
    return request.app.state.platform


def token_from(request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.cookies.get(COOKIE)


async def current_user(request: Request, p: Platform = Depends(platform)) -> str:
    user = await p.auth.user_for(token_from(request))
    if user is None:
        raise HTTPException(401, "not authenticated")
    return user


async def audit(p: Platform, user: str | None, action: str, details: dict | None = None,
                ok: bool = True) -> None:
    await p.db.aexecute(
        "INSERT INTO audit_log(ts, username, action, details, ok) VALUES (?,?,?,?,?)",
        (time.time(), user, action, json.dumps(details or {}, default=str), 1 if ok else 0))


async def call_driver(p: Platform, user: str, action: str, coro, details: dict | None = None,
                      audited: bool = True):
    """Run a driver coroutine, translating errors and writing the audit log."""
    try:
        result = await coro
    except NotSupported:
        raise HTTPException(501, f"{action} is not supported by the {p.driver.name} driver")
    except DriverError as exc:
        if audited:
            await audit(p, user, action, {**(details or {}), "error": str(exc)}, ok=False)
        raise HTTPException(502, str(exc))
    if audited:
        await audit(p, user, action, details)
    return result


async def read_driver(p: Platform, coro):
    try:
        return await coro
    except NotSupported:
        raise HTTPException(501, f"not supported by the {p.driver.name} driver")
    except DriverError as exc:
        raise HTTPException(502, str(exc))
    except (OSError, TimeoutError) as exc:
        raise HTTPException(502, f"router unreachable: {exc}")


def traffic_query(
    range: str | None = Q("1h", pattern=r"^(5m|15m|1h|6h|24h|7d|30d)$"),
    start: float | None = None, end: float | None = None,
    local_ip: str | None = None, remote_ip: str | None = None, ip: str | None = None,
    app: str | None = None,
    direction: str | None = Q(None, pattern=r"^(upload|download|lan|transit)$"),
    proto: int | None = Q(None, ge=0, le=255), port: int | None = Q(None, ge=0, le=65535),
    source: str | None = None, exclude_lan: bool = False,
) -> Query:
    if start is not None and end is not None and end <= start:
        raise HTTPException(422, "end must be after start")
    return Query.from_params(range_=range, start=start, end=end, local_ip=local_ip,
                             remote_ip=remote_ip, ip=ip, app=app, direction=direction,
                             proto=proto, port=port, source=source, exclude_lan=exclude_lan)
