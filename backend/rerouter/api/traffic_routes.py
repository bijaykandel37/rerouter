from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Query as Q
from fastapi.responses import StreamingResponse

from .. import analytics
from ..analytics import Query
from ..core import Platform
from .deps import audit, current_user, platform, traffic_query

router = APIRouter(prefix="/api/traffic", tags=["traffic"], dependencies=[Depends(current_user)])


async def _run(p: Platform, fn, *args, **kwargs):
    try:
        return await p.db.run(lambda: fn(p.db, *args, **kwargs))
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/summary")
async def summary(q: Query = Depends(traffic_query), p: Platform = Depends(platform)):
    return await _run(p, analytics.summary, q)


@router.get("/timeseries")
async def timeseries(q: Query = Depends(traffic_query),
                     group_by: str = "direction",
                     metric: str = Q("bytes", pattern="^(bytes|packets|flows)$"),
                     top: int = Q(7, ge=1, le=7), bucket: int | None = Q(None, ge=10),
                     p: Platform = Depends(platform)):
    return await _run(p, analytics.timeseries, q, group_by=group_by, metric=metric, top=top,
                      bucket=bucket)


@router.get("/top")
async def top(q: Query = Depends(traffic_query), by: str = "remote_ip",
              limit: int = Q(20, ge=1, le=500), p: Platform = Depends(platform)):
    return await _run(p, analytics.top, q, by=by, limit=limit)


@router.get("/sankey")
async def sankey(q: Query = Depends(traffic_query), p: Platform = Depends(platform)):
    return await _run(p, analytics.sankey, q)


@router.get("/graph")
async def graph(q: Query = Depends(traffic_query), limit: int = Q(80, ge=5, le=500),
                p: Platform = Depends(platform)):
    return await _run(p, analytics.graph, q, limit=limit)


@router.get("/heatmap")
async def heatmap(q: Query = Depends(traffic_query), p: Platform = Depends(platform)):
    return await _run(p, analytics.heatmap, q)


@router.get("/distribution")
async def distribution(q: Query = Depends(traffic_query), p: Platform = Depends(platform)):
    return await _run(p, analytics.distribution, q)


@router.get("/flows")
async def flows(q: Query = Depends(traffic_query), limit: int = Q(100, ge=1, le=1000),
                offset: int = Q(0, ge=0), sort: str = "ts_end", desc: bool = True,
                p: Platform = Depends(platform)):
    return await _run(p, analytics.flows, q, limit=limit, offset=offset, sort=sort, desc=desc)


@router.get("/apps")
async def apps(p: Platform = Depends(platform)):
    rows = await p.db.aquery("SELECT DISTINCT app FROM flows WHERE ts_end >= ? ORDER BY app",
                             (time.time() - 7 * 86400,))
    return [r["app"] for r in rows]


@router.get("/export")
async def export(q: Query = Depends(traffic_query), format: str = Q("csv", pattern="^(csv|jsonl)$"),
                 p: Platform = Depends(platform), user: str = Depends(current_user)):
    await audit(p, user, "export_flows", {"start": q.start, "end": q.end, "format": format})
    gen = analytics.export_rows(p.db, q, format)

    async def stream():
        while True:
            chunk = await p.db.run(next, gen, None)
            if chunk is None:
                break
            yield chunk

    stamp = time.strftime("%Y%m%d-%H%M%S")
    media = "text/csv" if format == "csv" else "application/x-ndjson"
    return StreamingResponse(stream(), media_type=media, headers={
        "Content-Disposition": f'attachment; filename="flows-{stamp}.{format}"'})
