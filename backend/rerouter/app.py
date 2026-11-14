"""FastAPI application factory."""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import (auth_routes, http_routes, platform_routes, router_routes,
                  traffic_routes)
from .config import Config, load_config
from .core import Platform
from .drivers import RouterDriver

STATIC_DIR = Path(__file__).parent / "static"


def create_app(cfg: Config | None = None, driver: RouterDriver | None = None,
               start_background: bool = True) -> FastAPI:
    cfg = cfg or load_config()

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        platform = Platform(cfg, driver)
        app.state.platform = platform
        if start_background:
            await platform.start()
        else:
            platform.auth.ensure_admin(cfg.admin_password)
        try:
            yield
        finally:
            await platform.stop()

    app = FastAPI(title="rerouter", version="0.1.0", lifespan=lifespan,
                  docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        return response

    for module in (auth_routes, traffic_routes, http_routes, router_routes, platform_routes):
        app.include_router(module.router)

    @app.get("/api/health", include_in_schema=False)
    async def health():
        return {"ok": True}

    if (STATIC_DIR / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        async def spa(path: str):
            if path.startswith("api/"):
                return JSONResponse({"detail": "Not Found"}, status_code=404)
            candidate = (STATIC_DIR / path).resolve()
            if path and candidate.is_file() and STATIC_DIR.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(STATIC_DIR / "index.html")

    return app


def get_app() -> FastAPI:  # for `uvicorn rerouter.app:get_app --factory`
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return create_app()
