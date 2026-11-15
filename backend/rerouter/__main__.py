"""``python -m rerouter`` / ``rerouter`` entry point."""

from __future__ import annotations

import argparse
import logging

import uvicorn

from .app import create_app
from .config import load_config


def main() -> None:
    parser = argparse.ArgumentParser(description="rerouter: router admin & traffic analytics")
    parser.add_argument("--host", help="HTTP bind address (default from config: 0.0.0.0)")
    parser.add_argument("--port", type=int, help="HTTP port (default 8080)")
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config()
    if args.host:
        cfg.http_host = args.host
    if args.port:
        cfg.http_port = args.port
    uvicorn.run(create_app(cfg), host=cfg.http_host, port=cfg.http_port,
                log_level=args.log_level, proxy_headers=True)


if __name__ == "__main__":
    main()
