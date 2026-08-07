"""FastAPI application factory for the `api` process.

Este processo só **lê** o banco e assina o canal de alertas do Redis. O pipeline de
ingestão roda no processo `detector` (`app.pipeline.orchestrator`), separado para que
uma rajada de log não concorra com o tráfego HTTP do dashboard.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    routes_health,
    routes_ingest,
    routes_models,
    routes_stats,
    routes_threats,
    ws_alerts,
)
from app.config import Settings, get_settings
from app.db.session import dispose_engine, init_engine
from app.logging_setup import configure_logging, get_logger
from app.redis_client import close_redis, init_redis

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = get_settings()
    configure_logging(settings)
    init_engine(settings)
    init_redis(settings)
    log.info("api.startup", environment=settings.environment)
    try:
        yield
    finally:
        await close_redis()
        await dispose_engine()
        log.info("api.shutdown")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Threat Detector API",
        version="0.1.0",
        description="Motor de detecção de ameaças em logs de acesso do nginx.",
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_prod else None,
        redoc_url=None,
    )

    if not settings.is_prod:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:5173", "http://localhost:46969"],
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.include_router(routes_health.router)
    app.include_router(routes_stats.router)
    app.include_router(routes_threats.router)
    app.include_router(routes_models.router)
    app.include_router(routes_ingest.router)
    app.include_router(ws_alerts.router)
    return app


app = create_app()
