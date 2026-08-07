"""Aggregate statistics and pipeline health."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import orjson
from fastapi import APIRouter, Depends, Query
from sqlalchemy import Integer, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ApiKeyDep, RateLimitDep
from app.api.schemas import (
    CategoryCount,
    SeverityCount,
    StatsOut,
    TimeBucket,
)
from app.db.models import Severity, ThreatEvent
from app.db.session import get_session
from app.logging_setup import get_logger
from app.redis_client import get_redis

log = get_logger(__name__)

router = APIRouter(tags=["stats"], dependencies=[RateLimitDep])

SessionDep = Annotated[AsyncSession, Depends(get_session)]


@router.get("/stats", response_model=StatsOut, summary="Estatísticas agregadas")
async def stats(
    session: SessionDep,
    _key: ApiKeyDep,
    hours: Annotated[int, Query(ge=1, le=720, description="Janela da linha do tempo")] = 24,
) -> StatsOut:
    now = datetime.now(UTC)
    window_start = now - timedelta(hours=hours)
    day_start = now - timedelta(hours=24)

    total = (await session.execute(select(func.count()).select_from(ThreatEvent))).scalar_one()

    last_24h = (
        await session.execute(
            select(func.count()).select_from(ThreatEvent).where(ThreatEvent.ts >= day_start)
        )
    ).scalar_one()

    unique_attackers = (
        await session.execute(
            select(func.count(func.distinct(ThreatEvent.remote_addr))).where(
                ThreatEvent.ts >= day_start,
                ThreatEvent.severity.in_([Severity.HIGH, Severity.MEDIUM]),
            )
        )
    ).scalar_one()

    severity_rows = (
        await session.execute(
            select(ThreatEvent.severity, func.count())
            .where(ThreatEvent.ts >= window_start)
            .group_by(ThreatEvent.severity)
        )
    ).all()

    # unnest expande o array de categorias: um evento com SQLi e traversal conta
    # nas duas, que é o comportamento certo para "quantos ataques de cada tipo".
    category_column = func.unnest(ThreatEvent.categories).label("category")
    category_rows = (
        await session.execute(
            select(category_column, func.count())
            .where(ThreatEvent.ts >= window_start)
            .group_by(category_column)
            .order_by(func.count().desc())
            .limit(15)
        )
    ).all()

    # Balde de hora fechada, para o gráfico não tremer conforme o relógio anda.
    bucket = func.date_trunc("hour", ThreatEvent.ts).label("bucket")
    timeline_rows = (
        await session.execute(
            select(
                bucket,
                func.count().label("total"),
                func.sum(cast(ThreatEvent.severity == Severity.HIGH, Integer)).label("high"),
                func.sum(cast(ThreatEvent.severity == Severity.MEDIUM, Integer)).label("medium"),
                func.sum(cast(ThreatEvent.severity == Severity.LOW, Integer)).label("low"),
            )
            .where(ThreatEvent.ts >= window_start)
            .group_by(bucket)
            .order_by(bucket)
        )
    ).all()

    attacker_rows = (
        await session.execute(
            select(
                ThreatEvent.remote_addr,
                func.count().label("events"),
                func.max(ThreatEvent.threat_score).label("max_score"),
                func.max(ThreatEvent.country).label("country"),
            )
            .where(
                ThreatEvent.ts >= day_start,
                ThreatEvent.severity.in_([Severity.HIGH, Severity.MEDIUM]),
            )
            .group_by(ThreatEvent.remote_addr)
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()

    pending = (
        await session.execute(
            select(func.count())
            .select_from(ThreatEvent)
            .where(
                ThreatEvent.reviewed.is_(False),
                ThreatEvent.severity.in_([Severity.HIGH, Severity.MEDIUM]),
            )
        )
    ).scalar_one()

    return StatsOut(
        total_events=total,
        events_last_24h=last_24h,
        unique_attackers_24h=unique_attackers,
        by_severity=[SeverityCount(severity=s, count=c) for s, c in severity_rows],
        by_category=[CategoryCount(category=c, count=n) for c, n in category_rows],
        timeline=[
            TimeBucket(
                bucket=row.bucket,
                total=row.total,
                high=row.high or 0,
                medium=row.medium or 0,
                low=row.low or 0,
            )
            for row in timeline_rows
        ],
        top_attackers=[
            {
                "remote_addr": row.remote_addr,
                "events": row.events,
                "max_score": round(float(row.max_score), 3),
                "country": row.country,
            }
            for row in attacker_rows
        ],
        pending_review=pending,
    )


@router.get("/stats/pipeline", summary="Saúde do pipeline de ingestão")
async def pipeline_health(_key: ApiKeyDep) -> dict[str, Any]:
    """Contadores publicados pelo processo `detector`.

    Os contadores vivem na memória do `detector`, que é outro processo. Ele
    publica um retrato no Redis a cada poucos segundos e a API lê daqui. A chave
    tem TTL: se o `detector` cair, este endpoint passa a dizer `stale` em vez de
    servir números congelados como se fossem atuais.
    """
    from app.pipeline.orchestrator import PIPELINE_STATS_KEY

    try:
        raw = await get_redis().get(PIPELINE_STATS_KEY)
    except Exception as exc:
        return {"status": "unavailable", "error": type(exc).__name__}

    if raw is None:
        return {
            "status": "stale",
            "message": "o processo detector não publica estatísticas há mais de 30s",
        }

    return {"status": "ok", **orjson.loads(raw)}
