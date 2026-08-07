"""Threat event listing, detail and human review."""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ApiKeyDep, RateLimitDep
from app.api.schemas import ReviewRequest, ThreatEventOut, ThreatEventSummary, ThreatPage
from app.db.models import Severity, ThreatEvent
from app.db.session import get_session
from app.logging_setup import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/threats", tags=["threats"], dependencies=[RateLimitDep])

SessionDep = Annotated[AsyncSession, Depends(get_session)]

MAX_PAGE_SIZE = 200


def encode_cursor(ts: datetime, event_id: int) -> str:
    return base64.urlsafe_b64encode(f"{ts.isoformat()}|{event_id}".encode()).decode()


def decode_cursor(cursor: str) -> tuple[datetime, int]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        ts_part, id_part = raw.rsplit("|", 1)
        return datetime.fromisoformat(ts_part), int(id_part)
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="cursor inválido"
        ) from exc


@router.get("", response_model=ThreatPage, summary="Lista eventos com filtros")
async def list_threats(
    session: SessionDep,
    _key: ApiKeyDep,
    severity: Annotated[list[Severity] | None, Query()] = None,
    category: Annotated[str | None, Query(description="Filtra por categoria de regra")] = None,
    remote_addr: Annotated[str | None, Query()] = None,
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    reviewed: Annotated[bool | None, Query()] = None,
    min_score: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
    cursor: Annotated[str | None, Query(description="Cursor da página anterior")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
) -> ThreatPage:
    """Eventos mais recentes primeiro, paginados por cursor.

    Cursor e não OFFSET: com escrita contínua na tabela, OFFSET pula ou repete
    eventos quando algo é inserido entre duas requisições, além de ficar cada vez
    mais caro conforme a página avança.
    """
    query = select(ThreatEvent)

    if severity:
        query = query.where(ThreatEvent.severity.in_(severity))
    if category:
        # `@>` usa o índice GIN em categories.
        query = query.where(ThreatEvent.categories.contains([category]))
    if remote_addr:
        query = query.where(ThreatEvent.remote_addr == remote_addr)
    if since:
        query = query.where(ThreatEvent.ts >= since)
    if until:
        query = query.where(ThreatEvent.ts <= until)
    if reviewed is not None:
        query = query.where(ThreatEvent.reviewed.is_(reviewed))
    if min_score is not None:
        query = query.where(ThreatEvent.threat_score >= min_score)

    if cursor:
        cursor_ts, cursor_id = decode_cursor(cursor)
        # Comparação de tupla: dois eventos podem ter o mesmo `ts` (o log do nginx
        # tem resolução de segundo), e o id desempata sem pular nem repetir.
        query = query.where(
            or_(
                ThreatEvent.ts < cursor_ts,
                and_(ThreatEvent.ts == cursor_ts, ThreatEvent.id < cursor_id),
            )
        )

    query = query.order_by(ThreatEvent.ts.desc(), ThreatEvent.id.desc()).limit(limit + 1)
    rows = list((await session.execute(query)).scalars().all())

    # Buscamos um a mais para saber se existe próxima página sem um COUNT extra.
    has_more = len(rows) > limit
    rows = rows[:limit]

    return ThreatPage(
        items=[ThreatEventSummary.model_validate(row) for row in rows],
        next_cursor=encode_cursor(rows[-1].ts, rows[-1].id) if rows and has_more else None,
        has_more=has_more,
    )


@router.get("/{event_id}", response_model=ThreatEventOut, summary="Detalhe do evento")
async def get_threat(
    session: SessionDep,
    _key: ApiKeyDep,
    event_id: Annotated[int, Path(ge=1)],
) -> ThreatEvent:
    event = await session.get(ThreatEvent, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evento não encontrado")
    return event


@router.patch(
    "/{event_id}/review",
    response_model=ThreatEventOut,
    summary="Marca o evento como verdadeiro ou falso positivo",
)
async def review_threat(
    session: SessionDep,
    _key: ApiKeyDep,
    event_id: Annotated[int, Path(ge=1)],
    body: ReviewRequest,
) -> ThreatEvent:
    """Registra o julgamento humano sobre o evento.

    Este endpoint não está no material de referência, mas sem ele o retreino a
    partir de dados reais não teria rótulo nenhum — só as próprias heurísticas de
    escore do sistema, o que faria o modelo aprender a concordar consigo mesmo em
    vez de melhorar.
    """
    event = await session.get(ThreatEvent, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evento não encontrado")

    event.reviewed = True
    event.review_label = body.is_attack
    event.reviewed_at = datetime.now(UTC)

    log.info("threat.reviewed", event_id=event_id, is_attack=body.is_attack)
    return event


@router.get("/{event_id}/similar", response_model=list[ThreatEventSummary])
async def similar_threats(
    session: SessionDep,
    _key: ApiKeyDep,
    event_id: Annotated[int, Path(ge=1)],
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> list[ThreatEventSummary]:
    """Outros eventos do mesmo IP ou da mesma categoria.

    Um alerta isolado quase nunca é decidível. O que responde "isto é real?" é o
    padrão em volta: o mesmo IP tentando outras coisas, a mesma categoria vindo de
    outras origens.
    """
    event = await session.get(ThreatEvent, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evento não encontrado")

    conditions = [ThreatEvent.remote_addr == event.remote_addr]
    if event.categories:
        conditions.append(ThreatEvent.categories.overlap(event.categories))

    rows = (
        (
            await session.execute(
                select(ThreatEvent)
                .where(or_(*conditions), ThreatEvent.id != event_id)
                .order_by(ThreatEvent.ts.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )

    return [ThreatEventSummary.model_validate(row) for row in rows]


__all__ = ["decode_cursor", "encode_cursor", "router"]
