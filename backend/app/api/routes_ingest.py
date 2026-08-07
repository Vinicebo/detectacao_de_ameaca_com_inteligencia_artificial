"""Manual log line ingestion.

Existe para três casos: testar a detecção sem montar um nginx, importar um lote de
log histórico, e receber de um agente que não compartilha volume com o detector.

Passa pelos mesmos quatro estágios da ingestão por arquivo — mesmo parser, mesmas
features, mesmo motor. Um caminho paralelo simplificado é como se acaba com um
endpoint que pontua diferente do pipeline principal.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.deps import ApiKeyDep, RateLimitDep
from app.api.schemas import IngestBatchRequest, IngestBatchResponse
from app.logging_setup import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"], dependencies=[RateLimitDep])


@router.post("/batch", response_model=IngestBatchResponse, summary="Ingere linhas de log")
async def ingest_batch(
    request: Request,
    _key: ApiKeyDep,
    body: IngestBatchRequest,
) -> IngestBatchResponse:
    from app.api.pipeline_state import get_ingest_pipeline

    pipeline = await get_ingest_pipeline(request.app)
    result = await pipeline.ingest_lines(body.lines)

    log.info("ingest.batch", **result)
    return IngestBatchResponse(**result)
