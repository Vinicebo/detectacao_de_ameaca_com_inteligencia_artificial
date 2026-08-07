"""Lazily-built pipeline instance for the API process.

O `POST /ingest/batch` precisa dos mesmos estágios que o processo `detector`, mas
a API não deve carregar modelo ONNX no arranque só por causa de um endpoint que
talvez nunca seja chamado — são centenas de milissegundos e dezenas de MB.

Então o pipeline é construído na primeira ingestão e reaproveitado. Só os
estágios: nenhuma tarefa de leitura de arquivo é iniciada aqui.
"""

from __future__ import annotations

import asyncio

from fastapi import FastAPI

from app.config import get_settings
from app.logging_setup import get_logger
from app.pipeline.orchestrator import Pipeline

log = get_logger(__name__)

_lock = asyncio.Lock()


async def get_ingest_pipeline(app: FastAPI) -> Pipeline:
    """Devolve o pipeline de ingestão da aplicação, criando-o na primeira chamada."""
    existing = getattr(app.state, "ingest_pipeline", None)
    if existing is not None:
        return existing  # type: ignore[no-any-return]

    # A trava evita que duas requisições concorrentes carreguem os modelos duas
    # vezes na primeira chamada.
    async with _lock:
        existing = getattr(app.state, "ingest_pipeline", None)
        if existing is not None:
            return existing  # type: ignore[no-any-return]

        pipeline = Pipeline(get_settings())
        app.state.ingest_pipeline = pipeline
        log.info("ingest.pipeline_ready", mode=pipeline.detector.mode)
        return pipeline


async def reload_ingest_models(app: FastAPI) -> bool:
    """Recarrega os modelos do pipeline de ingestão após um retreino."""
    pipeline = getattr(app.state, "ingest_pipeline", None)
    if pipeline is None:
        return False
    return pipeline.detector.reload_models()  # type: ignore[no-any-return]
