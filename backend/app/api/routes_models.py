"""Model status and retraining."""

from __future__ import annotations

import contextlib
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks

from app.api.deps import ApiKeyDep, RateLimitDep, SettingsDep
from app.api.schemas import (
    ModelStatusOut,
    ModelVersionOut,
    RetrainRequest,
    RetrainResponse,
)
from app.cli import REQUIRED_ARTIFACTS
from app.config import Settings
from app.logging_setup import get_logger
from app.ml.registry import get_active_version, list_versions
from app.redis_client import get_redis

log = get_logger(__name__)

router = APIRouter(prefix="/models", tags=["models"], dependencies=[RateLimitDep])

# Trava distribuída: o treino é CPU-bound e consome memória. Dois retreinos
# simultâneos — dois cliques no botão, ou duas réplicas da API — competiriam pela
# CPU e ainda poderiam escrever no mesmo arquivo ONNX ao mesmo tempo.
RETRAIN_LOCK_KEY = "models:retraining"
RETRAIN_LOCK_TTL = 3600


@router.get("/status", response_model=ModelStatusOut, summary="Estado dos modelos")
async def model_status(settings: SettingsDep, _key: ApiKeyDep) -> ModelStatusOut:
    from app.detection.engine import load_rules

    artifacts_present = all((settings.model_dir / name).is_file() for name in REQUIRED_ARTIFACTS)
    active = await get_active_version()
    history = await list_versions(limit=20)

    return ModelStatusOut(
        detection_mode="ensemble" if artifacts_present else "rules_only",
        active_version=ModelVersionOut.model_validate(active) if active else None,
        history=[ModelVersionOut.model_validate(v) for v in history],
        artifacts_present=artifacts_present,
        rule_count=len(load_rules()),
        ensemble_weights={
            "autoencoder": settings.weight_autoencoder,
            "random_forest": settings.weight_random_forest,
            "isolation_forest": settings.weight_isolation_forest,
        },
        thresholds={
            "high": settings.severity_high_threshold,
            "medium": settings.severity_medium_threshold,
            "min_f1": settings.min_f1,
            "min_pr_auc": settings.min_pr_auc,
        },
    )


async def _run_retrain(job_id: str, settings: Settings, use_real_data: bool) -> None:
    """Executa o retreino e libera a trava, aconteça o que acontecer."""
    from app.ml.retrain import retrain

    try:
        version = await retrain(settings, use_real_data=use_real_data)
        log.info("retrain.job_finished", job_id=job_id, version=version)
    except Exception as exc:
        log.error("retrain.job_failed", job_id=job_id, error=str(exc))
    finally:
        # Sem este release, uma falha de treino bloquearia novas tentativas até o
        # TTL de uma hora expirar. Redis fora do ar já será visível em /health.
        with contextlib.suppress(Exception):
            await get_redis().delete(RETRAIN_LOCK_KEY)


@router.post("/retrain", response_model=RetrainResponse, summary="Dispara o retreino")
async def retrain_models(
    settings: SettingsDep,
    _key: ApiKeyDep,
    background: BackgroundTasks,
    body: RetrainRequest | None = None,
) -> RetrainResponse:
    """Retreina a partir dos eventos armazenados, em segundo plano.

    Responde na hora com um id de job; o progresso aparece em `/models/status`
    quando uma versão nova é registrada. Treinar de forma síncrona seguraria a
    requisição por minutos e estouraria qualquer timeout de proxy.
    """
    job_id = uuid.uuid4().hex[:12]
    request = body or RetrainRequest()

    try:
        # SET NX: só pega a trava se ninguém a tiver. Atômico no Redis.
        acquired = await get_redis().set(RETRAIN_LOCK_KEY, job_id, nx=True, ex=RETRAIN_LOCK_TTL)
    except Exception as exc:
        log.warning("retrain.lock_unavailable", error=type(exc).__name__)
        acquired = True  # Redis fora do ar não deve impedir um retreino manual.

    if not acquired:
        return RetrainResponse(
            job_id="",
            status="already_running",
            message="já existe um retreino em andamento",
        )

    background.add_task(_run_retrain, job_id, settings, request.use_real_data)
    log.info("retrain.job_started", job_id=job_id, use_real_data=request.use_real_data)

    return RetrainResponse(
        job_id=job_id,
        status="started",
        message="retreino iniciado; acompanhe em GET /models/status",
    )


@router.get("/features", summary="Contrato de features usado pelos modelos")
async def feature_contract(_key: ApiKeyDep) -> dict[str, Any]:
    """As 35 dimensões, na ordem.

    Exposto porque o dashboard mostra o vetor de features no detalhe do evento, e
    sem os nomes seriam 35 números sem significado.
    """
    from app.ml.features_spec import FEATURE_COUNT, FEATURE_NAMES

    return {"count": FEATURE_COUNT, "names": list(FEATURE_NAMES)}
