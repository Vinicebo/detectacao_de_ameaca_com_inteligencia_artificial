"""Model version bookkeeping in Postgres, plus optional MLflow tracking.

Registramos **toda** tentativa de treino, aprovada ou não. Guardar só as
aprovadas deixaria a pergunta "por que a versão ativa ainda é a de três semanas
atrás?" sem resposta — e essa é justamente a pergunta que se faz quando a
detecção parece estar piorando.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select, update

from app.config import Settings, get_settings
from app.db.models import ModelVersion, TrainingSource
from app.db.session import session_scope
from app.logging_setup import get_logger
from app.ml.validate import ValidationResult

log = get_logger(__name__)


async def register_version(
    version: str,
    result: ValidationResult,
    paths: dict[str, str],
    source: str,
    sample_count: int,
) -> None:
    """Grava a tentativa de treino e promove se tiver passado nos portões."""
    async with session_scope() as session:
        if result.passed:
            # Desativa a anterior antes de inserir a nova: o índice único parcial
            # em `is_active` recusaria duas ativas ao mesmo tempo — que é o ponto,
            # porque com duas a inferência escolheria uma por sorte.
            await session.execute(
                update(ModelVersion).where(ModelVersion.is_active.is_(True)).values(is_active=False)
            )

        session.add(
            ModelVersion(
                version=version,
                is_active=result.passed,
                promoted=result.passed,
                rejection_reason=result.reason,
                metrics={k: v for k, v in result.metrics.items() if isinstance(v, int | float)},
                artifact_paths=paths,
                training_source=TrainingSource(source),
                sample_count=sample_count,
            )
        )

    log.info(
        "registry.recorded",
        version=version,
        promoted=result.passed,
        source=source,
        reason=result.reason,
    )


async def get_active_version() -> ModelVersion | None:
    async with session_scope() as session:
        return (
            await session.execute(select(ModelVersion).where(ModelVersion.is_active.is_(True)))
        ).scalar_one_or_none()


async def list_versions(limit: int = 20) -> list[ModelVersion]:
    async with session_scope() as session:
        rows = await session.execute(
            select(ModelVersion).order_by(ModelVersion.created_at.desc()).limit(limit)
        )
        return list(rows.scalars().all())


def log_to_mlflow(
    version: str,
    result: ValidationResult,
    source: str,
    sample_count: int,
    settings: Settings | None = None,
) -> None:
    """Registra o experimento no MLflow.

    Best-effort de propósito: rastreamento de experimento é conveniência de
    análise, e um MLflow indisponível não pode impedir que um modelo válido entre
    em produção.
    """
    settings = settings or get_settings()
    try:
        import mlflow

        mlflow.set_tracking_uri(settings.mlflow_tracking_uri)
        mlflow.set_experiment("threat-detector")

        with mlflow.start_run(run_name=version):
            mlflow.log_params(
                {
                    "source": source,
                    "sample_count": sample_count,
                    "weight_autoencoder": settings.weight_autoencoder,
                    "weight_random_forest": settings.weight_random_forest,
                    "weight_isolation_forest": settings.weight_isolation_forest,
                    "min_f1": settings.min_f1,
                    "min_pr_auc": settings.min_pr_auc,
                }
            )
            numeric: dict[str, Any] = {
                k: float(v) for k, v in result.metrics.items() if isinstance(v, int | float)
            }
            mlflow.log_metrics(numeric)
            mlflow.set_tag("promoted", str(result.passed))
            if result.reason:
                mlflow.set_tag("rejection_reason", result.reason)
    except Exception as exc:
        log.warning("mlflow.unavailable", error=str(exc))
