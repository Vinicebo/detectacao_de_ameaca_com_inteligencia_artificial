"""Health check. Sem autenticação — é o que o Docker usa como healthcheck."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app.config import get_settings
from app.db.session import session_scope
from app.redis_client import get_redis

router = APIRouter(tags=["health"])


async def _check_postgres() -> dict[str, Any]:
    try:
        async with session_scope() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "up"}
    except Exception as exc:
        return {"status": "down", "error": type(exc).__name__}


async def _check_redis() -> dict[str, Any]:
    try:
        await get_redis().ping()
        return {"status": "up"}
    except Exception as exc:
        return {"status": "down", "error": type(exc).__name__}


def _check_models() -> dict[str, Any]:
    """Ausência de modelo não é falha: o sistema roda em modo somente-regras."""
    settings = get_settings()
    expected = ["autoencoder.onnx", "random_forest.onnx", "isolation_forest.onnx", "scaler.json"]
    present = [name for name in expected if (settings.model_dir / name).is_file()]
    return {
        "status": "up" if len(present) == len(expected) else "degraded",
        "mode": "ensemble" if len(present) == len(expected) else "rules_only",
        "artifacts": f"{len(present)}/{len(expected)}",
    }


@router.get("/health", summary="Health check")
async def health(response: Response) -> dict[str, Any]:
    checks = {
        "postgres": await _check_postgres(),
        "redis": await _check_redis(),
        "models": _check_models(),
    }
    # Modelos degradados não derrubam o healthcheck — o motor de regras sozinho
    # ainda detecta ataques. Postgres ou Redis fora, sim.
    healthy = all(checks[name]["status"] == "up" for name in ("postgres", "redis"))
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "healthy" if healthy else "unhealthy",
        "service": get_settings().service_name,
        "checks": checks,
    }
