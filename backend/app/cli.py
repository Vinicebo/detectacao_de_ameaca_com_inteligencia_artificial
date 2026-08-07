"""Operational helpers invoked by the container entrypoint.

Ficam em Python (e não em shell) porque precisam falar as URLs do SQLAlchemy e do
Redis, e porque assim são testáveis.
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import sys
import time
from urllib.parse import urlparse

from app.config import Settings, get_settings
from app.logging_setup import configure_logging, get_logger

log = get_logger(__name__)

REQUIRED_ARTIFACTS = (
    "autoencoder.onnx",
    "random_forest.onnx",
    "isolation_forest.onnx",
    "scaler.json",
)


def _wait_for_tcp(host: str, port: int, timeout: float, label: str) -> bool:
    deadline = time.monotonic() + timeout
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        try:
            with socket.create_connection((host, port), timeout=3.0):
                log.info("deps.ready", service=label, attempts=attempt)
                return True
        except OSError:
            time.sleep(1.0)
    log.error("deps.timeout", service=label, host=host, port=port, timeout=timeout)
    return False


def wait_for_deps(settings: Settings, timeout: float = 90.0) -> int:
    """Espera Postgres e Redis aceitarem conexão.

    O `depends_on` do compose só garante que o container subiu, não que o serviço
    dentro dele está aceitando conexão.
    """
    db = urlparse(settings.database_url.replace("+asyncpg", ""))
    rd = urlparse(settings.redis_url)

    ok = _wait_for_tcp(db.hostname or "postgres", db.port or 5432, timeout, "postgres")
    ok = _wait_for_tcp(rd.hostname or "redis", rd.port or 6379, timeout, "redis") and ok
    return 0 if ok else 1


async def _migrations_applied(settings: Settings) -> bool:
    from sqlalchemy import text

    from app.db.session import dispose_engine, init_engine, session_scope

    init_engine(settings)
    try:
        async with session_scope() as session:
            result = await session.execute(
                text("SELECT to_regclass('public.threat_events') IS NOT NULL")
            )
            return bool(result.scalar())
    except Exception:
        return False
    finally:
        await dispose_engine()


def wait_for_migrations(settings: Settings, timeout: float = 120.0) -> int:
    """Espera o processo `api` aplicar as migrações.

    O `detector` escreve em ``threat_events`` desde a primeira linha de log; subir
    antes da tabela existir só produziria uma enxurrada de erros.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if asyncio.run(_migrations_applied(settings)):
            log.info("migrations.ready")
            return 0
        time.sleep(2.0)
    log.error("migrations.timeout", timeout=timeout)
    return 1


def models_present(settings: Settings) -> bool:
    return all((settings.model_dir / name).is_file() for name in REQUIRED_ARTIFACTS)


def ensure_models(settings: Settings) -> int:
    """Treina na primeira subida, se o volume de modelos estiver vazio.

    Depois disso os artefatos persistem no volume e o arranque é imediato. Falha de
    treino não é fatal: o motor de regras sozinho já detecta ataques, então o
    serviço sobe em modo degradado em vez de entrar em crash loop.
    """
    if models_present(settings):
        log.info("models.present", model_dir=str(settings.model_dir))
        return 0

    log.info("models.missing", model_dir=str(settings.model_dir), action="training")
    try:
        from app.ml.train import train_from_synthetic

        asyncio.run(train_from_synthetic(settings))
    except Exception as exc:
        log.error("models.training_failed", error=str(exc), mode="rules_only")
        return 0
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli")
    parser.add_argument(
        "command",
        choices=["wait-for-deps", "wait-for-migrations", "ensure-models", "detector"],
    )
    args = parser.parse_args(argv)

    settings = get_settings()
    configure_logging(settings)

    if args.command == "wait-for-deps":
        return wait_for_deps(settings)
    if args.command == "wait-for-migrations":
        return wait_for_migrations(settings)
    if args.command == "ensure-models":
        return ensure_models(settings)
    if args.command == "detector":
        from app.pipeline.orchestrator import run_detector

        asyncio.run(run_detector(settings))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
