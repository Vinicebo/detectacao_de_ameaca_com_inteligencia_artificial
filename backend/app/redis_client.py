"""Shared Redis connection pool.

Um pool por processo, usado por três coisas distintas: janelas deslizantes por IP
(estágio 2), rate limiting da API e pub/sub de alertas.
"""

from __future__ import annotations

import redis.asyncio as redis

from app.config import Settings

_client: redis.Redis | None = None


def init_redis(settings: Settings) -> redis.Redis:
    """Cria o cliente do processo. Idempotente."""
    global _client
    if _client is None:
        _client = redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            health_check_interval=30,
            socket_keepalive=True,
        )
    return _client


def get_redis() -> redis.Redis:
    if _client is None:
        raise RuntimeError("init_redis() precisa ser chamado antes de get_redis()")
    return _client


async def close_redis() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
