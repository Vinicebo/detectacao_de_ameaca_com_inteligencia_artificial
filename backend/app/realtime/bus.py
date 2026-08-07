"""Redis pub/sub bridge between the detector and the API's WebSocket clients.

Os dois rodam em processos separados, então uma fila em memória não serve. O
Redis pub/sub resolve com a semântica certa para este caso: **fire-and-forget**.
Alerta é dado vivo — se ninguém está com o dashboard aberto, não há para quem
entregar, e guardar para depois só encheria memória. A cópia durável do evento
está no Postgres; o canal é só o caminho rápido.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from typing import Any

import orjson
import redis.asyncio as redis

from app.logging_setup import get_logger

log = get_logger(__name__)

# Buffer de alertas recentes, para um cliente que acabou de conectar receber
# contexto em vez de uma tela vazia até o próximo ataque.
SNAPSHOT_KEY = "threats:recent"
SNAPSHOT_SIZE = 50


class AlertBus:
    def __init__(self, client: redis.Redis, channel: str) -> None:
        self._redis = client
        self._channel = channel
        self.published = 0

    async def publish(self, payload: dict[str, Any]) -> None:
        """Publica um alerta e o adiciona ao buffer recente.

        Nunca levanta exceção: falha em publicar não pode impedir a persistência
        do evento, que é a parte que não se pode perder.
        """
        try:
            message = orjson.dumps(payload, default=str)
            pipe = self._redis.pipeline()
            pipe.publish(self._channel, message)
            pipe.lpush(SNAPSHOT_KEY, message)
            pipe.ltrim(SNAPSHOT_KEY, 0, SNAPSHOT_SIZE - 1)
            pipe.expire(SNAPSHOT_KEY, 3600)
            await pipe.execute()
            self.published += 1
        except Exception as exc:
            log.warning("bus.publish_failed", error=type(exc).__name__)

    async def recent(self, limit: int = SNAPSHOT_SIZE) -> list[dict[str, Any]]:
        """Alertas recentes, mais novos primeiro."""
        try:
            raw = await self._redis.lrange(SNAPSHOT_KEY, 0, limit - 1)
        except Exception as exc:
            log.warning("bus.snapshot_failed", error=type(exc).__name__)
            return []

        alerts: list[dict[str, Any]] = []
        for item in raw:
            try:
                alerts.append(orjson.loads(item))
            except orjson.JSONDecodeError:
                continue
        return alerts

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        """Itera os alertas do canal até o consumidor desistir.

        O ``finally`` é obrigatório: sem ele, cada aba de dashboard fechada
        deixaria uma subscrição pendurada no Redis.
        """
        pubsub = self._redis.pubsub()
        try:
            await pubsub.subscribe(self._channel)
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                try:
                    yield orjson.loads(message["data"])
                except orjson.JSONDecodeError:
                    log.warning("bus.malformed_message")
        except asyncio.CancelledError:
            raise
        finally:
            # Conexão já pode ter caído; não há o que salvar aqui.
            with contextlib.suppress(Exception):
                await pubsub.unsubscribe(self._channel)
                # redis-py não anota `aclose`; o ignore é da biblioteca, não nosso.
                await pubsub.aclose()  # type: ignore[no-untyped-call]
