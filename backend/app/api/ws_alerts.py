"""Real-time alert stream.

**Autenticação.** O feed exige a API key num frame enviado logo após o handshake,
com prazo de 5 segundos. A alternativa comum — chave na query string
(``/ws/alerts?api_key=...``) — vaza a credencial para o log de acesso do proxy,
para o histórico do navegador e para o cabeçalho Referer. Um feed de alertas de
segurança aberto também entrega reconhecimento de graça: quem ataca vê em tempo
real o que foi detectado e ajusta a evasão. O custo é uma linha a mais no cliente.

**Entrega.** Alerta é dado vivo. Se o cliente não consegue acompanhar, descartamos
para ele em vez de acumular — o histórico completo está no Postgres, acessível
por ``GET /threats``.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
from typing import Any

import orjson
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from app.config import get_settings
from app.logging_setup import get_logger
from app.realtime.bus import AlertBus
from app.redis_client import get_redis

log = get_logger(__name__)

router = APIRouter(tags=["realtime"])

AUTH_TIMEOUT_SECONDS = 5.0
HEARTBEAT_SECONDS = 30.0
# Fecha a conexão em vez de acumular: um cliente que não drena não pode virar
# pressão de memória no servidor.
CLIENT_BUFFER_LIMIT = 200

# Códigos de fechamento na faixa de aplicação (4000+).
CLOSE_AUTH_TIMEOUT = 4001
CLOSE_AUTH_FAILED = 4003
CLOSE_SLOW_CLIENT = 4008


async def _send(websocket: WebSocket, message_type: str, data: Any = None) -> None:
    await websocket.send_bytes(orjson.dumps({"type": message_type, "data": data}, default=str))


async def _authenticate(websocket: WebSocket) -> bool:
    """Espera o frame de autenticação. ``{"type": "auth", "api_key": "..."}``."""
    settings = get_settings()
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=AUTH_TIMEOUT_SECONDS)
    except TimeoutError:
        await websocket.close(code=CLOSE_AUTH_TIMEOUT, reason="tempo de autenticação esgotado")
        return False
    except (WebSocketDisconnect, RuntimeError):
        return False

    try:
        message = orjson.loads(raw)
        provided = str(message.get("api_key", ""))
    except (orjson.JSONDecodeError, AttributeError):
        await _send(websocket, "auth_error", {"message": "frame de autenticação inválido"})
        await websocket.close(code=CLOSE_AUTH_FAILED, reason="frame inválido")
        return False

    # compare_digest: `==` vazaria o tamanho do prefixo correto pelo tempo.
    if not hmac.compare_digest(provided, settings.api_key.get_secret_value()):
        await _send(websocket, "auth_error", {"message": "API key inválida"})
        await websocket.close(code=CLOSE_AUTH_FAILED, reason="não autorizado")
        return False

    await _send(websocket, "auth_ok", {"heartbeat_seconds": HEARTBEAT_SECONDS})
    return True


async def _pump_alerts(websocket: WebSocket, bus: AlertBus, queue: asyncio.Queue[Any]) -> None:
    """Lê do Redis e alimenta a fila do cliente."""
    async for alert in bus.subscribe():
        if queue.qsize() >= CLIENT_BUFFER_LIMIT:
            raise SlowClientError
        queue.put_nowait(alert)


class SlowClientError(Exception):
    """Cliente não consegue acompanhar o fluxo."""


@router.websocket("/ws/alerts")
async def alerts_stream(websocket: WebSocket) -> None:
    await websocket.accept()

    if not await _authenticate(websocket):
        return

    bus = AlertBus(get_redis(), get_settings().alerts_channel)

    # Snapshot na conexão: sem ele o dashboard abre vazio até o próximo ataque, o
    # que é indistinguível de "está quebrado".
    with contextlib.suppress(Exception):
        await _send(websocket, "snapshot", await bus.recent())

    queue: asyncio.Queue[Any] = asyncio.Queue()
    pump = asyncio.create_task(_pump_alerts(websocket, bus, queue))

    try:
        while True:
            if pump.done():
                # Propaga SlowClientError ou erro do Redis.
                pump.result()

            try:
                alert = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
            except TimeoutError:
                # Sem o heartbeat, um proxy no meio do caminho mata a conexão
                # ociosa e o dashboard fica mudo sem sinal de erro.
                await _send(websocket, "pong")
                continue

            await _send(websocket, "alert", alert)

    except SlowClientError:
        log.warning("ws.slow_client", buffered=queue.qsize())
        with contextlib.suppress(Exception):
            await websocket.close(code=CLOSE_SLOW_CLIENT, reason="cliente lento")
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        log.warning("ws.error", error=str(exc))
    finally:
        pump.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await pump
        if websocket.client_state == WebSocketState.CONNECTED:
            with contextlib.suppress(Exception):
                await websocket.close()
