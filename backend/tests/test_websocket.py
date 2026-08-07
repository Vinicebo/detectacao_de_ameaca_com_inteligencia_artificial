"""WebSocket alert stream tests.

O foco é a autenticação. Este feed carrega, em tempo real, exatamente o que o
sistema detectou — deixá-lo aberto entregaria reconhecimento de graça a quem está
atacando: dá para ver o que foi pego e ajustar a evasão na hora.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Iterator

import orjson
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from app.api.ws_alerts import CLOSE_AUTH_FAILED, CLOSE_AUTH_TIMEOUT
from app.config import get_settings
from app.main import create_app
from app.realtime.bus import AlertBus

pytestmark = pytest.mark.integration


@pytest.fixture
def client() -> Iterator[TestClient]:
    # Como context manager, e não `TestClient(app)` solto: só assim o lifespan roda
    # e o pool do Redis é criado. Sem isso o handler do WebSocket levanta na
    # primeira chamada a get_redis().
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture
def api_key() -> str:
    return get_settings().api_key.get_secret_value()


def auth_frame(key: str) -> str:
    return json.dumps({"type": "auth", "api_key": key})


def test_valid_key_is_accepted(client: TestClient, api_key: str) -> None:
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_text(auth_frame(api_key))
        message = orjson.loads(ws.receive_bytes())
        assert message["type"] == "auth_ok"
        assert "heartbeat_seconds" in message["data"]


def test_wrong_key_is_rejected(client: TestClient) -> None:
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_text(auth_frame("chave-errada"))
        message = orjson.loads(ws.receive_bytes())
        assert message["type"] == "auth_error"


def test_malformed_auth_frame_is_rejected(client: TestClient) -> None:
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_text("isto não é json")
        message = orjson.loads(ws.receive_bytes())
        assert message["type"] == "auth_error"


def test_snapshot_follows_authentication(client: TestClient, api_key: str) -> None:
    """Sem snapshot, o dashboard abre vazio — indistinguível de estar quebrado."""
    with client.websocket_connect("/ws/alerts") as ws:
        ws.send_text(auth_frame(api_key))
        assert orjson.loads(ws.receive_bytes())["type"] == "auth_ok"

        message = orjson.loads(ws.receive_bytes())
        assert message["type"] == "snapshot"
        assert isinstance(message["data"], list)


def test_close_codes_are_in_application_range() -> None:
    """Códigos 4000+ são a faixa reservada à aplicação; o cliente distingue os casos."""
    assert 4000 <= CLOSE_AUTH_TIMEOUT < 5000
    assert 4000 <= CLOSE_AUTH_FAILED < 5000


# ---------------------------------------------------------------------------
# Barramento de alertas
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def bus() -> AsyncIterator[AlertBus]:
    """Barramento com cliente Redis próprio deste teste.

    Deliberadamente **não** usa o singleton de `app.redis_client`: o pytest-asyncio
    cria um event loop por teste, e um pool de conexões criado num loop já fechado
    falha com "Event loop is closed" ao ser reutilizado no seguinte.
    """
    import redis.asyncio as redis

    client = redis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        yield AlertBus(client, "teste:alertas")
    finally:
        await client.aclose()


async def test_published_alert_reaches_a_subscriber(bus: AlertBus) -> None:
    """Publicação e assinatura ligam o processo `detector` ao processo `api`."""
    received: list[dict[str, object]] = []

    async def consume() -> None:
        async for alert in bus.subscribe():
            received.append(alert)
            return

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.3)  # deixa a assinatura se estabelecer

    await bus.publish({"severity": "HIGH", "path": "/teste"})
    await asyncio.wait_for(task, timeout=5.0)

    assert received[0]["severity"] == "HIGH"


async def test_snapshot_is_capped(bus: AlertBus) -> None:
    """O buffer recente é limitado — não pode crescer sem limite no Redis."""
    from app.realtime.bus import SNAPSHOT_KEY, SNAPSHOT_SIZE

    await bus._redis.delete(SNAPSHOT_KEY)

    for index in range(SNAPSHOT_SIZE + 25):
        await bus.publish({"severity": "HIGH", "n": index})

    recent = await bus.recent(limit=1000)
    assert len(recent) == SNAPSHOT_SIZE
    # Mais novo primeiro.
    assert recent[0]["n"] > recent[-1]["n"]

    await bus._redis.delete(SNAPSHOT_KEY)


async def test_publish_failure_does_not_raise() -> None:
    """Falha ao publicar não pode impedir a persistência do evento."""
    import redis.asyncio as redis

    broken = redis.from_url("redis://localhost:1/0", socket_connect_timeout=0.1)
    bus = AlertBus(broken, "teste:alertas")

    await bus.publish({"severity": "HIGH"})  # não deve levantar
    assert bus.published == 0
