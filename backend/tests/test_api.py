"""API tests.

Marcados como `integration`: usam Postgres e Redis de verdade. Mockar o banco
aqui testaria os mocks — a paginação por cursor, o índice GIN de categorias e as
agregações são exatamente o tipo de coisa que só falha contra o banco real.

Cada teste limpa o que criou.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from app.config import get_settings
from app.db.models import Severity, ThreatEvent
from app.db.session import session_scope
from app.main import create_app

pytestmark = pytest.mark.integration

MARKER_IP_PREFIX = "192.0.2."  # TEST-NET-1, reservado para documentação

# Os eventos de teste ficam ancorados dez dias no passado. O banco de dev tem
# tráfego do simulador, sempre com horário "agora"; sem essa separação temporal, um
# teste de paginação que caminha a tabela inteira nunca alcançaria as linhas
# semeadas — foi assim que este teste passou a falhar depois da primeira simulação.
SEED_ANCHOR = datetime.now(UTC) - timedelta(days=10)


@pytest_asyncio.fixture
async def client() -> AsyncIterator[AsyncClient]:
    app = create_app()
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


@pytest.fixture
def auth() -> dict[str, str]:
    return {"X-API-Key": get_settings().api_key.get_secret_value()}


@pytest_asyncio.fixture
async def seeded() -> AsyncIterator[list[int]]:
    """Insere eventos conhecidos e remove ao final."""
    rows = [
        ThreatEvent(
            ts=SEED_ANCHOR - timedelta(minutes=index),
            remote_addr=f"{MARKER_IP_PREFIX}{index + 1}",
            method="GET",
            path=f"/teste/{index}",
            query="id=1" if index % 2 else None,
            protocol="HTTP/1.1",
            status=200 if index % 2 else 404,
            bytes_sent=100 * index,
            referer=None,
            user_agent="pytest",
            country="BR",
            rule_score=0.9 if index < 3 else 0.1,
            ml_score=0.8 if index < 3 else 0.1,
            threat_score=0.95 if index < 3 else 0.2,
            severity=Severity.HIGH if index < 3 else Severity.LOW,
            categories=["sqli"] if index < 2 else ["xss"] if index < 3 else [],
            matched_rules=[{"rule_id": "SQLI-001", "category": "sqli"}] if index < 2 else [],
            features=[0.5] * 35,
            model_version="teste",
        )
        for index in range(8)
    ]

    async with session_scope() as session:
        session.add_all(rows)
        await session.flush()
        ids = [row.id for row in rows]

    yield ids

    async with session_scope() as session:
        await session.execute(
            delete(ThreatEvent).where(ThreatEvent.remote_addr.like(f"{MARKER_IP_PREFIX}%"))
        )


# ---------------------------------------------------------------------------
# Autenticação
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/stats", "/threats", "/models/status", "/stats/pipeline"])
async def test_endpoints_require_api_key(client: AsyncClient, path: str) -> None:
    assert (await client.get(path)).status_code == 401


async def test_wrong_api_key_rejected(client: AsyncClient) -> None:
    response = await client.get("/threats", headers={"X-API-Key": "chave-errada"})
    assert response.status_code == 401


async def test_health_needs_no_auth(client: AsyncClient) -> None:
    """O healthcheck do Docker não tem como carregar credencial."""
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


# ---------------------------------------------------------------------------
# Listagem e filtros
# ---------------------------------------------------------------------------


async def test_list_returns_newest_first(
    client: AsyncClient, auth: dict[str, str], seeded: list[int]
) -> None:
    response = await client.get("/threats", params={"limit": 50}, headers=auth)
    assert response.status_code == 200

    items = [i for i in response.json()["items"] if i["remote_addr"].startswith(MARKER_IP_PREFIX)]
    timestamps = [i["ts"] for i in items]
    assert timestamps == sorted(timestamps, reverse=True)


async def test_filter_by_severity(
    client: AsyncClient, auth: dict[str, str], seeded: list[int]
) -> None:
    response = await client.get("/threats", params={"severity": "HIGH", "limit": 100}, headers=auth)
    items = [i for i in response.json()["items"] if i["remote_addr"].startswith(MARKER_IP_PREFIX)]
    assert len(items) == 3
    assert all(i["severity"] == "HIGH" for i in items)


async def test_filter_by_category_uses_array_containment(
    client: AsyncClient, auth: dict[str, str], seeded: list[int]
) -> None:
    response = await client.get("/threats", params={"category": "sqli", "limit": 100}, headers=auth)
    items = [i for i in response.json()["items"] if i["remote_addr"].startswith(MARKER_IP_PREFIX)]
    assert len(items) == 2
    assert all("sqli" in i["categories"] for i in items)


async def test_filter_by_remote_addr(
    client: AsyncClient, auth: dict[str, str], seeded: list[int]
) -> None:
    response = await client.get(
        "/threats", params={"remote_addr": f"{MARKER_IP_PREFIX}1"}, headers=auth
    )
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["remote_addr"] == f"{MARKER_IP_PREFIX}1"


async def test_min_score_filter(
    client: AsyncClient, auth: dict[str, str], seeded: list[int]
) -> None:
    response = await client.get("/threats", params={"min_score": 0.9, "limit": 100}, headers=auth)
    items = [i for i in response.json()["items"] if i["remote_addr"].startswith(MARKER_IP_PREFIX)]
    assert all(i["threat_score"] >= 0.9 for i in items)
    assert len(items) == 3


# ---------------------------------------------------------------------------
# Paginação por cursor
# ---------------------------------------------------------------------------


async def test_cursor_pagination_covers_everything_once(
    client: AsyncClient, auth: dict[str, str], seeded: list[int]
) -> None:
    """Sem pular nem repetir — a razão de usar cursor em vez de OFFSET."""
    # Janela restrita às linhas semeadas: o banco de dev também tem tráfego do
    # simulador, e sem o recorte a paginação caminharia a tabela inteira.
    window = {
        "since": (SEED_ANCHOR - timedelta(hours=1)).isoformat(),
        "until": (SEED_ANCHOR + timedelta(seconds=1)).isoformat(),
    }

    seen: list[int] = []
    cursor: str | None = None

    for _ in range(20):  # trava de segurança contra laço infinito
        params: dict[str, object] = {"limit": 3, **window}
        if cursor:
            params["cursor"] = cursor
        payload = (await client.get("/threats", params=params, headers=auth)).json()

        seen.extend(i["id"] for i in payload["items"])
        cursor = payload["next_cursor"]
        if not cursor:
            break

    assert sorted(seen) == sorted(seeded)
    assert len(seen) == len(set(seen)), "cursor repetiu evento"


async def test_invalid_cursor_is_rejected(client: AsyncClient, auth: dict[str, str]) -> None:
    response = await client.get("/threats", params={"cursor": "lixo!!!"}, headers=auth)
    assert response.status_code == 400


async def test_last_page_has_no_cursor(
    client: AsyncClient, auth: dict[str, str], seeded: list[int]
) -> None:
    response = await client.get(
        "/threats",
        params={
            "limit": 200,
            "since": (SEED_ANCHOR - timedelta(hours=1)).isoformat(),
            "until": (SEED_ANCHOR + timedelta(seconds=1)).isoformat(),
        },
        headers=auth,
    )
    assert response.status_code == 200

    payload = response.json()
    assert len(payload["items"]) == len(seeded)
    assert payload["next_cursor"] is None
    assert payload["has_more"] is False


async def test_page_size_is_capped(client: AsyncClient, auth: dict[str, str]) -> None:
    """Teto no tamanho da página: sem ele, `limit=1000000` seria um DoS de uma linha."""
    assert (await client.get("/threats", params={"limit": 500}, headers=auth)).status_code == 422


# ---------------------------------------------------------------------------
# Detalhe e revisão
# ---------------------------------------------------------------------------


async def test_detail_includes_features_and_rules(
    client: AsyncClient, auth: dict[str, str], seeded: list[int]
) -> None:
    """O detalhe traz o que a listagem omite — é o que torna o alerta revisável."""
    payload = (await client.get(f"/threats/{seeded[0]}", headers=auth)).json()
    assert len(payload["matched_rules"]) > 0
    assert payload["rule_score"] > 0
    assert payload["model_version"] == "teste"


async def test_missing_event_returns_404(client: AsyncClient, auth: dict[str, str]) -> None:
    assert (await client.get("/threats/999999999", headers=auth)).status_code == 404


async def test_review_records_human_label(
    client: AsyncClient, auth: dict[str, str], seeded: list[int]
) -> None:
    """Sem rótulo humano o retreino só aprenderia a concordar consigo mesmo."""
    response = await client.patch(
        f"/threats/{seeded[0]}/review", json={"is_attack": True}, headers=auth
    )
    assert response.status_code == 200

    payload = response.json()
    assert payload["reviewed"] is True
    assert payload["review_label"] is True
    assert payload["reviewed_at"] is not None


async def test_review_can_mark_false_positive(
    client: AsyncClient, auth: dict[str, str], seeded: list[int]
) -> None:
    payload = (
        await client.patch(f"/threats/{seeded[1]}/review", json={"is_attack": False}, headers=auth)
    ).json()
    assert payload["reviewed"] is True
    assert payload["review_label"] is False


async def test_similar_events_help_triage(
    client: AsyncClient, auth: dict[str, str], seeded: list[int]
) -> None:
    response = await client.get(f"/threats/{seeded[0]}/similar", headers=auth)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


# ---------------------------------------------------------------------------
# Estatísticas
# ---------------------------------------------------------------------------


async def test_stats_shape(client: AsyncClient, auth: dict[str, str], seeded: list[int]) -> None:
    # 720h para a janela cobrir as linhas semeadas, ancoradas dez dias atrás.
    payload = (await client.get("/stats", params={"hours": 720}, headers=auth)).json()

    assert payload["total_events"] >= len(seeded)
    assert any(s["severity"] == "HIGH" for s in payload["by_severity"])
    assert any(c["category"] == "sqli" for c in payload["by_category"])
    assert isinstance(payload["timeline"], list)
    assert isinstance(payload["top_attackers"], list)


async def test_pipeline_stats_reports_staleness(client: AsyncClient, auth: dict[str, str]) -> None:
    """Se o detector cair, o endpoint diz `stale` em vez de servir número velho."""
    payload = (await client.get("/stats/pipeline", headers=auth)).json()
    assert payload["status"] in {"ok", "stale", "unavailable"}


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------


async def test_model_status(client: AsyncClient, auth: dict[str, str]) -> None:
    payload = (await client.get("/models/status", headers=auth)).json()
    assert payload["detection_mode"] in {"ensemble", "rules_only"}
    assert payload["rule_count"] > 40
    assert sum(payload["ensemble_weights"].values()) == pytest.approx(1.0)


async def test_feature_contract_is_published(client: AsyncClient, auth: dict[str, str]) -> None:
    """O dashboard mostra o vetor de features; sem os nomes seriam 35 números soltos."""
    payload = (await client.get("/models/features", headers=auth)).json()
    assert payload["count"] == 35
    assert len(payload["names"]) == 35


# ---------------------------------------------------------------------------
# Ingestão
# ---------------------------------------------------------------------------


async def test_ingest_detects_attack(client: AsyncClient, auth: dict[str, str]) -> None:
    line = (
        f"{MARKER_IP_PREFIX}99 - - [06/Aug/2026:14:00:00 +0000] "
        '"GET /p?id=1%27%20UNION%20SELECT%20senha%20FROM%20usuarios-- HTTP/1.1" '
        '500 0 "-" "sqlmap/1.8"'
    )
    response = await client.post("/ingest/batch", json={"lines": [line]}, headers=auth)
    assert response.status_code == 200
    assert response.json() == {"accepted": 1, "parsed": 1, "malformed": 0}

    listing = (
        await client.get("/threats", params={"remote_addr": f"{MARKER_IP_PREFIX}99"}, headers=auth)
    ).json()
    assert listing["items"], "o evento ingerido deveria estar persistido"
    assert listing["items"][0]["severity"] == "HIGH"
    assert "sqli" in listing["items"][0]["categories"]

    async with session_scope() as session:
        await session.execute(
            delete(ThreatEvent).where(ThreatEvent.remote_addr == f"{MARKER_IP_PREFIX}99")
        )


async def test_ingest_counts_malformed_without_failing(
    client: AsyncClient, auth: dict[str, str]
) -> None:
    payload = (
        await client.post(
            "/ingest/batch", json={"lines": ["isto não é uma linha de log", ""]}, headers=auth
        )
    ).json()
    assert payload["accepted"] == 0
    assert payload["malformed"] >= 1


async def test_ingest_rejects_oversized_batch(client: AsyncClient, auth: dict[str, str]) -> None:
    response = await client.post("/ingest/batch", json={"lines": ["x"] * 5000}, headers=auth)
    assert response.status_code == 422


async def test_openapi_is_complete(client: AsyncClient) -> None:
    """O contrato do frontend é gerado deste schema."""
    schema = (await client.get("/openapi.json")).json()
    paths = schema["paths"]
    for expected in ("/health", "/stats", "/threats", "/models/status", "/ingest/batch"):
        assert expected in paths, f"{expected} ausente do OpenAPI"
