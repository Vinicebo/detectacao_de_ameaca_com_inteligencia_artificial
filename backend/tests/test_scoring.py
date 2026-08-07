"""Score fusion and severity policy tests.

A política de detecção mora em ``app/detection/scoring.py``. Estes testes são o
que impede alguém de "ajustar um pouquinho" a fusão e abrir um buraco silencioso
na detecção.
"""

from __future__ import annotations

import pytest

from app.config import Settings
from app.db.models import Severity
from app.detection.scoring import combine_ml, fuse, severity_for


@pytest.fixture
def settings() -> Settings:
    return Settings(api_key="teste")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# A propriedade que mais importa
# ---------------------------------------------------------------------------


def test_confident_rule_is_not_diluted_by_uncertain_ml(settings: Settings) -> None:
    """Este é o teste central deste módulo.

    Uma regra crítica casou (0.95): o payload *contém* `${jndi:ldap://`. O ML está
    indeciso (0.30). Uma média ponderada daria ~0.62 — abaixo do limiar de HIGH, e
    o Log4Shell passaria despercebido. Evidência não pode ser diluída por incerteza.
    """
    breakdown = fuse(rule_score=0.95, ml_score=0.30, settings=settings)
    assert breakdown.threat_score == 0.95
    assert breakdown.severity == Severity.HIGH


def test_ml_alone_can_raise_an_alert(settings: Settings) -> None:
    """O caminho inverso: ataque que nenhuma regra cobre.

    É a razão de existir do autoencoder — categoria nova, sem assinatura escrita.
    """
    breakdown = fuse(rule_score=0.0, ml_score=0.88, settings=settings)
    assert breakdown.threat_score == 0.88
    assert breakdown.severity == Severity.HIGH


def test_agreement_adds_bonus(settings: Settings) -> None:
    """Duas fontes independentes concordando valem mais que qualquer uma sozinha."""
    breakdown = fuse(rule_score=0.6, ml_score=0.65, settings=settings)
    assert breakdown.agreement_bonus == settings.ensemble_agreement_bonus
    assert breakdown.threat_score == pytest.approx(0.75)


def test_bonus_requires_both_sources_above_medium(settings: Settings) -> None:
    """Sem esta condição, ruído de ML somado a regra fraca fabricaria HIGH."""
    breakdown = fuse(rule_score=0.65, ml_score=0.2, settings=settings)
    assert breakdown.agreement_bonus == 0.0
    assert breakdown.threat_score == 0.65
    assert breakdown.severity == Severity.MEDIUM


def test_support_signal_plus_uncertain_ml_stays_below_high(settings: Settings) -> None:
    """Regressão do falso positivo do OAuth.

    Uma regra de apoio (URL absoluta em parâmetro, 0.4) com o modelo achando o
    caminho pouco familiar (0.55) não pode somar até HIGH. Foi assim que um login
    com OAuth virou alerta em teste real: a regra estava em 0.5, alcançava o
    limiar de MEDIUM, habilitava o bônus, e 0.5 + 0.1 dava 0.6... e com ml em 0.68
    o máximo passava de 0.7.
    """
    breakdown = fuse(rule_score=0.4, ml_score=0.55, settings=settings)
    assert breakdown.agreement_bonus == 0.0, "regra abaixo de MEDIUM não habilita o bônus"
    assert breakdown.severity != Severity.HIGH


def test_score_never_exceeds_one(settings: Settings) -> None:
    assert fuse(rule_score=1.0, ml_score=1.0, settings=settings).threat_score == 1.0


def test_clean_request_scores_zero(settings: Settings) -> None:
    breakdown = fuse(rule_score=0.0, ml_score=0.0, settings=settings)
    assert breakdown.threat_score == 0.0
    assert breakdown.severity == Severity.LOW


# ---------------------------------------------------------------------------
# Limiares de severidade
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "esperado"),
    [
        (0.0, Severity.LOW),
        (0.49, Severity.LOW),
        (0.5, Severity.MEDIUM),  # limiar é inclusivo
        (0.69, Severity.MEDIUM),
        (0.7, Severity.HIGH),
        (1.0, Severity.HIGH),
    ],
)
def test_severity_boundaries(score: float, esperado: Severity, settings: Settings) -> None:
    assert severity_for(score, settings) == esperado


def test_thresholds_are_configurable(settings: Settings) -> None:
    """Quanto ruído o time aguenta é decisão de política, não constante de código."""
    strict = Settings(api_key="t", severity_high_threshold=0.9, severity_medium_threshold=0.6)  # type: ignore[arg-type]
    assert severity_for(0.8, settings) == Severity.HIGH
    assert severity_for(0.8, strict) == Severity.MEDIUM


def test_medium_threshold_must_be_below_high() -> None:
    """Configuração incoerente falha no arranque, não em produção."""
    with pytest.raises(ValueError, match="menor que"):
        Settings(api_key="t", severity_high_threshold=0.5, severity_medium_threshold=0.8)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Combinação do ensemble
# ---------------------------------------------------------------------------


def test_ensemble_weights_match_configuration(settings: Settings) -> None:
    assert combine_ml(1.0, 0.0, 0.0, settings) == pytest.approx(settings.weight_autoencoder)
    assert combine_ml(0.0, 1.0, 0.0, settings) == pytest.approx(settings.weight_random_forest)
    assert combine_ml(0.0, 0.0, 1.0, settings) == pytest.approx(settings.weight_isolation_forest)
    assert combine_ml(1.0, 1.0, 1.0, settings) == pytest.approx(1.0)


def test_weights_must_sum_to_one() -> None:
    """Pesos que não somam 1 tornariam o escore não comparável aos limiares."""
    with pytest.raises(ValueError, match="somar"):
        Settings(  # type: ignore[arg-type]
            api_key="t",
            weight_autoencoder=0.5,
            weight_random_forest=0.5,
            weight_isolation_forest=0.5,
        )


def test_breakdown_keeps_components_for_the_dashboard(settings: Settings) -> None:
    """Alerta sem decomposição não é revisável."""
    breakdown = fuse(
        rule_score=0.4,
        ml_score=0.8,
        settings=settings,
        autoencoder=0.9,
        random_forest=0.7,
        isolation_forest=0.8,
    )
    assert breakdown.autoencoder == 0.9
    assert breakdown.random_forest == 0.7
    assert breakdown.isolation_forest == 0.8
    assert breakdown.rule_score == 0.4
    assert breakdown.ml_score == 0.8
