"""Score fusion and severity policy — the single place detection policy lives.

Todo ajuste de "está alertando demais" ou "está deixando passar" acontece aqui ou
no ``.env``, nunca espalhado pelo pipeline.

**Por que ``max(regras, ml)`` e não uma média ponderada.** As duas fontes têm
naturezas diferentes. Uma regra que casou é evidência positiva: o payload
*contém* ``${jndi:ldap://``. O escore de ML é uma estimativa de quão incomum a
requisição é. Fazer média deixaria um modelo indeciso (0.3) diluir uma regra
crítica (0.95) para 0.62 — abaixo do limiar de HIGH, e o Log4Shell passa. A
evidência não deve ser diluída por incerteza.

O bônus de concordância é o inverso: quando as duas fontes independentes apontam
para o mesmo lado, a confiança conjunta é maior que a de qualquer uma sozinha.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.config import Settings
from app.db.models import Severity


@dataclass(slots=True, frozen=True)
class ScoreBreakdown:
    """Todas as parcelas, para o dashboard poder explicar o alerta."""

    rule_score: float
    ml_score: float
    threat_score: float
    severity: Severity
    autoencoder: float | None = None
    random_forest: float | None = None
    isolation_forest: float | None = None
    agreement_bonus: float = 0.0


def combine_ml(
    autoencoder: float, random_forest: float, isolation_forest: float, settings: Settings
) -> float:
    """Média ponderada das três saídas do ensemble."""
    return (
        settings.weight_autoencoder * autoencoder
        + settings.weight_random_forest * random_forest
        + settings.weight_isolation_forest * isolation_forest
    )


def severity_for(score: float, settings: Settings) -> Severity:
    if score >= settings.severity_high_threshold:
        return Severity.HIGH
    if score >= settings.severity_medium_threshold:
        return Severity.MEDIUM
    return Severity.LOW


def fuse(
    rule_score: float,
    ml_score: float,
    settings: Settings,
    *,
    autoencoder: float | None = None,
    random_forest: float | None = None,
    isolation_forest: float | None = None,
) -> ScoreBreakdown:
    """Funde regras e ML na pontuação final."""
    base = max(rule_score, ml_score)

    # O bônus exige que AMBAS as fontes tenham passado do limiar de MEDIUM por
    # conta própria. Sem isso, ruído de ML somado a uma regra fraca produziria
    # HIGH a partir de duas evidências que, isoladas, não valiam nada.
    threshold = settings.severity_medium_threshold
    bonus = (
        settings.ensemble_agreement_bonus
        if rule_score >= threshold and ml_score >= threshold
        else 0.0
    )

    threat_score = min(base + bonus, 1.0)

    return ScoreBreakdown(
        rule_score=rule_score,
        ml_score=ml_score,
        threat_score=threat_score,
        severity=severity_for(threat_score, settings),
        autoencoder=autoencoder,
        random_forest=random_forest,
        isolation_forest=isolation_forest,
        agreement_bonus=bonus,
    )
