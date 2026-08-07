"""Quality gates that decide whether a freshly trained model gets promoted.

Um modelo pior que o anterior entrando em produção sem ninguém perceber é o modo
de falha mais caro deste sistema: a detecção degrada, nenhum erro aparece, e o
sintoma só surge semanas depois como "ando vendo menos alertas".

Por isso todo treino passa por aqui e todo resultado — aprovado ou reprovado —
vai para ``model_versions`` com o motivo.

**Por que PR-AUC e não ROC-AUC:** ataque é a classe rara. Com 1% de positivos, um
classificador medíocre atinge ROC-AUC de 0.95 sem esforço, porque a métrica é
dominada pelos negativos. PR-AUC olha precisão e recall da classe positiva, que é
a que interessa.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

from app.array_types import FloatArray, LabelArray
from app.config import Settings
from app.logging_setup import get_logger

log = get_logger(__name__)


@dataclass(slots=True)
class ValidationResult:
    passed: bool
    metrics: dict[str, float]
    reason: str | None = None

    def as_dict(self) -> dict[str, float]:
        return self.metrics


def compute_metrics(
    y_true: LabelArray, scores: FloatArray, threshold: float = 0.5
) -> dict[str, float]:
    predictions = (scores >= threshold).astype(int)

    metrics = {
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "precision": float(precision_score(y_true, predictions, zero_division=0)),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "pr_auc": float(average_precision_score(y_true, scores)),
        "threshold": float(threshold),
        "positives": int(y_true.sum()),
        "samples": len(y_true),
    }

    # ROC-AUC entra só como referência; não é portão. Precisa de ambas as classes.
    if len(np.unique(y_true)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_true, scores))

    # Taxa de falso positivo é o número que decide se o dashboard é utilizável.
    negatives = int((y_true == 0).sum())
    if negatives:
        metrics["false_positive_rate"] = float(
            ((predictions == 1) & (y_true == 0)).sum() / negatives
        )

    return metrics


def best_threshold(y_true: LabelArray, scores: FloatArray) -> float:
    """Limiar que maximiza F1 no conjunto de validação.

    Reportado como informação, não aplicado: o limiar de operação é
    ``severity_high_threshold``, que é decisão de política (quanto ruído o time
    aguenta), não de otimização.
    """
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    if len(thresholds) == 0:
        return 0.5
    denominator = precision + recall
    with np.errstate(divide="ignore", invalid="ignore"):
        f1 = np.where(denominator > 0, 2 * precision * recall / denominator, 0.0)
    # precision_recall_curve devolve um ponto a mais que thresholds.
    return float(thresholds[int(np.argmax(f1[:-1]))])


def validate(
    y_true: LabelArray, scores: FloatArray, settings: Settings, threshold: float = 0.5
) -> ValidationResult:
    """Aplica os portões. Reprovou, não promove."""
    if len(np.unique(y_true)) < 2:
        return ValidationResult(
            passed=False,
            metrics={"samples": len(y_true)},
            reason="conjunto de validação tem uma classe só — métricas não têm significado",
        )

    metrics = compute_metrics(y_true, scores, threshold)
    metrics["best_threshold"] = best_threshold(y_true, scores)

    failures: list[str] = []
    if metrics["f1"] < settings.min_f1:
        failures.append(f"F1 {metrics['f1']:.3f} < mínimo {settings.min_f1:.2f}")
    if metrics["pr_auc"] < settings.min_pr_auc:
        failures.append(f"PR-AUC {metrics['pr_auc']:.3f} < mínimo {settings.min_pr_auc:.2f}")

    if failures:
        reason = "; ".join(failures)
        log.warning(
            "validation.rejected",
            reason=reason,
            **{k: v for k, v in metrics.items() if isinstance(v, float)},
        )
        return ValidationResult(passed=False, metrics=metrics, reason=reason)

    log.info(
        "validation.passed",
        f1=round(metrics["f1"], 4),
        pr_auc=round(metrics["pr_auc"], 4),
        fpr=round(metrics.get("false_positive_rate", 0.0), 4),
    )
    return ValidationResult(passed=True, metrics=metrics)
