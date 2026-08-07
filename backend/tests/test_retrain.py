"""Retraining tests.

O foco é o balanceamento dos rótulos heurísticos — a proteção contra o retreino
piorar o modelo em vez de melhorá-lo.
"""

from __future__ import annotations

import numpy as np
import pytest

from app.config import Settings
from app.ml.features_spec import FEATURE_COUNT
from app.ml.retrain import DatasetComposition, _balanced_count, top_up_with_synthetic


@pytest.fixture
def settings() -> Settings:
    return Settings(api_key="teste")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Balanceamento dos rótulos heurísticos
# ---------------------------------------------------------------------------


def test_heuristic_labels_are_balanced() -> None:
    """Usa o mínimo entre as classes, nunca o que houver de cada uma."""
    assert _balanced_count(attacks=100, benign=40) == 40
    assert _balanced_count(attacks=40, benign=100) == 40
    assert _balanced_count(attacks=50, benign=50) == 50


def test_single_class_heuristic_is_discarded_entirely() -> None:
    """Regressão de um defeito real encontrado com tráfego de verdade.

    A amostragem de eventos LOW (5%) somada ao rótulo só nos extremos fazia o
    conjunto real chegar com 61 ataques e ZERO benignos. Treinar assim empurrava a
    fronteira para cima e tráfego normal passava a pontuar MEDIUM — e os portões
    de qualidade não pegavam, porque validam contra os mesmos rótulos enviesados.

    Sem exemplo das duas classes, o rótulo heurístico só enviesaria: descarta-se
    tudo e o treino cai para sintético mais os rótulos humanos.
    """
    assert _balanced_count(attacks=61, benign=0) == 0
    assert _balanced_count(attacks=0, benign=61) == 0
    assert _balanced_count(attacks=0, benign=0) == 0


# ---------------------------------------------------------------------------
# Complemento com dados sintéticos
# ---------------------------------------------------------------------------


def test_top_up_fills_missing_classes(settings: Settings) -> None:
    """Ambiente sem ataque nenhum treinaria um classificador que diz sempre "benigno"."""
    vectors = [[0.1] * FEATURE_COUNT for _ in range(10)]
    labels = [0] * 10

    _X, y, composition = top_up_with_synthetic(vectors, labels, DatasetComposition(), settings)

    assert len(np.unique(y)) == 2, "precisa das duas classes para treinar"
    assert int((y == 1).sum()) >= settings.retrain_min_samples_per_class
    assert composition.synthetic_attacks > 0


def test_top_up_is_skipped_when_real_data_suffices(settings: Settings) -> None:
    minimum = settings.retrain_min_samples_per_class
    vectors = [[0.5] * FEATURE_COUNT for _ in range(minimum * 2)]
    labels = [0] * minimum + [1] * minimum

    X, y, composition = top_up_with_synthetic(vectors, labels, DatasetComposition(), settings)

    assert composition.synthetic_total == 0
    assert len(y) == minimum * 2
    assert X.shape[1] == FEATURE_COUNT


def test_composition_reports_source_honestly() -> None:
    """`training_source` precisa refletir de onde os dados vieram."""
    assert DatasetComposition(reviewed_attacks=10, reviewed_benign=10).source == "real"
    assert DatasetComposition(synthetic_attacks=10, synthetic_benign=10).source == "synthetic"
    assert DatasetComposition(reviewed_attacks=5, synthetic_benign=10).source == "mixed"


def test_composition_counts_are_exposed() -> None:
    """Sem a composição, não dá para explicar por que um modelo ficou pior."""
    composition = DatasetComposition(
        reviewed_attacks=3, reviewed_benign=2, heuristic_attacks=40, heuristic_benign=40
    )
    assert composition.real_total == 85
    assert set(composition.as_dict()) == {
        "reviewed_attacks",
        "reviewed_benign",
        "heuristic_attacks",
        "heuristic_benign",
        "synthetic_attacks",
        "synthetic_benign",
    }
