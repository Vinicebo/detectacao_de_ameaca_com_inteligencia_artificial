"""ML pipeline tests: synthetic data, calibration, gates, and the ONNX round-trip."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from app.config import Settings
from app.ml import validate
from app.ml.calibration import Calibration, CalibrationError, fit_scaler
from app.ml.features_spec import FEATURE_COUNT, FEATURE_NAMES
from app.ml.synthetic import generate_dataset


@pytest.fixture
def settings() -> Settings:
    return Settings(api_key="teste")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Dados sintéticos
# ---------------------------------------------------------------------------


def test_dataset_shape_and_labels() -> None:
    X, y = generate_dataset(600)
    assert X.shape == (600, FEATURE_COUNT)
    assert set(np.unique(y)) == {0, 1}
    assert X.dtype == np.float32


def test_dataset_values_are_valid() -> None:
    X, _y = generate_dataset(400)
    assert np.isfinite(X).all()
    assert (X >= 0).all() and (X <= 1).all()


def test_dataset_is_reproducible() -> None:
    """Semente fixa é o que torna uma regressão de métrica investigável."""
    X1, y1 = generate_dataset(300, seed=42)
    X2, y2 = generate_dataset(300, seed=42)
    assert np.array_equal(X1, X2)
    assert np.array_equal(y1, y2)


def test_attack_ratio_is_realistic() -> None:
    """50/50 produziria um modelo com viés otimista que dispara demais."""
    _X, y = generate_dataset(2000, attack_ratio=0.35)
    assert 0.30 < y.mean() < 0.40


def test_classes_overlap_in_feature_space() -> None:
    """As classes precisam se sobrepor, ou o modelo aprende o gerador.

    Se benigno e ataque fossem perfeitamente separáveis, qualquer classificador
    atingiria F1 = 1.0 no holdout e falharia em produção, onde as distribuições se
    tocam. A sobreposição vem de `generate_hard_benign` e `generate_stealthy_attack`.
    """
    X, y = generate_dataset(3000)
    benign, attacks = X[y == 0], X[y == 1]

    # Nenhuma feature isolada pode separar as classes por completo.
    for index in range(FEATURE_COUNT):
        b_min, b_max = benign[:, index].min(), benign[:, index].max()
        a_min, a_max = attacks[:, index].min(), attacks[:, index].max()
        assert not (b_max < a_min or a_max < b_min), (
            f"feature {FEATURE_NAMES[index]!r} separa as classes sozinha — "
            "o conjunto sintético é fácil demais"
        )


def test_hard_benign_cases_are_present() -> None:
    """Sem casos difíceis o treino vira decorar, não aprender."""
    from app.ml.synthetic import HARD_BENIGN_FRACTION, STEALTHY_ATTACK_FRACTION

    assert HARD_BENIGN_FRACTION > 0
    assert STEALTHY_ATTACK_FRACTION > 0


# ---------------------------------------------------------------------------
# Calibração
# ---------------------------------------------------------------------------


def test_scaler_handles_constant_feature() -> None:
    """Feature constante (ex.: country_risk sem GeoIP) daria divisão por zero.

    O resultado seria NaN propagando por todas as predições — sem erro nenhum.
    """
    X = np.ones((100, FEATURE_COUNT), dtype=np.float32)
    X[:, 0] = np.random.default_rng(0).random(100)
    _mean, scale = fit_scaler(X)
    assert all(s > 0 for s in scale)


def make_calibration(**overrides: object) -> Calibration:
    defaults: dict[str, object] = {
        "version": "teste",
        "feature_names": list(FEATURE_NAMES),
        "mean": [0.5] * FEATURE_COUNT,
        "scale": [0.2] * FEATURE_COUNT,
        "ae_error_p99": 0.05,
        "if_min": -0.2,
        "if_max": 0.3,
    }
    defaults.update(overrides)
    return Calibration(**defaults)  # type: ignore[arg-type]


def test_calibration_round_trip(tmp_path: Path) -> None:
    original = make_calibration()
    original.save(tmp_path)
    assert Calibration.load(tmp_path).mean == original.mean


def test_calibration_rejects_contract_mismatch(tmp_path: Path) -> None:
    """A proteção que impede degradação silenciosa.

    Alguém acrescenta uma feature e esquece de retreinar: sem esta checagem, os
    modelos antigos passariam a receber um vetor cujas posições significam outra
    coisa. Nenhum erro apareceria — só a detecção piorando.
    """
    stale = make_calibration(feature_names=["a", "b", "c"], mean=[0.0] * 3, scale=[1.0] * 3)
    (tmp_path / "scaler.json").write_text(stale.to_json(), encoding="utf-8")

    with pytest.raises(CalibrationError, match="outro contrato"):
        Calibration.load(tmp_path)


def test_calibration_missing_file(tmp_path: Path) -> None:
    with pytest.raises(CalibrationError, match="não encontrada"):
        Calibration.load(tmp_path)


def test_calibration_corrupt_file(tmp_path: Path) -> None:
    (tmp_path / "scaler.json").write_text("{isto não é json", encoding="utf-8")
    with pytest.raises(CalibrationError, match="corrompida"):
        Calibration.load(tmp_path)


def test_ae_normalization_saturates_at_p99() -> None:
    """O p99 do benigno mapeia para 0.5 — "tão incomum quanto o 1% mais incomum"."""
    calibration = make_calibration(ae_error_p99=0.05)
    assert calibration.normalize_ae(0.05) == pytest.approx(0.5)
    assert calibration.normalize_ae(0.0) == 0.0
    assert 0.9 < calibration.normalize_ae(10.0) < 1.0
    assert calibration.normalize_ae(-1.0) == 0.0


def test_if_normalization_inverts_sign() -> None:
    """decision_function é negativa para outlier; o escore precisa crescer com a anomalia."""
    calibration = make_calibration(if_min=-0.2, if_max=0.3)
    assert calibration.normalize_if(0.3) == pytest.approx(0.0)  # mais normal
    assert calibration.normalize_if(-0.2) == pytest.approx(1.0)  # mais anômalo
    assert calibration.normalize_if(-5.0) == 1.0  # limitado


def test_degenerate_calibration_returns_zero() -> None:
    assert make_calibration(ae_error_p99=0.0).normalize_ae(1.0) == 0.0
    assert make_calibration(if_min=0.5, if_max=0.5).normalize_if(0.1) == 0.0


# ---------------------------------------------------------------------------
# Portões de qualidade
# ---------------------------------------------------------------------------


def test_gates_reject_weak_model(settings: Settings) -> None:
    """Modelo ruim não entra em produção — a versão anterior segue ativa."""
    rng = np.random.default_rng(0)
    y = rng.integers(0, 2, 500)
    scores = rng.random(500)  # aleatório: sem poder preditivo

    result = validate.validate(y, scores, settings)
    assert not result.passed
    assert result.reason is not None
    assert "F1" in result.reason or "PR-AUC" in result.reason


def test_gates_accept_strong_model(settings: Settings) -> None:
    rng = np.random.default_rng(0)
    y = rng.integers(0, 2, 500)
    scores = np.where(y == 1, rng.uniform(0.75, 1.0, 500), rng.uniform(0.0, 0.25, 500))

    result = validate.validate(y, scores, settings)
    assert result.passed
    assert result.metrics["f1"] > 0.9


def test_single_class_validation_is_rejected(settings: Settings) -> None:
    """Métrica sobre uma classe só não tem significado — e passaria pelos portões."""
    result = validate.validate(
        np.zeros(100, dtype=int), np.random.default_rng(0).random(100), settings
    )
    assert not result.passed
    assert "uma classe" in (result.reason or "")


def test_metrics_include_false_positive_rate(settings: Settings) -> None:
    """FPR é o número que decide se o dashboard é utilizável."""
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    scores = np.array([0.1, 0.2, 0.9, 0.1, 0.8, 0.9, 0.7, 0.6])
    metrics = validate.compute_metrics(y, scores)
    assert metrics["false_positive_rate"] == pytest.approx(0.25)


# ---------------------------------------------------------------------------
# Ida e volta pelo ONNX
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_onnx_round_trip_preserves_predictions(tmp_path: Path, settings: Settings) -> None:
    """O modelo exportado precisa concordar com o original.

    Divergência aqui significaria treinar um modelo e servir outro — e as métricas
    de validação, calculadas antes do export, não diriam nada sobre o que roda em
    produção.
    """
    from sklearn.ensemble import RandomForestClassifier

    from app.ml.export_onnx import RANDOM_FOREST_FILE, export_sklearn, verify_export

    X, y = generate_dataset(800)
    model = RandomForestClassifier(n_estimators=20, max_depth=8, random_state=0).fit(X, y)

    path = export_sklearn(model, tmp_path / RANDOM_FOREST_FILE, FEATURE_COUNT)
    sample = X[:32]

    outputs = verify_export(path, sample)
    onnx_probabilities = np.asarray(outputs[-1]).reshape(len(sample), -1)[:, -1]
    sklearn_probabilities = model.predict_proba(sample)[:, 1]

    np.testing.assert_allclose(onnx_probabilities, sklearn_probabilities, atol=1e-4)


def test_calibration_json_is_human_readable(tmp_path: Path) -> None:
    """Arquivo de calibração é diagnosticável a olho, não blob binário."""
    make_calibration().save(tmp_path)
    data = json.loads((tmp_path / "scaler.json").read_text(encoding="utf-8"))
    assert data["feature_names"][0] == FEATURE_NAMES[0]
    assert "ae_error_p99" in data
