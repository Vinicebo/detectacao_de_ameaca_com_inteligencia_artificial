"""Calibration constants shipped alongside the ONNX models.

Os três modelos produzem saídas em escalas incompatíveis: erro de reconstrução
(0 a ∞), probabilidade (0 a 1) e distância de anomalia (negativa para outlier).
Combiná-las exige mapear tudo para [0, 1] — e as constantes desse mapeamento vêm
da distribuição do treino, então precisam viajar junto com os modelos.

Carrega também a lista de nomes das features. Isso transforma um bug silencioso
numa falha explícita: se alguém acrescentar uma dimensão em ``features_spec`` e
esquecer de retreinar, o carregamento recusa os modelos antigos em vez de
alimentá-los com um vetor que significa outra coisa.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np

from app.array_types import FloatArray
from app.ml.features_spec import FEATURE_NAMES

CALIBRATION_FILENAME = "scaler.json"


class CalibrationError(Exception):
    """Calibração ausente, corrompida ou incompatível com o contrato atual."""


@dataclass(slots=True)
class Calibration:
    version: str
    feature_names: list[str]
    # StandardScaler
    mean: list[float]
    scale: list[float]
    # Percentil 99 do erro de reconstrução em tráfego benigno. É o ponto em que o
    # autoencoder passa a pontuar 0.5 — ou seja, "tão incomum quanto o 1% mais
    # incomum do que considero normal".
    ae_error_p99: float
    # Limites do decision_function do Isolation Forest no treino, para inverter e
    # normalizar (valor negativo = outlier).
    if_min: float
    if_max: float

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    def save(self, model_dir: Path) -> Path:
        model_dir.mkdir(parents=True, exist_ok=True)
        path = model_dir / CALIBRATION_FILENAME
        path.write_text(self.to_json(), encoding="utf-8")
        return path

    @classmethod
    def load(cls, model_dir: Path) -> Calibration:
        path = model_dir / CALIBRATION_FILENAME
        if not path.is_file():
            raise CalibrationError(f"calibração não encontrada: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            calibration = cls(**data)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise CalibrationError(f"calibração corrompida em {path}: {exc}") from exc

        calibration.verify_contract()
        return calibration

    def verify_contract(self) -> None:
        """Recusa modelos treinados com um contrato de features diferente."""
        current = list(FEATURE_NAMES)
        if self.feature_names != current:
            missing = set(current) - set(self.feature_names)
            extra = set(self.feature_names) - set(current)
            raise CalibrationError(
                "modelos treinados com outro contrato de features — retreine. "
                f"Ausentes nos modelos: {sorted(missing) or 'nenhuma'}; "
                f"desconhecidas para o código atual: {sorted(extra) or 'nenhuma'}"
            )
        if len(self.mean) != len(current) or len(self.scale) != len(current):
            raise CalibrationError(
                f"scaler com {len(self.mean)} dimensões, contrato tem {len(current)}"
            )

    def transform(self, vector: FloatArray) -> FloatArray:
        """Aplica o StandardScaler. Aceita (35,) ou (n, 35)."""
        mean = np.asarray(self.mean, dtype=np.float32)
        scale = np.asarray(self.scale, dtype=np.float32)
        return ((vector - mean) / scale).astype(np.float32)

    def normalize_ae(self, reconstruction_error: float) -> float:
        """Erro de reconstrução → [0, 1), saturando em 0.5 no p99 do benigno."""
        if self.ae_error_p99 <= 0:
            return 0.0
        error = max(reconstruction_error, 0.0)
        return float(error / (error + self.ae_error_p99))

    def normalize_if(self, decision: float) -> float:
        """decision_function → [0, 1], invertido (mais negativo = mais anômalo)."""
        span = self.if_max - self.if_min
        if span <= 0:
            return 0.0
        return float(np.clip((self.if_max - decision) / span, 0.0, 1.0))


def fit_scaler(X: FloatArray) -> tuple[list[float], list[float]]:
    """Média e desvio por dimensão.

    Desvio zero vira 1.0: acontece quando uma feature é constante no conjunto de
    treino (por exemplo, ``country_risk`` sem base GeoIP). Dividir por zero
    produziria NaN e envenenaria todas as predições.
    """
    mean = X.mean(axis=0)
    scale = X.std(axis=0)
    scale[scale < 1e-8] = 1.0
    return mean.astype(float).tolist(), scale.astype(float).tolist()
