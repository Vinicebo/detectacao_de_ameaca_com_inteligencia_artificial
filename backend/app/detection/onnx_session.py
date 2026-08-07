"""ONNX Runtime session management.

Sessões são criadas uma vez e reutilizadas. Criar uma por predição custaria mais
que a própria inferência.

Regra de ouro deste módulo: **nunca deixar um problema de modelo derrubar a
detecção.** Artefato ausente, corrompido ou treinado com outro contrato de
features faz o sistema cair para o modo somente-regras — que detecta bem menos,
mas detecta. Um detector fora do ar não protege nada.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import numpy as np

from app.array_types import FloatArray
from app.logging_setup import get_logger
from app.ml.calibration import Calibration, CalibrationError
from app.ml.export_onnx import (
    AUTOENCODER_FILE,
    INPUT_NAME,
    ISOLATION_FOREST_FILE,
    RANDOM_FOREST_FILE,
)

log = get_logger(__name__)


class EnsembleUnavailableError(Exception):
    """Modelos não carregáveis. Quem chama cai para somente-regras."""


def _load_session(path: Path) -> Any:
    import onnxruntime as ort

    options = ort.SessionOptions()
    # Um thread por sessão: o pipeline já é concorrente por outras vias, e deixar
    # o ORT abrir um pool por modelo faz três pools competirem pelas mesmas CPUs.
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

    return ort.InferenceSession(str(path), options, providers=["CPUExecutionProvider"])


def _pick_output(outputs: list[Any], names: list[str], preferred: tuple[str, ...]) -> FloatArray:
    """Escolhe a saída pelo nome, com a posição como reserva.

    skl2onnx nomeia as saídas de forma diferente entre versões; casar por nome com
    fallback posicional evita quebrar num upgrade de dependência.
    """
    for wanted in preferred:
        for index, name in enumerate(names):
            if name == wanted:
                return np.asarray(outputs[index])
    # Reserva: a primeira saída de ponto flutuante com mais de uma dimensão útil.
    for output in outputs:
        array = np.asarray(output)
        if array.dtype.kind == "f":
            return array
    raise EnsembleUnavailableError(f"nenhuma saída utilizável entre {names}")


class EnsembleSession:
    """As três sessões ONNX mais a calibração."""

    def __init__(self, model_dir: Path) -> None:
        self._model_dir = model_dir
        self._lock = threading.Lock()
        self.calibration = Calibration.load(model_dir)

        try:
            self._ae = _load_session(model_dir / AUTOENCODER_FILE)
            self._rf = _load_session(model_dir / RANDOM_FOREST_FILE)
            self._if = _load_session(model_dir / ISOLATION_FOREST_FILE)
        except Exception as exc:
            raise EnsembleUnavailableError(f"falha ao carregar sessão ONNX: {exc}") from exc

        self._rf_outputs = [o.name for o in self._rf.get_outputs()]
        self._if_outputs = [o.name for o in self._if.get_outputs()]

        log.info(
            "ensemble.loaded",
            version=self.calibration.version,
            model_dir=str(model_dir),
        )

    @property
    def version(self) -> str:
        return self.calibration.version

    def score(self, features: list[float]) -> tuple[float, float, float]:
        """Devolve ``(ae, rf, if)``, cada um em [0, 1]."""
        vector = np.asarray(features, dtype=np.float32).reshape(1, -1)
        scaled = self.calibration.transform(vector)

        # InferenceSession.run é thread-safe no ORT, mas serializamos porque o
        # dispatch é single-threaded e a trava custa quase nada aqui.
        with self._lock:
            reconstruction = np.asarray(self._ae.run(None, {INPUT_NAME: scaled})[0])
            rf_raw = self._rf.run(None, {INPUT_NAME: scaled})
            if_raw = self._if.run(None, {INPUT_NAME: scaled})

        ae_error = float(np.mean((scaled - reconstruction) ** 2))
        ae_score = self.calibration.normalize_ae(ae_error)

        probabilities = _pick_output(
            rf_raw, self._rf_outputs, ("probabilities", "output_probability")
        )
        # Coluna 1 é a probabilidade da classe positiva (ataque).
        rf_score = float(
            np.clip(probabilities.reshape(probabilities.shape[0], -1)[0, -1], 0.0, 1.0)
        )

        decisions = _pick_output(if_raw, self._if_outputs, ("scores", "decision_function"))
        if_score = self.calibration.normalize_if(float(decisions.reshape(-1)[0]))

        return ae_score, rf_score, if_score


def try_load(model_dir: Path) -> EnsembleSession | None:
    """Carrega o ensemble, devolvendo ``None`` em vez de propagar erro.

    Todo motivo de falha é logado com clareza: descobrir que rodou um mês em modo
    somente-regras é bem pior do que a degradação em si.
    """
    try:
        return EnsembleSession(model_dir)
    except CalibrationError as exc:
        log.error("ensemble.contract_mismatch", error=str(exc), mode="rules_only")
    except EnsembleUnavailableError as exc:
        log.error("ensemble.unavailable", error=str(exc), mode="rules_only")
    except Exception as exc:
        log.error("ensemble.load_failed", error=str(exc), mode="rules_only")
    return None
