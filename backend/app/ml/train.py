"""Train the three-model ensemble and export it to ONNX.

Por que três modelos e não um: cada um enxerga um tipo de ataque que os outros
perdem.

* **Autoencoder** — treinado *só em tráfego benigno*. Aprende a reconstruir o que
  é normal; o que ele reconstrói mal é, por definição, incomum. Pega ataque que
  nunca esteve no conjunto de treino, inclusive categoria que ainda não existia.
* **Random Forest** — supervisionado. É o mais preciso nas famílias que conhece, e
  o único que dá alguma explicabilidade por importância de feature.
* **Isolation Forest** — não supervisionado, isola outlier por partição
  aleatória. Barato e independente do autoencoder, o que faz o desacordo entre os
  dois ser informativo.

Um ataque que imita tráfego normal engana o autoencoder mas não o Random Forest;
uma categoria nova engana o Random Forest mas não o autoencoder.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from app.array_types import FloatArray, LabelArray
from app.config import Settings, get_settings
from app.logging_setup import configure_logging, get_logger
from app.ml import export_onnx, validate
from app.ml.calibration import Calibration, fit_scaler
from app.ml.features_spec import FEATURE_COUNT, FEATURE_NAMES

log = get_logger(__name__)

RANDOM_SEED = 20260806
AE_EPOCHS = 60
AE_BATCH_SIZE = 256
AE_LEARNING_RATE = 1e-3
HOLDOUT_FRACTION = 0.25


def build_autoencoder(n_features: int) -> Any:
    """35 → 24 → 12 → 24 → 35.

    O gargalo de 12 é ~1/3 da entrada: apertado o bastante para forçar o modelo a
    aprender a estrutura do tráfego normal em vez de copiar a entrada, largo o
    bastante para não perder as features de janela, que carregam boa parte do sinal.
    """
    import torch.nn as nn

    return nn.Sequential(
        nn.Linear(n_features, 24),
        nn.ReLU(),
        nn.Linear(24, 12),
        nn.ReLU(),
        nn.Linear(12, 24),
        nn.ReLU(),
        nn.Linear(24, n_features),
    )


def train_autoencoder(X_benign: FloatArray, n_features: int) -> tuple[Any, FloatArray]:
    """Treina só em benigno e devolve ``(modelo, erros_de_reconstrução_benignos)``."""
    import torch
    from torch.utils.data import DataLoader, TensorDataset

    torch.manual_seed(RANDOM_SEED)

    model = build_autoencoder(n_features)
    optimizer = torch.optim.Adam(model.parameters(), lr=AE_LEARNING_RATE)
    criterion = torch.nn.MSELoss()

    tensor = torch.from_numpy(X_benign.astype(np.float32))
    loader = DataLoader(TensorDataset(tensor, tensor), batch_size=AE_BATCH_SIZE, shuffle=True)

    model.train()
    for epoch in range(AE_EPOCHS):
        total = 0.0
        for batch, _target in loader:
            optimizer.zero_grad()
            loss = criterion(model(batch), batch)
            loss.backward()
            optimizer.step()
            total += loss.item() * len(batch)
        if epoch % 15 == 0 or epoch == AE_EPOCHS - 1:
            log.info("train.autoencoder", epoch=epoch, loss=round(total / len(tensor), 6))

    model.eval()
    with torch.no_grad():
        reconstruction = model(tensor).numpy()
    errors = np.mean((X_benign - reconstruction) ** 2, axis=1)

    return model, errors


def train_random_forest(X: FloatArray, y: LabelArray) -> Any:
    from sklearn.ensemble import RandomForestClassifier

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=16,
        min_samples_leaf=3,
        # Compensa o desbalanceamento sem reamostrar: sem isto o modelo aprende
        # que "chutar benigno sempre" já acerta a maioria.
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_SEED,
    )
    model.fit(X, y)
    log.info("train.random_forest", trees=model.n_estimators, depth=model.max_depth)
    return model


def train_isolation_forest(X: FloatArray, contamination: float) -> Any:
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(
        n_estimators=150,
        # Limitado ao intervalo aceito pelo sklearn; fora disso o fit levanta erro.
        contamination=float(np.clip(contamination, 0.01, 0.5)),
        max_samples="auto",
        n_jobs=-1,
        random_state=RANDOM_SEED,
    )
    model.fit(X)
    log.info("train.isolation_forest", trees=model.n_estimators, contamination=contamination)
    return model


def ensemble_scores(
    ae_errors: FloatArray,
    rf_probabilities: FloatArray,
    if_decisions: FloatArray,
    calibration: Calibration,
    settings: Settings,
) -> FloatArray:
    """Combina as três saídas normalizadas com os pesos configurados."""
    ae = np.array([calibration.normalize_ae(float(e)) for e in ae_errors])
    isolation = np.array([calibration.normalize_if(float(d)) for d in if_decisions])
    combined = (
        settings.weight_autoencoder * ae
        + settings.weight_random_forest * rf_probabilities
        + settings.weight_isolation_forest * isolation
    )
    return np.asarray(combined, dtype=np.float64)


def _split(X: FloatArray, y: LabelArray, fraction: float) -> tuple[FloatArray, ...]:
    """Divisão estratificada — cada lado precisa das duas classes."""
    from sklearn.model_selection import train_test_split

    return train_test_split(  # type: ignore[no-any-return]
        X, y, test_size=fraction, random_state=RANDOM_SEED, stratify=y
    )


def train_and_export(
    X: FloatArray,
    y: LabelArray,
    settings: Settings,
    source: str = "synthetic",
) -> tuple[validate.ValidationResult, str, dict[str, str]]:
    """Treina, valida e — se passar nos portões — grava os artefatos.

    Devolve ``(resultado, versão, caminhos)``. Os arquivos só são escritos se a
    validação passar: assim o volume de modelos nunca fica com um artefato
    reprovado que um restart carregaria sem querer.
    """
    if X.shape[1] != FEATURE_COUNT:
        raise ValueError(f"esperado {FEATURE_COUNT} features, recebido {X.shape[1]}")

    version = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    log.info("train.start", samples=len(y), attacks=int(y.sum()), source=source, version=version)

    X_train, X_holdout, y_train, y_holdout = _split(X, y, HOLDOUT_FRACTION)

    # O scaler é ajustado SÓ no treino. Ajustar no conjunto todo vazaria
    # informação do holdout e inflaria as métricas.
    mean, scale = fit_scaler(X_train)
    mean_array = np.asarray(mean, dtype=np.float32)
    scale_array = np.asarray(scale, dtype=np.float32)

    def transform(data: FloatArray) -> FloatArray:
        return ((data - mean_array) / scale_array).astype(np.float32)

    X_train_scaled = transform(X_train)
    X_holdout_scaled = transform(X_holdout)

    benign_train = X_train_scaled[y_train == 0]
    if len(benign_train) < 50:
        raise ValueError(f"amostras benignas insuficientes para o autoencoder: {len(benign_train)}")

    autoencoder, benign_errors = train_autoencoder(benign_train, FEATURE_COUNT)
    random_forest = train_random_forest(X_train_scaled, y_train)
    isolation_forest = train_isolation_forest(X_train_scaled, float(y_train.mean()))

    if_train_decisions = isolation_forest.decision_function(X_train_scaled)

    calibration = Calibration(
        version=version,
        feature_names=list(FEATURE_NAMES),
        mean=mean,
        scale=scale,
        ae_error_p99=float(np.percentile(benign_errors, 99)),
        if_min=float(if_train_decisions.min()),
        if_max=float(if_train_decisions.max()),
    )

    # ---------------------------------------------------------------- validação
    import torch

    with torch.no_grad():
        holdout_reconstruction = autoencoder(torch.from_numpy(X_holdout_scaled)).numpy()
    ae_holdout_errors = np.mean((X_holdout_scaled - holdout_reconstruction) ** 2, axis=1)
    rf_holdout = random_forest.predict_proba(X_holdout_scaled)[:, 1]
    if_holdout = isolation_forest.decision_function(X_holdout_scaled)

    scores = ensemble_scores(ae_holdout_errors, rf_holdout, if_holdout, calibration, settings)
    result = validate.validate(y_holdout, scores, settings)

    if not result.passed:
        log.error("train.rejected", version=version, reason=result.reason)
        return result, version, {}

    # ---------------------------------------------------------------- artefatos
    model_dir = settings.model_dir
    paths = {
        "autoencoder": str(
            export_onnx.export_autoencoder(
                autoencoder, model_dir / export_onnx.AUTOENCODER_FILE, FEATURE_COUNT
            )
        ),
        "random_forest": str(
            export_onnx.export_sklearn(
                random_forest, model_dir / export_onnx.RANDOM_FOREST_FILE, FEATURE_COUNT
            )
        ),
        "isolation_forest": str(
            export_onnx.export_sklearn(
                isolation_forest, model_dir / export_onnx.ISOLATION_FOREST_FILE, FEATURE_COUNT
            )
        ),
    }

    sample = X_holdout_scaled[:4]
    for name, path in paths.items():
        export_onnx.verify_export(Path(path), sample)
        log.info("train.export_verified", model=name)

    paths["calibration"] = str(calibration.save(model_dir))
    log.info(
        "train.completed",
        version=version,
        **{k: round(v, 4) for k, v in result.metrics.items() if isinstance(v, float)},
    )

    return result, version, paths


async def train_from_synthetic(settings: Settings | None = None) -> str:
    """Treino de bootstrap — chamado pelo entrypoint na primeira subida."""
    from app.db.session import init_engine
    from app.ml.synthetic import generate_dataset

    settings = settings or get_settings()
    # Idempotente. Necessário porque este caminho roda tanto dentro da API (engine
    # já criado pelo lifespan) quanto como processo solto via `python -m app.ml.train`.
    init_engine(settings)

    X, y = generate_dataset(settings.synthetic_sample_count)

    # to_thread: o treino é CPU-bound e travaria o loop de eventos por minutos.
    # Importa porque o /models/retrain dispara este mesmo caminho dentro da API,
    # que precisa seguir respondendo enquanto treina.
    result, version, paths = await asyncio.to_thread(train_and_export, X, y, settings, "synthetic")

    from app.ml.registry import log_to_mlflow, register_version

    log_to_mlflow(version, result, "synthetic", len(y), settings)
    await register_version(
        version=version,
        result=result,
        paths=paths,
        source="synthetic",
        sample_count=len(y),
    )
    return version


def main() -> int:
    settings = get_settings()
    configure_logging(settings)
    version = asyncio.run(train_from_synthetic(settings))
    log.info("train.done", version=version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
