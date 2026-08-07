"""Retrain from stored events — where the model stops being generic.

O modelo de bootstrap aprende com tráfego sintético, que é uma caricatura. O
modelo bom aprende com o tráfego do ambiente real: as URLs que existem de fato, os
clientes que existem de fato, os ataques que esse alvo específico atrai.

Duas fontes de rótulo, com pesos bem diferentes:

* **Eventos revisados** — julgamento humano. É o rótulo de verdade.
* **Eventos não revisados** — heurística sobre o escore que o próprio sistema
  atribuiu. Isso é parcialmente circular (o modelo aprende a concordar consigo
  mesmo), então usamos só os extremos: escore muito alto ou muito baixo. A faixa
  do meio é exatamente onde o sistema está incerto, e transformar essa incerteza
  em rótulo ensinaria o erro.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import numpy as np
from sqlalchemy import select

from app.array_types import FloatArray, LabelArray
from app.config import Settings, get_settings
from app.db.models import ThreatEvent
from app.db.session import session_scope
from app.logging_setup import get_logger
from app.ml.features_spec import FEATURE_COUNT

log = get_logger(__name__)

# Teto de eventos lidos do banco. Sem isto, uma base de meses viraria uma
# alocação de vários GB dentro do processo da API.
MAX_EVENTS = 200_000


@dataclass(slots=True)
class DatasetComposition:
    """De onde veio cada amostra — vai para os metadados da versão do modelo."""

    reviewed_attacks: int = 0
    reviewed_benign: int = 0
    heuristic_attacks: int = 0
    heuristic_benign: int = 0
    synthetic_attacks: int = 0
    synthetic_benign: int = 0

    @property
    def real_total(self) -> int:
        return (
            self.reviewed_attacks
            + self.reviewed_benign
            + self.heuristic_attacks
            + self.heuristic_benign
        )

    @property
    def synthetic_total(self) -> int:
        return self.synthetic_attacks + self.synthetic_benign

    @property
    def source(self) -> str:
        if self.synthetic_total == 0:
            return "real"
        if self.real_total == 0:
            return "synthetic"
        return "mixed"

    def as_dict(self) -> dict[str, int]:
        return {
            "reviewed_attacks": self.reviewed_attacks,
            "reviewed_benign": self.reviewed_benign,
            "heuristic_attacks": self.heuristic_attacks,
            "heuristic_benign": self.heuristic_benign,
            "synthetic_attacks": self.synthetic_attacks,
            "synthetic_benign": self.synthetic_benign,
        }


async def collect_real_samples(
    settings: Settings,
) -> tuple[list[list[float]], list[int], DatasetComposition]:
    """Lê eventos armazenados e monta ``(vetores, rótulos, composição)``."""
    composition = DatasetComposition()
    vectors: list[list[float]] = []
    labels: list[int] = []

    async with session_scope() as session:
        # Eventos revisados primeiro — são os rótulos que valem.
        reviewed = (
            await session.execute(
                select(ThreatEvent.features, ThreatEvent.review_label)
                .where(
                    ThreatEvent.reviewed.is_(True),
                    ThreatEvent.review_label.is_not(None),
                    ThreatEvent.features.is_not(None),
                )
                .order_by(ThreatEvent.reviewed_at.desc())
                .limit(MAX_EVENTS)
            )
        ).all()

        for features, is_attack in reviewed:
            if features is None or len(features) != FEATURE_COUNT:
                # Evento gravado sob outro contrato de features. Descartar é a
                # única opção correta: o vetor significa outra coisa.
                continue
            vectors.append(list(features))
            labels.append(1 if is_attack else 0)
            if is_attack:
                composition.reviewed_attacks += 1
            else:
                composition.reviewed_benign += 1

        remaining = MAX_EVENTS - len(vectors)
        if remaining > 0:
            unreviewed = (
                await session.execute(
                    select(ThreatEvent.features, ThreatEvent.threat_score)
                    .where(
                        ThreatEvent.reviewed.is_(False),
                        ThreatEvent.features.is_not(None),
                    )
                    .order_by(ThreatEvent.ts.desc())
                    .limit(remaining)
                )
            ).all()

            heuristic_attacks: list[list[float]] = []
            heuristic_benign: list[list[float]] = []

            for features, score in unreviewed:
                if features is None or len(features) != FEATURE_COUNT:
                    continue
                # Só os extremos. A faixa do meio é onde o sistema está incerto —
                # rotulá-la ensinaria o próprio erro.
                if score >= settings.retrain_attack_score_floor:
                    heuristic_attacks.append(list(features))
                elif score <= settings.retrain_benign_score_ceiling:
                    heuristic_benign.append(list(features))

            keep = _balanced_count(len(heuristic_attacks), len(heuristic_benign))
            for vector in heuristic_attacks[:keep]:
                vectors.append(vector)
                labels.append(1)
                composition.heuristic_attacks += 1
            for vector in heuristic_benign[:keep]:
                vectors.append(vector)
                labels.append(0)
                composition.heuristic_benign += 1

            if keep == 0 and (heuristic_attacks or heuristic_benign):
                log.warning(
                    "retrain.heuristic_discarded",
                    attacks_available=len(heuristic_attacks),
                    benign_available=len(heuristic_benign),
                    reason="sem as duas classes, o rótulo heurístico só enviesaria",
                )

    return vectors, labels, composition


def _balanced_count(attacks: int, benign: int) -> int:
    """Quantas amostras heurísticas usar de CADA classe.

    Sempre o mínimo entre as duas — se uma classe não tem exemplo, nenhuma é
    usada. Isso corrige um defeito real, encontrado testando com tráfego de
    verdade: o retreino degradava o modelo em vez de melhorá-lo.

    A causa era a combinação de duas decisões que, isoladas, fazem sentido:

    1. Eventos LOW são gravados por amostragem (5%), para o banco não inchar.
    2. O rótulo heurístico só aceita os extremos do escore.

    Juntas, elas garantem que quase nenhum evento **benigno** chega rotulado:
    os que pontuam baixo foram descartados na amostragem, e os que sobram caem na
    faixa do meio. Numa medição real: 61 amostras rotuladas como ataque e **zero**
    como benigno. Treinar assim empurra a fronteira de decisão para cima, e
    tráfego normal passa a pontuar MEDIUM.

    Pior: os portões de qualidade não pegam isso, porque validam contra os mesmos
    rótulos enviesados — o modelo aprende a concordar com o viés e tira nota alta.

    Rótulos humanos (`reviewed`) não passam por aqui: são confiáveis e nunca
    descartados.
    """
    return min(attacks, benign)


def top_up_with_synthetic(
    vectors: list[list[float]],
    labels: list[int],
    composition: DatasetComposition,
    settings: Settings,
) -> tuple[FloatArray, LabelArray, DatasetComposition]:
    """Completa com dados sintéticos se alguma classe estiver escassa.

    Um ambiente que ainda não sofreu ataque nenhum tem zero exemplos positivos, e
    treinar assim produziria um classificador que diz "benigno" para tudo. Melhor
    misturar sintético e registrar isso em `training_source` do que gerar um
    modelo confiante e inútil.
    """
    from app.ml.synthetic import generate_dataset

    minimum = settings.retrain_min_samples_per_class
    label_array = np.asarray(labels, dtype=np.int64) if labels else np.empty(0, dtype=np.int64)
    attacks = int((label_array == 1).sum())
    benign = int((label_array == 0).sum())

    need_attacks = max(0, minimum - attacks)
    need_benign = max(0, minimum - benign)

    if need_attacks == 0 and need_benign == 0:
        return np.asarray(vectors, dtype=np.float32), label_array, composition

    log.info("retrain.topping_up", need_attacks=need_attacks, need_benign=need_benign)

    # Gera com folga e seleciona o que falta de cada classe.
    total_needed = (need_attacks + need_benign) * 4
    X_synth, y_synth = generate_dataset(max(total_needed, 2000))

    if need_attacks:
        extra = X_synth[y_synth == 1][:need_attacks]
        vectors.extend(extra.tolist())
        labels.extend([1] * len(extra))
        composition.synthetic_attacks = len(extra)
    if need_benign:
        extra = X_synth[y_synth == 0][:need_benign]
        vectors.extend(extra.tolist())
        labels.extend([0] * len(extra))
        composition.synthetic_benign = len(extra)

    return (
        np.asarray(vectors, dtype=np.float32),
        np.asarray(labels, dtype=np.int64),
        composition,
    )


async def retrain(settings: Settings | None = None, use_real_data: bool = True) -> str:
    """Retreina, valida e promove se passar. Devolve a versão."""
    from app.ml.registry import log_to_mlflow, register_version
    from app.ml.train import train_and_export

    settings = settings or get_settings()

    if use_real_data:
        vectors, labels, composition = await collect_real_samples(settings)
        log.info("retrain.collected", **composition.as_dict())
    else:
        vectors, labels, composition = [], [], DatasetComposition()

    X, y, composition = await asyncio.to_thread(
        top_up_with_synthetic, vectors, labels, composition, settings
    )

    if len(np.unique(y)) < 2:
        raise ValueError("dados insuficientes: o conjunto ficou com uma classe só")

    result, version, paths = await asyncio.to_thread(
        train_and_export, X, y, settings, composition.source
    )

    log_to_mlflow(version, result, composition.source, len(y), settings)
    await register_version(
        version=version,
        result=result,
        paths=paths,
        source=composition.source,
        sample_count=len(y),
    )

    log.info(
        "retrain.finished",
        version=version,
        promoted=result.passed,
        source=composition.source,
        samples=len(y),
    )
    return version
