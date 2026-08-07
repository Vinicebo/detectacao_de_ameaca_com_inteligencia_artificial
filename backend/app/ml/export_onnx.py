"""Export trained models to ONNX.

Por que ONNX e não carregar torch/sklearn direto na inferência: o container `api`
fica em ~350 MB com onnxruntime, contra vários GB com torch. E o custo por
predição cai de forma relevante — o pipeline pontua cada requisição
individualmente, então latência por amostra importa mais que vazão em lote.

Nomes de entrada e saída são fixados aqui e consumidos por
``app.detection.onnx_session``. Mudar um nome sem mudar o outro produz um
``InvalidArgument`` no arranque, que é o momento certo para descobrir.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np

from app.array_types import FloatArray
from app.logging_setup import get_logger

log = get_logger(__name__)

INPUT_NAME = "features"

AUTOENCODER_FILE = "autoencoder.onnx"
RANDOM_FOREST_FILE = "random_forest.onnx"
ISOLATION_FOREST_FILE = "isolation_forest.onnx"

ONNX_OPSET = 17

# Modelos do scikit-learn usam operadores do domínio `ai.onnx.ml`, versionado
# separadamente do opset principal. O skl2onnx escolhe a versão 4 por padrão e
# depois recusa a própria escolha; fixar em 3 é o que o onnxruntime atual consome.
SKLEARN_TARGET_OPSET = {"": ONNX_OPSET, "ai.onnx.ml": 3}


def export_autoencoder(model: Any, path: Path, n_features: int) -> Path:
    """Exporta o autoencoder PyTorch. A saída é a reconstrução da entrada."""
    import torch

    model.eval()
    dummy = torch.zeros(1, n_features, dtype=torch.float32)

    path.parent.mkdir(parents=True, exist_ok=True)
    with torch.no_grad():
        torch.onnx.export(
            model,
            (dummy,),
            str(path),
            input_names=[INPUT_NAME],
            output_names=["reconstruction"],
            opset_version=ONNX_OPSET,
            # Exportador dynamo (padrão a partir do torch 2.9). O legado ainda
            # existe mas está a caminho da remoção.
            dynamo=True,
            # Sem isto o exportador escreve os pesos num `.onnx.data` separado. O
            # modelo tem alguns KB — não há motivo para dois arquivos, e o segundo
            # escaparia da checagem de artefatos do healthcheck e do entrypoint.
            external_data=False,
            # Lote dinâmico: o pipeline pontua de uma em uma, a validação avalia
            # milhares de uma vez. O caminho dynamo usa dynamic_shapes, não
            # dynamic_axes — este último é silenciosamente ignorado aqui.
            dynamic_shapes=({0: torch.export.Dim("batch")},),
        )
    log.info("onnx.exported", model="autoencoder", path=str(path))
    return path


def export_sklearn(model: Any, path: Path, n_features: int, *, zipmap: bool = False) -> Path:
    """Exporta um modelo scikit-learn via skl2onnx."""
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    initial_types = [(INPUT_NAME, FloatTensorType([None, n_features]))]
    options: dict[Any, Any] = {}
    if hasattr(model, "predict_proba"):
        # Sem isso o classificador devolve uma lista de dicionários em vez de um
        # tensor, e o onnxruntime perde a vetorização.
        options[id(model)] = {"zipmap": zipmap}

    onnx_model = convert_sklearn(
        model,
        initial_types=initial_types,
        options=options or None,
        target_opset=SKLEARN_TARGET_OPSET,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(onnx_model.SerializeToString())
    log.info("onnx.exported", model=type(model).__name__, path=str(path))
    return path


def verify_export(path: Path, sample: FloatArray) -> list[FloatArray]:
    """Roda o modelo exportado uma vez.

    Exportação que grava um arquivo mas produz um grafo inválido acontece, e o
    sintoma sem esta checagem seria o `detector` entrando em crash loop depois do
    deploy, não o treino falhando.
    """
    import onnxruntime as ort

    session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
    outputs = session.run(None, {INPUT_NAME: sample.astype(np.float32)})

    for output in outputs:
        array = np.asarray(output)
        if array.dtype.kind == "f" and not np.isfinite(array).all():
            raise ValueError(f"{path.name}: saída com NaN ou infinito na verificação")
    return [np.asarray(o) for o in outputs]
