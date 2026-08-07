"""Typed numpy array aliases.

O mypy em modo estrito recusa ``np.ndarray`` sem parâmetros de tipo, e com razão:
`ndarray` sozinho não diz nada. Mas anotar cada uso com
``np.ndarray[Any, np.dtype[np.float32]]`` polui a assinatura e esconde o que
importa.

Os dois aliases abaixo carregam a distinção que de fato importa neste código:
matriz de features (contínua) versus vetor de rótulos (inteiro). Confundir os dois
é um erro real — já aconteceu de um `y` ser passado onde se esperava `X`.
"""

from __future__ import annotations

from typing import Any

import numpy.typing as npt

# Matriz de features (n, 35) ou vetor de escores contínuos.
type FloatArray = npt.NDArray[Any]

# Vetor de rótulos binários: 0 = benigno, 1 = ataque.
type LabelArray = npt.NDArray[Any]

__all__ = ["FloatArray", "LabelArray"]
