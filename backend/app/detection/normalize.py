"""Request normalization applied before rule matching.

É aqui que se ganha ou se perde contra evasão. Um filtro que casa
``UNION SELECT`` no texto cru é contornado em segundos::

    UNION/**/SELECT          comentário no lugar do espaço
    %55NION %53ELECT         percent-encoding parcial
    %2555NION                codificação dupla
    UNION%09SELECT           tab em vez de espaço
    UnIoN sElEcT             variação de caixa

Todos viram a mesma coisa depois de normalizar. O custo é falso positivo: quanto
mais agressiva a normalização, mais tráfego legítimo passa a parecer ataque — por
isso as regras casam contra **duas** visões, e a mais agressiva (sem comentários)
só existe para as categorias em que comentário é evasão conhecida.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final
from urllib.parse import unquote_plus

# Comentários de SQL e C, usados para partir palavras-chave ao meio.
_COMMENTS: re.Pattern[str] = re.compile(r"/\*.*?\*/", re.DOTALL)
# Espaços unicode que substituem o espaço comum em payloads de evasão, escritos
# como CODEPOINTS e não como caractere.
#
# Duas formas mais óbvias falham: caractere literal é invisível no editor
# (ninguém revisando este arquivo saberia o que há aqui), e escape \uXXXX é
# reconvertido em literal pelo `ruff format`. Inteiro nenhum formatador mexe, e
# ainda documenta o que cada faixa cobre.
_UNICODE_SPACE_RANGES: Final[tuple[tuple[int, int], ...]] = (
    (0x00A0, 0x00A0),  # no-break space
    (0x1680, 0x1680),  # ogham space mark
    (0x2000, 0x200A),  # en quad ate hair space
    (0x2028, 0x2029),  # line separator, paragraph separator
    (0x202F, 0x202F),  # narrow no-break space
    (0x205F, 0x205F),  # medium mathematical space
    (0x3000, 0x3000),  # ideographic space
)
_UNICODE_SPACES: Final[str] = "".join(
    chr(codepoint) for first, last in _UNICODE_SPACE_RANGES for codepoint in range(first, last + 1)
)
_WHITESPACE: re.Pattern[str] = re.compile(rf"[\s{re.escape(_UNICODE_SPACES)}]+")

_NULL_BYTES: re.Pattern[str] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Teto por campo. Regex sobre megabytes de texto é um vetor de negação de serviço
# contra o próprio detector.
MAX_FIELD_LENGTH = 8192


def decode_percent(value: str, passes: int = 2) -> str:
    """Decodifica percent-encoding repetidamente.

    Duas passadas por padrão: cobre ``%2527`` → ``%27`` → ``'``. Mais que isso dá
    retorno decrescente e abre espaço para gastar CPU à toa.
    """
    result = value
    for _ in range(passes):
        try:
            decoded = unquote_plus(result)
        except Exception:
            return result
        if decoded == result:
            break
        result = decoded
    return result


def normalize(value: str, *, strip_comments: bool = False) -> str:
    """Reduz um campo à forma canônica usada no match."""
    if not value:
        return ""

    text = value[:MAX_FIELD_LENGTH]
    text = decode_percent(text)
    # Byte nulo e caractere de controle são usados para partir palavra-chave.
    text = _NULL_BYTES.sub("", text)
    if strip_comments:
        text = _COMMENTS.sub(" ", text)
    # Tab, newline e espaços unicode substituem o espaço em muitos payloads.
    text = _WHITESPACE.sub(" ", text)
    return text.strip().lower()


@dataclass(slots=True, frozen=True)
class NormalizedRequest:
    """As visões normalizadas contra as quais as regras casam."""

    method: str
    path: str
    query: str
    uri: str
    user_agent: str
    referer: str
    # Mesma URI, sem comentários. Separada porque remover comentários de todo
    # tráfego geraria falso positivo em qualquer URL que contenha "/*".
    uri_decommented: str
    raw_path: str
    raw_query: str

    def field(self, target: str) -> str:
        return {
            "method": self.method,
            "path": self.path,
            "query": self.query,
            "uri": self.uri,
            "uri_decommented": self.uri_decommented,
            "user_agent": self.user_agent,
            "referer": self.referer,
            "raw_path": self.raw_path,
            "raw_query": self.raw_query,
        }.get(target, "")


def build(method: str, path: str, query: str, user_agent: str, referer: str) -> NormalizedRequest:
    norm_path = normalize(path)
    norm_query = normalize(query)
    uri = f"{norm_path}?{norm_query}" if norm_query else norm_path
    raw_uri = f"{path}?{query}" if query else path

    return NormalizedRequest(
        method=method.upper()[:16],
        path=norm_path,
        query=norm_query,
        uri=uri,
        user_agent=normalize(user_agent),
        referer=normalize(referer),
        uri_decommented=normalize(raw_uri, strip_comments=True),
        raw_path=path[:MAX_FIELD_LENGTH],
        raw_query=query[:MAX_FIELD_LENGTH],
    )
