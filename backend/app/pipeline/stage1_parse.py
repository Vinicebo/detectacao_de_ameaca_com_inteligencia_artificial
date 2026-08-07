"""Stage 1 — parse nginx access log lines into structured entries.

Formato ``combined``, que é o default do nginx::

    $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
    "$http_referer" "$http_user_agent"

O parser é deliberadamente tolerante. A entrada é controlada por atacante em boa
parte — a linha do request vem do cliente — então linha malformada é rotina, não
exceção. Nada aqui pode levantar exceção para fora: uma linha ruim vira ``None`` e
incrementa um contador.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Final

from app.logging_setup import get_logger
from app.pipeline.types import LogEntry

log = get_logger(__name__)

# Aspas dentro dos campos entre aspas vêm escapadas pelo nginx (\" ou \x22), então
# (?:[^"\\]|\\.)* casa o conteúdo sem parar na primeira aspa escapada.
_QUOTED: Final[str] = r'(?:[^"\\]|\\.)*'

_COMBINED: Final[re.Pattern[str]] = re.compile(
    r"^(?P<remote_addr>\S+)"
    r"\s+(?P<ident>\S+)"
    r"\s+(?P<user>\S+)"
    r"\s+\[(?P<time>[^\]]+)\]"
    rf'\s+"(?P<request>{_QUOTED})"'
    r"\s+(?P<status>\d{3})"
    r"\s+(?P<bytes>\d+|-)"
    rf'(?:\s+"(?P<referer>{_QUOTED})")?'
    rf'(?:\s+"(?P<agent>{_QUOTED})")?'
)

# "GET /path?q=1 HTTP/1.1" — mas o cliente manda o que quiser aqui.
_REQUEST: Final[re.Pattern[str]] = re.compile(
    r"^(?P<method>[A-Za-z_-]{1,20})\s+(?P<uri>\S*)(?:\s+(?P<protocol>HTTP/[\d.]+))?\s*$"
)

# Mapa manual em vez de %b no strptime: %b depende do locale do processo, e um
# container com LANG diferente quebraria o parse de toda linha de log.
_MONTHS: Final[dict[str, int]] = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

_TIME: Final[re.Pattern[str]] = re.compile(
    r"^(?P<day>\d{2})/(?P<mon>\w{3})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"\s*(?P<tz>[+-]\d{4})?$"
)

# Uma linha de log de verdade não passa disso. Acima do limite é tentativa de
# estourar memória ou de afogar o regex, e cortamos antes de qualquer processamento.
MAX_LINE_LENGTH: Final[int] = 8192


class ParseStats:
    """Contadores expostos em /stats."""

    __slots__ = ("malformed", "parsed", "truncated")

    def __init__(self) -> None:
        self.parsed = 0
        self.malformed = 0
        self.truncated = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "parsed": self.parsed,
            "malformed": self.malformed,
            "truncated": self.truncated,
        }


def parse_timestamp(value: str) -> datetime | None:
    match = _TIME.match(value.strip())
    if match is None:
        return None
    month = _MONTHS.get(match["mon"])
    if month is None:
        return None
    try:
        tz = UTC
        if match["tz"]:
            sign = 1 if match["tz"][0] == "+" else -1
            offset = timedelta(hours=int(match["tz"][1:3]), minutes=int(match["tz"][3:5]))
            tz = timezone(sign * offset)
        return datetime(
            year=int(match["year"]),
            month=month,
            day=int(match["day"]),
            hour=int(match["hour"]),
            minute=int(match["minute"]),
            second=int(match["second"]),
            tzinfo=tz,
        )
    except ValueError:
        # Data impossível (31/Feb, hora 25). Cliente não controla isto, mas log
        # corrompido acontece.
        return None


def _split_uri(uri: str) -> tuple[str, str]:
    path, sep, query = uri.partition("?")
    return path, query if sep else ""


def _unescape(value: str) -> str:
    """Desfaz o escape do nginx nos campos entre aspas.

    O nginx escreve `"` como `\\x22` e `\\` como `\\\\`. Sem desfazer, um payload
    de XSS com aspas chegaria ao motor de regras deformado e escaparia do match.
    """
    if "\\" not in value:
        return value
    return (
        value.replace('\\"', '"').replace("\\x22", '"').replace("\\x5C", "\\").replace("\\\\", "\\")
    )


def parse_line(line: str, stats: ParseStats | None = None) -> LogEntry | None:
    """Converte uma linha de log em ``LogEntry``, ou ``None`` se não der.

    Nunca levanta exceção: o estágio não pode morrer por causa de uma linha.
    """
    line = line.strip()
    if not line:
        return None

    if len(line) > MAX_LINE_LENGTH:
        line = line[:MAX_LINE_LENGTH]
        if stats:
            stats.truncated += 1

    try:
        match = _COMBINED.match(line)
        if match is None:
            if stats:
                stats.malformed += 1
            return None

        ts = parse_timestamp(match["time"])
        if ts is None:
            if stats:
                stats.malformed += 1
            return None

        raw_request = _unescape(match["request"] or "")
        request_match = _REQUEST.match(raw_request)
        if request_match is not None:
            method = request_match["method"].upper()
            path, query = _split_uri(request_match["uri"] or "/")
            protocol = request_match["protocol"] or "HTTP/1.0"
        else:
            # Request malformado é sinal por si só — scanner mandando lixo, tentativa
            # de request smuggling. Guardamos como está para as regras avaliarem, em
            # vez de descartar a linha.
            method = "INVALID"
            path = raw_request[:2048]
            query = ""
            protocol = "INVALID"

        byte_field = match["bytes"]
        entry = LogEntry(
            ts=ts,
            remote_addr=match["remote_addr"][:45],
            method=method[:10],
            path=path,
            query=query,
            protocol=protocol[:16],
            status=int(match["status"]),
            bytes_sent=int(byte_field) if byte_field != "-" else 0,
            referer=_unescape(match["referer"] or ""),
            user_agent=_unescape(match["agent"] or ""),
            raw=line,
        )
    except Exception as exc:
        # Rede de segurança. Se cair aqui é bug nosso, não linha ruim — por isso loga.
        if stats:
            stats.malformed += 1
        log.warning("parse.unexpected_error", error=str(exc), line=line[:200])
        return None

    if stats:
        stats.parsed += 1
    return entry
