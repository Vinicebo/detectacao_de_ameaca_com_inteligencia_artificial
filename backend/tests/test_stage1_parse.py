"""Parser tests.

A linha do request é controlada pelo cliente, então boa parte destes testes é
sobre entrada hostil ou malformada. O critério é sempre o mesmo: não levantar
exceção, e não perder informação que as regras vão precisar.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from app.pipeline.stage1_parse import MAX_LINE_LENGTH, ParseStats, parse_line, parse_timestamp

# --------------------------------------------------------------------------
# Linhas golden — formato combined real do nginx
# --------------------------------------------------------------------------

BENIGN = (
    '203.0.113.42 - - [06/Aug/2026:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 4821 '
    '"https://exemplo.com/" "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0.0.0"'
)

SQLI = (
    "198.51.100.7 - - [06/Aug/2026:14:31:12 -0300] "
    '"GET /produto?id=1%27%20UNION%20SELECT%20NULL,version()--%20 HTTP/1.1" 500 0 '
    '"-" "sqlmap/1.8#stable (https://sqlmap.org)"'
)

NO_REFERER_NO_AGENT = '10.0.0.1 - - [06/Aug/2026:00:00:01 +0000] "HEAD / HTTP/1.0" 301 0'


def test_parses_benign_line() -> None:
    entry = parse_line(BENIGN)
    assert entry is not None
    assert entry.remote_addr == "203.0.113.42"
    assert entry.method == "GET"
    assert entry.path == "/index.html"
    assert entry.query == ""
    assert entry.protocol == "HTTP/1.1"
    assert entry.status == 200
    assert entry.bytes_sent == 4821
    assert entry.referer == "https://exemplo.com/"
    assert "Chrome" in entry.user_agent
    assert entry.ts == datetime(2026, 8, 6, 14, 30, 0, tzinfo=UTC)


def test_splits_path_and_query() -> None:
    entry = parse_line(SQLI)
    assert entry is not None
    assert entry.path == "/produto"
    # O parser não decodifica: quem decodifica é o estágio 2, em duas passadas.
    # Guardar o texto cru preserva a evidência da codificação usada.
    assert entry.query == "id=1%27%20UNION%20SELECT%20NULL,version()--%20"
    assert entry.full_uri.startswith("/produto?id=")


def test_honours_timezone_offset() -> None:
    entry = parse_line(SQLI)
    assert entry is not None
    assert entry.ts.utcoffset() == timedelta(hours=-3)
    # Comparação entre timezones diferentes precisa bater no instante absoluto.
    assert entry.ts == datetime(2026, 8, 6, 17, 31, 12, tzinfo=UTC)


def test_optional_referer_and_agent() -> None:
    entry = parse_line(NO_REFERER_NO_AGENT)
    assert entry is not None
    assert entry.referer == ""
    assert entry.user_agent == ""
    assert entry.status == 301


def test_dash_bytes_becomes_zero() -> None:
    line = '10.0.0.1 - - [06/Aug/2026:00:00:01 +0000] "GET / HTTP/1.1" 304 - "-" "-"'
    entry = parse_line(line)
    assert entry is not None
    assert entry.bytes_sent == 0


def test_ipv6_address() -> None:
    line = (
        "2001:db8:85a3::8a2e:370:7334 - - [06/Aug/2026:00:00:01 +0000] "
        '"GET / HTTP/1.1" 200 100 "-" "-"'
    )
    entry = parse_line(line)
    assert entry is not None
    assert entry.remote_addr == "2001:db8:85a3::8a2e:370:7334"


# --------------------------------------------------------------------------
# Entrada hostil
# --------------------------------------------------------------------------


def test_escaped_quotes_in_user_agent() -> None:
    """Aspas escapadas não podem truncar o campo.

    Se o unescape falhasse, um payload de XSS com aspas chegaria deformado ao
    motor de regras e escaparia do match — que é exatamente o objetivo de quem
    injeta a aspa.
    """
    line = (
        '10.0.0.1 - - [06/Aug/2026:00:00:01 +0000] "GET / HTTP/1.1" 200 100 '
        '"-" "Mozilla/5.0 \\x22onload=alert(1)\\x22 rest"'
    )
    entry = parse_line(line)
    assert entry is not None
    assert entry.user_agent == 'Mozilla/5.0 "onload=alert(1)" rest'


def test_malformed_request_line_is_preserved_not_dropped() -> None:
    """Request sem verbo/protocolo é sinal, não lixo.

    Scanner mandando bytes crus e tentativa de request smuggling aparecem assim.
    Descartar a linha apagaria justamente o evento que interessa.
    """
    line = (
        "10.0.0.1 - - [06/Aug/2026:00:00:01 +0000] "
        '"\\x16\\x03\\x01\\x02\\x00\\x01\\x00" 400 150 "-" "-"'
    )
    entry = parse_line(line)
    assert entry is not None
    assert entry.method == "INVALID"
    assert entry.protocol == "INVALID"
    assert entry.status == 400


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "linha totalmente aleatória sem estrutura nenhuma",
        '10.0.0.1 - - [data-invalida] "GET / HTTP/1.1" 200 100 "-" "-"',
        '10.0.0.1 - - [06/Aug/2026:00:00:01 +0000] "GET / HTTP/1.1" 20 100 "-" "-"',  # status curto
        '10.0.0.1 - - [32/Aug/2026:00:00:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-"',  # dia 32
        '10.0.0.1 - - [06/Xyz/2026:00:00:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-"',  # mês inv.
        "\x00\x01\x02\x03",
    ],
)
def test_malformed_lines_return_none_without_raising(line: str) -> None:
    stats = ParseStats()
    assert parse_line(line, stats) is None


def test_overlong_line_is_truncated_not_rejected() -> None:
    """Linha gigante é cortada, não descartada.

    O começo da linha ainda traz IP, horário e o início da URI — informação
    suficiente para pontuar. E o corte acontece antes do regex, então uma URI de
    vários megabytes não vira custo de CPU.
    """
    huge_path = "/a" * MAX_LINE_LENGTH
    line = f'10.0.0.1 - - [06/Aug/2026:00:00:01 +0000] "GET {huge_path} HTTP/1.1" 200 100 "-" "-"'
    stats = ParseStats()
    parse_line(line, stats)
    assert stats.truncated == 1


def test_stats_are_counted() -> None:
    stats = ParseStats()
    parse_line(BENIGN, stats)
    parse_line(SQLI, stats)
    parse_line("lixo", stats)
    assert stats.parsed == 2
    assert stats.malformed == 1
    assert stats.as_dict()["parsed"] == 2


# --------------------------------------------------------------------------
# Timestamp
# --------------------------------------------------------------------------


def test_timestamp_without_offset_assumes_utc() -> None:
    ts = parse_timestamp("06/Aug/2026:14:30:00")
    assert ts == datetime(2026, 8, 6, 14, 30, 0, tzinfo=UTC)


def test_timestamp_positive_offset() -> None:
    ts = parse_timestamp("06/Aug/2026:14:30:00 +0530")
    assert ts is not None
    assert ts.utcoffset() == timedelta(hours=5, minutes=30)


def test_month_parsing_is_locale_independent() -> None:
    """Os meses vêm de um mapa nosso, não de %b.

    %b usa o locale do processo: um container com LANG=pt_BR não reconheceria
    "Aug" e todo parse de log falharia — em produção, silenciosamente.
    """
    for index, month in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    ):
        ts = parse_timestamp(f"15/{month}/2026:12:00:00 +0000")
        assert ts is not None and ts.month == index


def test_timestamp_negative_offset_sign() -> None:
    ts = parse_timestamp("06/Aug/2026:00:00:00 -0800")
    assert ts is not None
    assert ts.utcoffset() == timedelta(hours=-8)
    assert ts.tzinfo == timezone(timedelta(hours=-8))
