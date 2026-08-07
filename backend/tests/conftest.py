"""Shared test fixtures."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.pipeline.types import LogEntry


@pytest.fixture
def benign_entry() -> LogEntry:
    return LogEntry(
        ts=datetime(2026, 8, 6, 14, 30, 0, tzinfo=UTC),
        remote_addr="203.0.113.42",
        method="GET",
        path="/produtos/categoria/eletronicos",
        query="pagina=2&ordenar=preco",
        protocol="HTTP/1.1",
        status=200,
        bytes_sent=4821,
        referer="https://loja.exemplo.com/",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        raw="",
    )


def make_entry(**overrides: object) -> LogEntry:
    """Constrói um LogEntry com defaults benignos, sobrescrevendo o que interessa."""
    defaults: dict[str, object] = {
        "ts": datetime(2026, 8, 6, 14, 30, 0, tzinfo=UTC),
        "remote_addr": "203.0.113.42",
        "method": "GET",
        "path": "/index.html",
        "query": "",
        "protocol": "HTTP/1.1",
        "status": 200,
        "bytes_sent": 1024,
        "referer": "",
        "user_agent": "Mozilla/5.0",
        "raw": "",
    }
    defaults.update(overrides)
    return LogEntry(**defaults)  # type: ignore[arg-type]
