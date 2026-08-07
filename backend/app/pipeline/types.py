"""Data carried between pipeline stages.

Cada estágio recebe o tipo do anterior e produz o próximo. Dataclasses com
``slots=True`` porque isso passa por aqui dezenas de milhares de vezes por minuto
e o dicionário por instância pesa.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from app.db.models import Severity


@dataclass(slots=True, frozen=True)
class LogEntry:
    """Estágio 1 — uma linha de log do nginx já estruturada."""

    ts: datetime
    remote_addr: str
    method: str
    path: str
    query: str
    protocol: str
    status: int
    bytes_sent: int
    referer: str
    user_agent: str
    raw: str

    @property
    def full_uri(self) -> str:
        return f"{self.path}?{self.query}" if self.query else self.path


@dataclass(slots=True)
class FeaturedEntry:
    """Estágio 2 — entrada + vetor de 35 dimensões + enriquecimento."""

    entry: LogEntry
    features: list[float]
    country: str | None = None
    asn: int | None = None


@dataclass(slots=True)
class RuleMatch:
    rule_id: str
    category: str
    severity: str
    score: float
    description: str
    matched_on: str


@dataclass(slots=True)
class ScoredEntry:
    """Estágio 3 — pronto para persistir e alertar."""

    featured: FeaturedEntry
    rule_score: float
    ml_score: float
    threat_score: float
    severity: Severity
    matched_rules: list[RuleMatch] = field(default_factory=list)
    model_version: str | None = None

    @property
    def categories(self) -> list[str]:
        # dict.fromkeys em vez de set: preserva a ordem de detecção, o que deixa
        # o campo estável entre execuções e mais fácil de ler no dashboard.
        return list(dict.fromkeys(m.category for m in self.matched_rules))
