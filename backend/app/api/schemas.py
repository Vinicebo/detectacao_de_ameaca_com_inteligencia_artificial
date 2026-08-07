"""Pydantic schemas for the API surface.

Estes modelos são o contrato público: o OpenAPI sai daqui e os tipos do frontend
são gerados a partir dele. Alterar um campo aqui quebra o dashboard, então cada um
existe por um motivo declarado.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import Severity


class RuleMatchOut(BaseModel):
    """Uma regra que casou. É o que torna o alerta revisável por uma pessoa."""

    rule_id: str
    category: str
    severity: str
    score: float
    description: str
    matched_on: str = Field(description="Alvo e trecho exato que casou, truncado")


class ThreatEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    ingested_at: datetime
    remote_addr: str
    method: str
    path: str
    query: str | None
    protocol: str
    status: int
    bytes_sent: int
    referer: str | None
    user_agent: str | None
    country: str | None
    asn: int | None
    rule_score: float
    ml_score: float
    threat_score: float
    severity: Severity
    categories: list[str]
    matched_rules: list[dict[str, Any]]
    model_version: str | None
    reviewed: bool
    review_label: bool | None
    reviewed_at: datetime | None


class ThreatEventSummary(BaseModel):
    """Versão enxuta para listagem.

    A tabela do dashboard pagina 50 eventos por vez; mandar o vetor de 35 features
    e as regras completas em cada linha seria dezenas de vezes mais tráfego para
    dado que só aparece quando o analista abre o detalhe.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    remote_addr: str
    method: str
    path: str
    status: int
    country: str | None
    threat_score: float
    severity: Severity
    categories: list[str]
    reviewed: bool
    review_label: bool | None


class ThreatPage(BaseModel):
    """Paginação por cursor, não por offset.

    Com OFFSET, o banco varre e descarta as linhas puladas — na página 500 de uma
    tabela que recebe escrita contínua isso fica caro e ainda pula ou repete
    eventos quando algo é inserido entre duas requisições.
    """

    items: list[ThreatEventSummary]
    next_cursor: str | None = Field(
        default=None, description="Passe em `cursor` para a próxima página; null no fim"
    )
    has_more: bool


class SeverityCount(BaseModel):
    severity: Severity
    count: int


class CategoryCount(BaseModel):
    category: str
    count: int


class TimeBucket(BaseModel):
    bucket: datetime
    total: int
    high: int
    medium: int
    low: int


class QueueStats(BaseModel):
    depth: int
    enqueued: int
    dropped: int


class PipelineHealth(BaseModel):
    """Saúde do pipeline de ingestão.

    `dropped` é o campo que importa: sob flood as filas descartam o item mais
    antigo, e perda silenciosa num sistema de segurança é pior que perda nenhuma.
    """

    queues: dict[str, QueueStats]
    parse: dict[str, int]
    events_persisted: int
    alerts_published: int


class StatsOut(BaseModel):
    total_events: int
    events_last_24h: int
    unique_attackers_24h: int
    by_severity: list[SeverityCount]
    by_category: list[CategoryCount]
    timeline: list[TimeBucket]
    top_attackers: list[dict[str, Any]]
    pending_review: int


class ModelMetrics(BaseModel):
    f1: float | None = None
    pr_auc: float | None = None
    precision: float | None = None
    recall: float | None = None
    false_positive_rate: float | None = None


class ModelVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    version: str
    created_at: datetime
    is_active: bool
    promoted: bool
    rejection_reason: str | None
    metrics: dict[str, float]
    training_source: str
    sample_count: int


class ModelStatusOut(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    detection_mode: Literal["ensemble", "rules_only"] = Field(
        description="`rules_only` significa que os modelos não carregaram — degradado, não parado"
    )
    active_version: ModelVersionOut | None
    history: list[ModelVersionOut]
    artifacts_present: bool
    rule_count: int
    ensemble_weights: dict[str, float]
    thresholds: dict[str, float]


class RetrainRequest(BaseModel):
    use_real_data: bool = Field(
        default=True,
        description="Usa eventos armazenados; completa com sintético se faltar volume",
    )


class RetrainResponse(BaseModel):
    job_id: str
    status: Literal["started", "already_running"]
    message: str


class ReviewRequest(BaseModel):
    """Rótulo humano — a entrada mais valiosa do sistema.

    É o que transforma o retreino de "aprender com os próprios palpites" em
    aprendizado supervisionado de verdade.
    """

    is_attack: bool = Field(description="true = ataque confirmado, false = falso positivo")


class IngestBatchRequest(BaseModel):
    lines: list[str] = Field(min_length=1, max_length=1000)


class IngestBatchResponse(BaseModel):
    accepted: int
    parsed: int
    malformed: int


class AlertOut(BaseModel):
    """Payload enviado pelo WebSocket."""

    model_config = ConfigDict(protected_namespaces=())

    id: int | None = None
    ts: datetime
    remote_addr: str
    method: str
    path: str
    query: str | None
    status: int
    country: str | None
    user_agent: str | None
    rule_score: float
    ml_score: float
    threat_score: float
    severity: Severity
    categories: list[str]
    matched_rules: list[RuleMatchOut]
    model_version: str | None
    recommend_block: bool = Field(
        description="Recomendação, não ação — este sistema observa, não bloqueia"
    )


class WSMessage(BaseModel):
    type: Literal["auth_ok", "auth_error", "alert", "snapshot", "pong", "error"]
    data: Any = None
