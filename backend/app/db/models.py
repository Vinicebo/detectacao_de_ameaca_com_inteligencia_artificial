"""SQLAlchemy ORM models."""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


# StrEnum e não `(str, Enum)`: com o segundo, um f-string renderiza
# "Severity.HIGH" em vez de "HIGH", o que já vazou para log e resposta de API em
# projetos assim mais de uma vez.
class Severity(enum.StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class TrainingSource(enum.StrEnum):
    SYNTHETIC = "synthetic"
    REAL = "real"
    MIXED = "mixed"


# native_enum=False guarda como VARCHAR + CHECK. Um tipo ENUM nativo do Postgres
# exigiria ALTER TYPE a cada valor novo, o que é doloroso em migração.
SeverityType = Enum(
    Severity, native_enum=False, length=16, values_callable=lambda e: [m.value for m in e]
)
TrainingSourceType = Enum(
    TrainingSource, native_enum=False, length=16, values_callable=lambda e: [m.value for m in e]
)


class ThreatEvent(Base):
    """Uma requisição HTTP pontuada.

    Guardamos o vetor de features junto com o evento: sem ele, o retreino a partir
    de dados reais teria de reprocessar os logs crus, que já rotacionaram.
    """

    __tablename__ = "threat_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # Horário do log, não da ingestão — podem divergir bastante depois de um backlog.
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # ------------------------------------------------------------ requisição
    remote_addr: Mapped[str] = mapped_column(String(45), nullable=False)  # cabe IPv6
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    query: Mapped[str | None] = mapped_column(Text)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, default="HTTP/1.1")
    status: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    bytes_sent: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    referer: Mapped[str | None] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(Text)

    # ------------------------------------------------------------ enriquecimento
    country: Mapped[str | None] = mapped_column(String(2))
    asn: Mapped[int | None] = mapped_column(Integer)

    # ------------------------------------------------------------ pontuação
    rule_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    ml_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    threat_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    severity: Mapped[Severity] = mapped_column(SeverityType, nullable=False)

    # Denormalizado a partir de matched_rules para dar índice GIN ao filtro por categoria.
    categories: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'::text[]")
    )
    matched_rules: Mapped[list[dict[str, object]]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )

    # ARRAY(Float) em vez de JSONB: lê direto para numpy no retreino, sem parse.
    features: Mapped[list[float] | None] = mapped_column(ARRAY(Float))
    model_version: Mapped[str | None] = mapped_column(String(64))

    # ------------------------------------------------------------ revisão humana
    reviewed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # True = ataque confirmado, False = falso positivo, NULL = ainda não revisado.
    review_label: Mapped[bool | None] = mapped_column(Boolean)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        # A listagem padrão é "mais recentes primeiro", com e sem filtro de severidade.
        Index("ix_threat_events_ts", text("ts DESC")),
        Index("ix_threat_events_severity_ts", "severity", text("ts DESC")),
        Index("ix_threat_events_remote_addr", "remote_addr"),
        Index("ix_threat_events_categories", "categories", postgresql_using="gin"),
        # Parcial: a fila de triagem só olha o que ainda não foi revisado, e isso é
        # uma fração minúscula da tabela.
        Index(
            "ix_threat_events_unreviewed",
            text("ts DESC"),
            postgresql_where=text("reviewed = false AND severity IN ('HIGH', 'MEDIUM')"),
        ),
        CheckConstraint("threat_score >= 0 AND threat_score <= 1", name="ck_threat_score_range"),
        CheckConstraint("rule_score >= 0 AND rule_score <= 1", name="ck_rule_score_range"),
        CheckConstraint("ml_score >= 0 AND ml_score <= 1", name="ck_ml_score_range"),
        # Um evento marcado como revisado sem rótulo não serve para treinar.
        CheckConstraint(
            "(reviewed = false AND review_label IS NULL) OR "
            "(reviewed = true AND review_label IS NOT NULL)",
            name="ck_review_consistency",
        ),
    )


class ModelVersion(Base):
    """Uma tentativa de treino, promovida ou reprovada.

    Reprovações também ficam registradas: sem elas não dá para explicar por que a
    versão ativa continua sendo a antiga.
    """

    __tablename__ = "model_versions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    promoted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Motivo da reprovação nos portões de qualidade, quando houver.
    rejection_reason: Mapped[str | None] = mapped_column(Text)

    metrics: Mapped[dict[str, float]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    artifact_paths: Mapped[dict[str, str]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    training_source: Mapped[TrainingSource] = mapped_column(TrainingSourceType, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        # Só pode haver uma versão ativa. Garantido pelo banco, não por convenção:
        # duas ativas fariam a inferência escolher modelo por sorte.
        Index(
            "uq_model_versions_single_active",
            "is_active",
            unique=True,
            postgresql_where=text("is_active"),
        ),
    )


class IngestCheckpoint(Base):
    """Posição de leitura por arquivo de log, para retomar após restart.

    Sem isso, todo restart reprocessaria o arquivo inteiro e duplicaria eventos.
    """

    __tablename__ = "ingest_checkpoints"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    file_path: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    # Detecta rotação: mesmo caminho, inode novo = arquivo novo, offset zera.
    inode: Mapped[int] = mapped_column(BigInteger, nullable=False)
    byte_offset: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
