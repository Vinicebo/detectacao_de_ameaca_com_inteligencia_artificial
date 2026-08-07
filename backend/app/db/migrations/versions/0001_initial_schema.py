"""Schema inicial: threat_events, model_versions, ingest_checkpoints

Revision ID: 0001
Revises:
Create Date: 2026-08-06
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SEVERITY_VALUES = ("HIGH", "MEDIUM", "LOW")
TRAINING_SOURCE_VALUES = ("synthetic", "real", "mixed")


def upgrade() -> None:
    op.create_table(
        "threat_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("remote_addr", sa.String(length=45), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("query", sa.Text(), nullable=True),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("status", sa.SmallInteger(), nullable=False),
        sa.Column("bytes_sent", sa.BigInteger(), nullable=False),
        sa.Column("referer", sa.Text(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("country", sa.String(length=2), nullable=True),
        sa.Column("asn", sa.Integer(), nullable=True),
        sa.Column("rule_score", sa.Float(), nullable=False),
        sa.Column("ml_score", sa.Float(), nullable=False),
        sa.Column("threat_score", sa.Float(), nullable=False),
        sa.Column(
            "severity",
            sa.Enum(*SEVERITY_VALUES, name="severity", native_enum=False, length=16),
            nullable=False,
        ),
        sa.Column(
            "categories",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
        sa.Column(
            "matched_rules",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("features", postgresql.ARRAY(sa.Float()), nullable=True),
        sa.Column("model_version", sa.String(length=64), nullable=True),
        sa.Column("reviewed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("review_label", sa.Boolean(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("threat_score >= 0 AND threat_score <= 1", name="ck_threat_score_range"),
        sa.CheckConstraint("rule_score >= 0 AND rule_score <= 1", name="ck_rule_score_range"),
        sa.CheckConstraint("ml_score >= 0 AND ml_score <= 1", name="ck_ml_score_range"),
        sa.CheckConstraint(
            "(reviewed = false AND review_label IS NULL) OR "
            "(reviewed = true AND review_label IS NOT NULL)",
            name="ck_review_consistency",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_threat_events_ts", "threat_events", [sa.text("ts DESC")])
    op.create_index(
        "ix_threat_events_severity_ts", "threat_events", ["severity", sa.text("ts DESC")]
    )
    op.create_index("ix_threat_events_remote_addr", "threat_events", ["remote_addr"])
    op.create_index(
        "ix_threat_events_categories", "threat_events", ["categories"], postgresql_using="gin"
    )
    op.create_index(
        "ix_threat_events_unreviewed",
        "threat_events",
        [sa.text("ts DESC")],
        postgresql_where=sa.text("reviewed = false AND severity IN ('HIGH', 'MEDIUM')"),
    )

    op.create_table(
        "model_versions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("promoted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column(
            "metrics",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "artifact_paths",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "training_source",
            sa.Enum(*TRAINING_SOURCE_VALUES, name="trainingsource", native_enum=False, length=16),
            nullable=False,
        ),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("version"),
    )
    op.create_index(
        "uq_model_versions_single_active",
        "model_versions",
        ["is_active"],
        unique=True,
        postgresql_where=sa.text("is_active"),
    )

    op.create_table(
        "ingest_checkpoints",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("inode", sa.BigInteger(), nullable=False),
        sa.Column("byte_offset", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("file_path"),
    )


def downgrade() -> None:
    op.drop_table("ingest_checkpoints")
    op.drop_index("uq_model_versions_single_active", table_name="model_versions")
    op.drop_table("model_versions")
    for index in (
        "ix_threat_events_unreviewed",
        "ix_threat_events_categories",
        "ix_threat_events_remote_addr",
        "ix_threat_events_severity_ts",
        "ix_threat_events_ts",
    ):
        op.drop_index(index, table_name="threat_events")
    op.drop_table("threat_events")
