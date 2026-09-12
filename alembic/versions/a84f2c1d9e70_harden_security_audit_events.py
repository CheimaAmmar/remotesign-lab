"""harden security audit events

Revision ID: a84f2c1d9e70
Revises: e74a1c6d902f
Create Date: 2026-09-11 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "a84f2c1d9e70"
down_revision: Union[str, Sequence[str], None] = "e74a1c6d902f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    columns = (
        sa.Column("category", sa.String(length=32), nullable=True),
        sa.Column("actor_type", sa.String(length=16), nullable=True),
        sa.Column("actor_id", sa.String(length=128), nullable=True),
        sa.Column("signature_request_id", sa.UUID(), nullable=True),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("correlation_id", sa.UUID(), nullable=True),
        sa.Column("http_method", sa.String(length=10), nullable=True),
        sa.Column("http_path", sa.String(length=255), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("event_hash", sa.String(length=64), nullable=True),
    )

    for column in columns:
        op.add_column("security_audit_events", column)

    op.create_foreign_key(
        "fk_security_audit_events_signature_request_id",
        "security_audit_events",
        "signature_requests",
        ["signature_request_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_check_constraint(
        "ck_security_audit_hash_pair",
        "security_audit_events",
        "(previous_hash IS NULL AND event_hash IS NULL) OR "
        "(previous_hash IS NOT NULL AND event_hash IS NOT NULL "
        "AND char_length(previous_hash) = 64 "
        "AND char_length(event_hash) = 64)",
    )

    for column in (
        "category",
        "actor_type",
        "signature_request_id",
        "correlation_id",
    ):
        op.create_index(
            f"ix_security_audit_events_{column}",
            "security_audit_events",
            [column],
            unique=False,
        )


def downgrade() -> None:
    for column in (
        "correlation_id",
        "signature_request_id",
        "actor_type",
        "category",
    ):
        op.drop_index(
            f"ix_security_audit_events_{column}",
            table_name="security_audit_events",
        )

    op.drop_constraint(
        "ck_security_audit_hash_pair",
        "security_audit_events",
        type_="check",
    )
    op.drop_constraint(
        "fk_security_audit_events_signature_request_id",
        "security_audit_events",
        type_="foreignkey",
    )

    for column in (
        "event_hash",
        "previous_hash",
        "details",
        "user_agent",
        "http_status",
        "http_path",
        "http_method",
        "correlation_id",
        "failure_code",
        "signature_request_id",
        "actor_id",
        "actor_type",
        "category",
    ):
        op.drop_column("security_audit_events", column)
