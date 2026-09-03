"""add signature request queue

Revision ID: 9c42f0b7a6d1
Revises: 6e154e02cecf
Create Date: 2026-09-01 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "9c42f0b7a6d1"
down_revision: Union[str, Sequence[str], None] = "6e154e02cecf"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


signature_request_status = postgresql.ENUM(
    "PENDING",
    "CLAIMED",
    "AUTHENTICATING",
    "AUTHENTICATED",
    "SIGNED",
    "FAILED",
    "EXPIRED",
    name="signature_request_status",
    create_type=False,
)


def upgrade() -> None:
    """Create the persistent device signature queue."""
    signature_request_status.create(
        op.get_bind(),
        checkfirst=True,
    )

    op.create_table(
        "signature_requests",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "owner_session_id",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("document_id", sa.UUID(), nullable=False),
        sa.Column(
            "document_hash",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "decision",
            sa.String(length=20),
            server_default="APPROVE",
            nullable=False,
        ),
        sa.Column(
            "status",
            signature_request_status,
            server_default="PENDING",
            nullable=False,
        ),
        sa.Column(
            "authentication_session_id",
            sa.UUID(),
            nullable=True,
        ),
        sa.Column("signature_id", sa.UUID(), nullable=True),
        sa.Column(
            "failure_detail",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "claimed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "authentication_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "authenticated_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "char_length(document_hash) = 64",
            name="ck_signature_request_document_hash_length",
        ),
        sa.CheckConstraint(
            "decision = 'APPROVE'",
            name="ck_signature_request_decision",
        ),
        sa.ForeignKeyConstraint(
            ["authentication_session_id"],
            ["authentication_sessions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["documents.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["signature_id"],
            ["document_signatures.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "authentication_session_id",
            name="uq_signature_request_authentication_session",
        ),
        sa.UniqueConstraint(
            "signature_id",
            name="uq_signature_request_signature",
        ),
    )
    op.create_index(
        "ix_signature_requests_device_status_created_at",
        "signature_requests",
        ["device_id", "status", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_signature_requests_document_id",
        "signature_requests",
        ["document_id"],
        unique=False,
    )
    op.create_index(
        "ix_signature_requests_status_expires_at",
        "signature_requests",
        ["status", "expires_at"],
        unique=False,
    )


def downgrade() -> None:
    """Remove the persistent device signature queue."""
    op.drop_index(
        "ix_signature_requests_status_expires_at",
        table_name="signature_requests",
    )
    op.drop_index(
        "ix_signature_requests_document_id",
        table_name="signature_requests",
    )
    op.drop_index(
        "ix_signature_requests_device_status_created_at",
        table_name="signature_requests",
    )
    op.drop_table("signature_requests")
    signature_request_status.drop(
        op.get_bind(),
        checkfirst=True,
    )
