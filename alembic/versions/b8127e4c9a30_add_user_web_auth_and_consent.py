"""add user web authentication and consent ownership

Revision ID: b8127e4c9a30
Revises: 9c42f0b7a6d1
Create Date: 2026-09-03 19:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b8127e4c9a30"
down_revision: Union[str, Sequence[str], None] = "9c42f0b7a6d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("email", sa.String(length=320), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column(
            "password_hash",
            sa.String(length=255),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_users_email",
        "users",
        ["email"],
        unique=True,
    )

    op.add_column(
        "documents",
        sa.Column("user_id", sa.UUID(), nullable=True),
    )
    op.create_foreign_key(
        "fk_documents_user_id_users",
        "documents",
        "users",
        ["user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_documents_user_id",
        "documents",
        ["user_id"],
        unique=False,
    )

    op.add_column(
        "signature_requests",
        sa.Column("user_id", sa.UUID(), nullable=True),
    )
    op.add_column(
        "signature_requests",
        sa.Column(
            "consented_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "signature_requests",
        sa.Column(
            "consent_version",
            sa.String(length=64),
            nullable=True,
        ),
    )

    # The authentication session is the historical source of truth for
    # the user who actually completed strong authentication. Requests
    # without an authentication session intentionally remain unowned.
    op.execute(
        sa.text(
            """
            UPDATE signature_requests AS signature_request
            SET user_id = authentication_session.user_id
            FROM authentication_sessions AS authentication_session
            WHERE signature_request.authentication_session_id = authentication_session.id
              AND signature_request.user_id IS NULL
            """
        )
    )
    op.create_foreign_key(
        "fk_signature_requests_user_id_users",
        "signature_requests",
        "users",
        ["user_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_signature_requests_user_id",
        "signature_requests",
        ["user_id"],
        unique=False,
    )

    # Preserve ownership for documents already referenced by a request.
    op.execute(
        sa.text(
            """
            UPDATE documents AS document
            SET user_id = latest_request.user_id
            FROM (
                SELECT DISTINCT ON (document_id)
                    document_id,
                    user_id
                FROM signature_requests
                WHERE user_id IS NOT NULL
                ORDER BY document_id, created_at DESC, id DESC
            ) AS latest_request
            WHERE document.id = latest_request.document_id
              AND document.user_id IS NULL
            """
        )
    )


def downgrade() -> None:
    op.drop_index(
        "ix_signature_requests_user_id",
        table_name="signature_requests",
    )
    op.drop_constraint(
        "fk_signature_requests_user_id_users",
        "signature_requests",
        type_="foreignkey",
    )
    op.drop_column("signature_requests", "consent_version")
    op.drop_column("signature_requests", "consented_at")
    op.drop_column("signature_requests", "user_id")

    op.drop_index(
        "ix_documents_user_id",
        table_name="documents",
    )
    op.drop_constraint(
        "fk_documents_user_id_users",
        "documents",
        type_="foreignkey",
    )
    op.drop_column("documents", "user_id")

    op.drop_index("ix_users_email", table_name="users")
    op.drop_column("users", "password_hash")
    op.drop_column("users", "email")
