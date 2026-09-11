"""add PAdES signature metadata

Revision ID: c31d7e9f4b22
Revises: b8127e4c9a30
Create Date: 2026-09-05 13:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c31d7e9f4b22"
down_revision: Union[str, Sequence[str], None] = "b8127e4c9a30"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "document_signatures",
        sa.Column(
            "signed_document_path",
            sa.String(length=255),
            nullable=True,
        ),
    )
    op.add_column(
        "document_signatures",
        sa.Column(
            "pades_profile",
            sa.String(length=32),
            nullable=True,
        ),
    )
    op.add_column(
        "document_signatures",
        sa.Column(
            "certificate_fingerprint_sha256",
            sa.String(length=64),
            nullable=True,
        ),
    )
    op.add_column(
        "document_signatures",
        sa.Column(
            "certificate_subject",
            sa.String(length=512),
            nullable=True,
        ),
    )
    op.add_column(
        "document_signatures",
        sa.Column(
            "signing_time",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.create_unique_constraint(
        "uq_document_signatures_signed_document_path",
        "document_signatures",
        ["signed_document_path"],
    )
    op.create_check_constraint(
        "ck_document_signature_certificate_fingerprint_length",
        "document_signatures",
        (
            "certificate_fingerprint_sha256 IS NULL OR "
            "char_length(certificate_fingerprint_sha256) = 64"
        ),
    )
    op.create_check_constraint(
        "ck_document_signature_pades_metadata_complete",
        "document_signatures",
        (
            "(signed_document_path IS NULL AND "
            "pades_profile IS NULL AND "
            "certificate_fingerprint_sha256 IS NULL AND "
            "certificate_subject IS NULL AND signing_time IS NULL) "
            "OR (signed_document_path IS NOT NULL AND "
            "pades_profile IS NOT NULL AND "
            "certificate_fingerprint_sha256 IS NOT NULL AND "
            "certificate_subject IS NOT NULL AND signing_time IS NOT NULL)"
        ),
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_document_signature_pades_metadata_complete",
        "document_signatures",
        type_="check",
    )
    op.drop_constraint(
        "ck_document_signature_certificate_fingerprint_length",
        "document_signatures",
        type_="check",
    )
    op.drop_constraint(
        "uq_document_signatures_signed_document_path",
        "document_signatures",
        type_="unique",
    )
    op.drop_column("document_signatures", "signing_time")
    op.drop_column(
        "document_signatures",
        "certificate_subject",
    )
    op.drop_column(
        "document_signatures",
        "certificate_fingerprint_sha256",
    )
    op.drop_column("document_signatures", "pades_profile")
    op.drop_column(
        "document_signatures",
        "signed_document_path",
    )
