"""add PAdES timestamp metadata

Revision ID: e74a1c6d902f
Revises: c31d7e9f4b22
Create Date: 2026-09-05 16:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e74a1c6d902f"
down_revision: Union[str, Sequence[str], None] = "c31d7e9f4b22"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "document_signatures",
        sa.Column(
            "timestamp_time",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "document_signatures",
        sa.Column(
            "tsa_certificate_subject",
            sa.String(length=512),
            nullable=True,
        ),
    )
    op.add_column(
        "document_signatures",
        sa.Column(
            "tsa_certificate_fingerprint_sha256",
            sa.String(length=64),
            nullable=True,
        ),
    )
    op.create_check_constraint(
        "ck_document_signature_tsa_certificate_fingerprint_length",
        "document_signatures",
        (
            "tsa_certificate_fingerprint_sha256 IS NULL OR "
            "char_length(tsa_certificate_fingerprint_sha256) = 64"
        ),
    )
    op.create_check_constraint(
        "ck_document_signature_tsa_metadata_complete",
        "document_signatures",
        (
            "(timestamp_time IS NULL AND "
            "tsa_certificate_subject IS NULL AND "
            "tsa_certificate_fingerprint_sha256 IS NULL) OR "
            "(timestamp_time IS NOT NULL AND "
            "tsa_certificate_subject IS NOT NULL AND "
            "tsa_certificate_fingerprint_sha256 IS NOT NULL AND "
            "pades_profile = 'PAdES-B-T')"
        ),
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_document_signature_tsa_metadata_complete",
        "document_signatures",
        type_="check",
    )
    op.drop_constraint(
        "ck_document_signature_tsa_certificate_fingerprint_length",
        "document_signatures",
        type_="check",
    )
    op.drop_column(
        "document_signatures",
        "tsa_certificate_fingerprint_sha256",
    )
    op.drop_column(
        "document_signatures",
        "tsa_certificate_subject",
    )
    op.drop_column("document_signatures", "timestamp_time")
