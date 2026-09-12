import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    JSON,
    Text,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class UserStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class DeviceStatus(str, enum.Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class SignatureRequestStatus(str, enum.Enum):
    PENDING = "PENDING"
    CLAIMED = "CLAIMED"
    AUTHENTICATING = "AUTHENTICATING"
    AUTHENTICATED = "AUTHENTICATED"
    SIGNED = "SIGNED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    username: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    full_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    email: Mapped[str | None] = mapped_column(
        String(320),
        unique=True,
        nullable=True,
        index=True,
    )

    password_hash: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    status: Mapped[UserStatus] = mapped_column(
        Enum(
            UserStatus,
            name="user_status",
            native_enum=True,
        ),
        nullable=False,
        default=UserStatus.ACTIVE,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    devices: Mapped[list["Device"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )

    documents: Mapped[list["Document"]] = relationship(
        back_populates="user",
    )

    signature_requests: Mapped[
        list["SignatureRequest"]
    ] = relationship(
        back_populates="user",
    )


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    device_uid: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    display_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    device_secret: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    status: Mapped[DeviceStatus] = mapped_column(
        Enum(
            DeviceStatus,
            name="device_status",
            native_enum=True,
        ),
        nullable=False,
        default=DeviceStatus.PENDING,
    )

    rfid_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    fingerprint_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    user: Mapped["User"] = relationship(
        back_populates="devices",
    )
class AuthenticationCredential(Base):
    __tablename__ = "authentication_credentials"

    __table_args__ = (
        UniqueConstraint(
            "device_id",
            "rfid_uid",
            name="uq_auth_credential_device_rfid",
        ),
        UniqueConstraint(
            "device_id",
            "fingerprint_id",
            name="uq_auth_credential_device_fingerprint",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "devices.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    rfid_uid: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    fingerprint_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

class SecurityAuditEvent(Base):
    __tablename__ = "security_audit_events"

    __table_args__ = (
        CheckConstraint(
            "(previous_hash IS NULL AND event_hash IS NULL) OR "
            "(previous_hash IS NOT NULL AND event_hash IS NOT NULL "
            "AND char_length(previous_hash) = 64 "
            "AND char_length(event_hash) = 64)",
            name="ck_security_audit_hash_pair",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    event_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    category: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        index=True,
    )

    actor_type: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
        index=True,
    )

    actor_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    outcome: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "devices.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "authentication_sessions.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    document_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "documents.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    signature_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "document_signatures.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    signature_request_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "signature_requests.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    failure_code: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    correlation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )

    http_method: Mapped[str | None] = mapped_column(
        String(10),
        nullable=True,
    )

    http_path: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    http_status: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    user_agent: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )

    detail: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    details: Mapped[dict | list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    previous_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    event_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

class AuthenticationSession(Base):
    __tablename__ = "authentication_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "devices.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    rfid_uid: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    document_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    decision: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )
    challenge: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    document_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "documents.id",
            ondelete="RESTRICT",
        ),
        nullable=True,
        index=True,
    )

class UsedNonce(Base):
    __tablename__ = "used_nonces"

    __table_args__ = (
        UniqueConstraint(
            "device_id",
            "nonce",
            name="uq_used_nonce_device_nonce",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "devices.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    nonce: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
class Document(Base):
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    original_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    stored_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
    )

    content_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    size_bytes: Mapped[int] = mapped_column(
        nullable=False,
    )

    document_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    user: Mapped["User | None"] = relationship(
        back_populates="documents",
    )

class DocumentSignature(Base):
    __tablename__ = "document_signatures"

    __table_args__ = (
        UniqueConstraint(
            "session_id",
            name="uq_document_signature_session",
        ),
        UniqueConstraint(
            "signed_document_path",
            name=(
                "uq_document_signatures_signed_document_path"
            ),
        ),
        CheckConstraint(
            "certificate_fingerprint_sha256 IS NULL OR "
            "char_length(certificate_fingerprint_sha256) = 64",
            name=(
                "ck_document_signature_certificate_fingerprint_length"
            ),
        ),
        CheckConstraint(
            "(signed_document_path IS NULL AND "
            "pades_profile IS NULL AND "
            "certificate_fingerprint_sha256 IS NULL AND "
            "certificate_subject IS NULL AND signing_time IS NULL) "
            "OR (signed_document_path IS NOT NULL AND "
            "pades_profile IS NOT NULL AND "
            "certificate_fingerprint_sha256 IS NOT NULL AND "
            "certificate_subject IS NOT NULL AND signing_time IS NOT NULL)",
            name="ck_document_signature_pades_metadata_complete",
        ),
        CheckConstraint(
            "tsa_certificate_fingerprint_sha256 IS NULL OR "
            "char_length(tsa_certificate_fingerprint_sha256) = 64",
            name=(
                "ck_document_signature_tsa_certificate_"
                "fingerprint_length"
            ),
        ),
        CheckConstraint(
            "(timestamp_time IS NULL AND "
            "tsa_certificate_subject IS NULL AND "
            "tsa_certificate_fingerprint_sha256 IS NULL) OR "
            "(timestamp_time IS NOT NULL AND "
            "tsa_certificate_subject IS NOT NULL AND "
            "tsa_certificate_fingerprint_sha256 IS NOT NULL AND "
            "pades_profile = 'PAdES-B-T')",
            name="ck_document_signature_tsa_metadata_complete",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "authentication_sessions.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "documents.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "devices.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    document_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    algorithm: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    key_label: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    signature_base64: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    signed_document_path: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    pades_profile: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )

    certificate_fingerprint_sha256: Mapped[
        str | None
    ] = mapped_column(
        String(64),
        nullable=True,
    )

    certificate_subject: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )

    signing_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    timestamp_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    tsa_certificate_subject: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )

    tsa_certificate_fingerprint_sha256: Mapped[
        str | None
    ] = mapped_column(
        String(64),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class SignatureRequest(Base):
    __tablename__ = "signature_requests"

    __table_args__ = (
        CheckConstraint(
            "char_length(document_hash) = 64",
            name="ck_signature_request_document_hash_length",
        ),
        CheckConstraint(
            "decision = 'APPROVE'",
            name="ck_signature_request_decision",
        ),
        UniqueConstraint(
            "authentication_session_id",
            name="uq_signature_request_authentication_session",
        ),
        UniqueConstraint(
            "signature_id",
            name="uq_signature_request_signature",
        ),
        Index(
            "ix_signature_requests_device_status_created_at",
            "device_id",
            "status",
            "created_at",
        ),
        Index(
            "ix_signature_requests_status_expires_at",
            "status",
            "expires_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    owner_session_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "devices.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "documents.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    document_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    decision: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="APPROVE",
        server_default="APPROVE",
    )

    status: Mapped[SignatureRequestStatus] = mapped_column(
        Enum(
            SignatureRequestStatus,
            name="signature_request_status",
            native_enum=True,
        ),
        nullable=False,
        default=SignatureRequestStatus.PENDING,
        server_default=SignatureRequestStatus.PENDING.value,
    )

    authentication_session_id: Mapped[
        uuid.UUID | None
    ] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "authentication_sessions.id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    signature_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "document_signatures.id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    failure_detail: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    consented_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    consent_version: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    authentication_started_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    authenticated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    user: Mapped["User"] = relationship(
        back_populates="signature_requests",
    )
