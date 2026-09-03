import logging
import uuid

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import (
    AuthenticationSession,
    Device,
    Document,
    DocumentSignature,
    SignatureRequest,
    SignatureRequestStatus,
)


logger = logging.getLogger(__name__)

SIGNATURE_REQUEST_TTL_SECONDS = 15 * 60

EXPIRABLE_SIGNATURE_REQUEST_STATUSES = (
    SignatureRequestStatus.PENDING,
    SignatureRequestStatus.CLAIMED,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _device_queue_lock_key(device_id: uuid.UUID) -> int:
    # PostgreSQL advisory locks accept a signed BIGINT. UUID entropy is
    # retained in the low 63 bits without risking an integer overflow.
    return device_id.int & ((1 << 63) - 1)


def _expire_if_needed(
    signature_request: SignatureRequest,
    *,
    now: datetime,
) -> bool:
    if (
        signature_request.status
        not in EXPIRABLE_SIGNATURE_REQUEST_STATUSES
        or signature_request.expires_at > now
    ):
        return False

    signature_request.status = SignatureRequestStatus.EXPIRED
    signature_request.failure_detail = (
        "Signature request expired"
    )
    signature_request.completed_at = now
    signature_request.updated_at = now

    return True


def create_signature_request(
    database: Session,
    *,
    owner_session_id: str,
    device: Device,
    document: Document,
) -> SignatureRequest:
    now = utc_now()
    signature_request = SignatureRequest(
        owner_session_id=owner_session_id,
        device_id=device.id,
        document_id=document.id,
        document_hash=document.document_hash,
        decision="APPROVE",
        status=SignatureRequestStatus.PENDING,
        expires_at=(
            now
            + timedelta(
                seconds=SIGNATURE_REQUEST_TTL_SECONDS
            )
        ),
        updated_at=now,
    )

    database.add(signature_request)

    return signature_request


def expire_signature_requests(
    database: Session,
    *,
    device_id: uuid.UUID | None = None,
    now: datetime | None = None,
) -> int:
    current_time = now or utc_now()
    conditions = [
        SignatureRequest.status.in_(
            EXPIRABLE_SIGNATURE_REQUEST_STATUSES
        ),
        SignatureRequest.expires_at <= current_time,
    ]

    if device_id is not None:
        conditions.append(
            SignatureRequest.device_id == device_id
        )

    result = database.execute(
        update(SignatureRequest)
        .where(*conditions)
        .values(
            status=SignatureRequestStatus.EXPIRED,
            failure_detail="Signature request expired",
            completed_at=current_time,
            updated_at=current_time,
        )
    )

    return int(result.rowcount or 0)


def claim_next_signature_request(
    database: Session,
    *,
    device: Device,
) -> SignatureRequest | None:
    now = utc_now()

    # Serializes queue pollers for one physical device without locking
    # the devices row also updated by the existing authentication flows.
    # The lock is released automatically with this transaction.
    database.execute(
        select(
            func.pg_advisory_xact_lock(
                _device_queue_lock_key(device.id)
            )
        )
    )

    expire_signature_requests(
        database,
        device_id=device.id,
        now=now,
    )

    in_flight_request = database.scalar(
        select(SignatureRequest)
        .where(
            SignatureRequest.device_id == device.id,
            SignatureRequest.status.in_(
                (
                    SignatureRequestStatus.CLAIMED,
                    SignatureRequestStatus.AUTHENTICATING,
                    SignatureRequestStatus.AUTHENTICATED,
                )
            ),
        )
        .order_by(
            SignatureRequest.claimed_at.asc(),
            SignatureRequest.created_at.asc(),
            SignatureRequest.id.asc(),
        )
        .with_for_update()
        .limit(1)
    )

    if in_flight_request is not None:
        # Never deliver a CLAIMED request a second time. The device must
        # finish or explicitly fail its current request before polling the
        # next FIFO item.
        return None

    signature_request = database.scalar(
        select(SignatureRequest)
        .where(
            SignatureRequest.device_id == device.id,
            SignatureRequest.status
            == SignatureRequestStatus.PENDING,
            SignatureRequest.expires_at > now,
        )
        .order_by(
            SignatureRequest.created_at.asc(),
            SignatureRequest.id.asc(),
        )
        .with_for_update(skip_locked=True)
        .limit(1)
    )

    if signature_request is None:
        return None

    signature_request.status = SignatureRequestStatus.CLAIMED
    signature_request.claimed_at = now
    signature_request.updated_at = now

    return signature_request


def get_owned_signature_request(
    database: Session,
    *,
    request_id: uuid.UUID,
    owner_session_id: str,
) -> SignatureRequest | None:
    signature_request = database.scalar(
        select(SignatureRequest)
        .where(
            SignatureRequest.id == request_id,
            SignatureRequest.owner_session_id
            == owner_session_id,
        )
        .with_for_update()
    )

    if signature_request is None:
        return None

    now = utc_now()

    _expire_if_needed(
        signature_request,
        now=now,
    )

    return signature_request


def attach_authentication_session(
    database: Session,
    *,
    device_id: uuid.UUID,
    document_id: uuid.UUID,
    document_hash: str,
    decision: str,
    authentication_session: AuthenticationSession,
) -> SignatureRequest | None:
    now = utc_now()

    if (
        authentication_session.device_id != device_id
        or authentication_session.document_id != document_id
        or authentication_session.document_hash != document_hash
        or authentication_session.decision != decision
    ):
        return None

    signature_request = database.scalar(
        select(SignatureRequest)
        .where(
            SignatureRequest.device_id == device_id,
            SignatureRequest.document_id == document_id,
            SignatureRequest.document_hash == document_hash,
            SignatureRequest.decision == decision,
            SignatureRequest.status.in_(
                (
                    SignatureRequestStatus.CLAIMED,
                )
            ),
            SignatureRequest.authentication_session_id.is_(
                None
            ),
        )
        .order_by(
            SignatureRequest.claimed_at.asc(),
            SignatureRequest.created_at.asc(),
        )
        .with_for_update()
        .limit(1)
    )

    if signature_request is None:
        return None

    if _expire_if_needed(signature_request, now=now):
        return signature_request

    signature_request.authentication_session_id = (
        authentication_session.id
    )
    signature_request.status = (
        SignatureRequestStatus.AUTHENTICATING
    )
    signature_request.authentication_started_at = now
    signature_request.updated_at = now

    return signature_request


def mark_signature_request_authenticated(
    database: Session,
    *,
    authentication_session_id: uuid.UUID,
) -> SignatureRequest | None:
    signature_request = database.scalar(
        select(SignatureRequest)
        .where(
            SignatureRequest.authentication_session_id
            == authentication_session_id,
        )
        .with_for_update()
    )

    if signature_request is None:
        return None

    now = utc_now()

    if _expire_if_needed(signature_request, now=now):
        return signature_request

    if (
        signature_request.status
        == SignatureRequestStatus.AUTHENTICATING
    ):
        signature_request.status = (
            SignatureRequestStatus.AUTHENTICATED
        )
        signature_request.authenticated_at = now
        signature_request.updated_at = now

    return signature_request


def mark_signature_request_signed(
    database: Session,
    *,
    authentication_session_id: uuid.UUID,
    signature: DocumentSignature,
) -> SignatureRequest | None:
    signature_request = database.scalar(
        select(SignatureRequest)
        .where(
            SignatureRequest.authentication_session_id
            == authentication_session_id,
        )
        .with_for_update()
    )

    if signature_request is None:
        return None

    if (
        signature.session_id != authentication_session_id
        or signature_request.document_id
        != signature.document_id
        or signature_request.device_id != signature.device_id
        or signature_request.document_hash
        != signature.document_hash
    ):
        return signature_request

    now = utc_now()

    if _expire_if_needed(signature_request, now=now):
        return signature_request

    if (
        signature_request.status
        == SignatureRequestStatus.AUTHENTICATED
    ):
        signature_request.status = SignatureRequestStatus.SIGNED
        signature_request.signature_id = signature.id
        signature_request.completed_at = now
        signature_request.updated_at = now

    return signature_request


def mark_signature_request_failed(
    database: Session,
    *,
    request_id: uuid.UUID,
    device_id: uuid.UUID,
    failure_detail: str,
) -> SignatureRequest | None:
    signature_request = database.scalar(
        select(SignatureRequest)
        .where(
            SignatureRequest.id == request_id,
            SignatureRequest.device_id == device_id,
        )
        .with_for_update()
    )

    if signature_request is None:
        return None

    now = utc_now()

    if _expire_if_needed(signature_request, now=now):
        return signature_request

    if signature_request.status in (
        SignatureRequestStatus.CLAIMED,
        SignatureRequestStatus.AUTHENTICATING,
        SignatureRequestStatus.AUTHENTICATED,
    ):
        signature_request.status = SignatureRequestStatus.FAILED
        signature_request.failure_detail = failure_detail[:255]
        signature_request.completed_at = now
        signature_request.updated_at = now

    return signature_request


def mark_signature_request_failed_by_session(
    database: Session,
    *,
    authentication_session_id: uuid.UUID,
    failure_detail: str,
) -> SignatureRequest | None:
    signature_request = database.scalar(
        select(SignatureRequest)
        .where(
            SignatureRequest.authentication_session_id
            == authentication_session_id,
        )
        .with_for_update()
    )

    if signature_request is None:
        return None

    now = utc_now()

    if _expire_if_needed(signature_request, now=now):
        return signature_request

    if signature_request.status in (
        SignatureRequestStatus.AUTHENTICATING,
        SignatureRequestStatus.AUTHENTICATED,
    ):
        signature_request.status = SignatureRequestStatus.FAILED
        signature_request.failure_detail = failure_detail[:255]
        signature_request.completed_at = now
        signature_request.updated_at = now

    return signature_request


def persist_terminal_signature_request_failure(
    database: Session,
    *,
    authentication_session_id: uuid.UUID,
    failure_detail: str,
) -> None:
    """Persist a terminal queue failure after an API rejection rollback."""
    try:
        mark_signature_request_failed_by_session(
            database,
            authentication_session_id=(
                authentication_session_id
            ),
            failure_detail=failure_detail,
        )
        database.commit()

    except SQLAlchemyError:
        database.rollback()
        logger.exception(
            "Unable to persist the terminal signature queue failure"
        )


def _run_optional_queue_hook(
    database: Session,
    operation,
) -> None:
    try:
        with database.begin_nested():
            operation()

    except SQLAlchemyError as error:
        original_error = getattr(error, "orig", None)
        sqlstate = (
            getattr(original_error, "sqlstate", None)
            or getattr(original_error, "pgcode", None)
        )

        # Preserve the legacy device routes only during the short window
        # before this revision's table has been migrated. Any other queue
        # database error must abort the surrounding auth/sign transaction
        # instead of silently leaving its state behind.
        if sqlstate != "42P01":
            raise

        logger.warning(
            "Signature queue table is not migrated yet; "
            "skipping state synchronization"
        )


def try_attach_authentication_session(
    database: Session,
    **kwargs,
) -> None:
    _run_optional_queue_hook(
        database,
        lambda: attach_authentication_session(
            database,
            **kwargs,
        ),
    )


def try_mark_signature_request_authenticated(
    database: Session,
    *,
    authentication_session_id: uuid.UUID,
) -> None:
    _run_optional_queue_hook(
        database,
        lambda: mark_signature_request_authenticated(
            database,
            authentication_session_id=(
                authentication_session_id
            ),
        ),
    )


def try_mark_signature_request_signed(
    database: Session,
    *,
    authentication_session_id: uuid.UUID,
    signature: DocumentSignature,
) -> None:
    _run_optional_queue_hook(
        database,
        lambda: mark_signature_request_signed(
            database,
            authentication_session_id=(
                authentication_session_id
            ),
            signature=signature,
        ),
    )
