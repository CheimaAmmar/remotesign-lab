import secrets
from urllib import request
import uuid

from datetime import (
    datetime,
    timedelta,
    timezone,
)

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    status,
)

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db

from app.models import (
    AuthenticationCredential,
    AuthenticationSession,
    Device,
    DeviceStatus,
    Document,
    SignatureRequestStatus,
    User,
    UserStatus,
)

from app.security.device_auth import (
    verify_device_hmac,
)

from app.security.rate_limit import (
    is_rate_limited,
)

from app.security.nonce_store import (
    consume_nonce,
)
from app.services.audit_service import (
    add_audit_event,
    record_audit_event,
)
from app.services.signature_request_service import (
    persist_terminal_signature_request_failure,
    signature_request_is_authorized_for_session,
    try_attach_authentication_session,
    try_mark_signature_request_authenticated,
)

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


CHALLENGE_TTL_SECONDS = 60

def reject_complete(
    database: Session,
    *,
    status_code: int,
    response_detail: str,
    audit_detail: str,
    source_ip: str | None,
    user_id=None,
    device_id=None,
    session_id=None,
    document_id=None,
    terminal_queue_failure: bool = False,
) -> None:

    # Libère notamment un éventuel FOR UPDATE.
    database.rollback()

    if terminal_queue_failure and isinstance(
        session_id,
        uuid.UUID,
    ):
        persist_terminal_signature_request_failure(
            database,
            authentication_session_id=session_id,
            failure_detail=audit_detail,
        )

    record_audit_event(
        database,
        event_type="STRONG_AUTH_REJECTED",
        outcome="FAILED",
        user_id=user_id,
        device_id=device_id,
        session_id=session_id,
        document_id=document_id,
        source_ip=source_ip,
        detail=audit_detail,
    )

    raise HTTPException(
        status_code=status_code,
        detail=response_detail,
    )

# ======================================================
# CHALLENGE
# ======================================================

@router.post(
    "/challenge",
    status_code=status.HTTP_200_OK,
)
def create_challenge(
    request: Request,

    x_device_uid: str = Header(...),
    x_timestamp: str = Header(...),
    x_nonce: str = Header(...),

    x_rfid_uid: str = Header(...),

    x_document_id: str = Header(...),
    x_document_hash: str = Header(...),
    x_decision: str = Header(...),

    x_signature: str = Header(...),

    database: Session = Depends(get_db),
) -> dict:

    # ==================================================
    # SOURCE IP
    # ==================================================

    source_ip = (
        request.client.host
        if request.client
        else None
    )

    # ==================================================
    # NORMALISATION
    # ==================================================

    device_uid = (
        x_device_uid
        .strip()
        .upper()
    )

    rfid_uid = (
        x_rfid_uid
        .strip()
        .upper()
    )

    document_hash = (
        x_document_hash
        .strip()
        .lower()
    )

    decision = (
        x_decision
        .strip()
        .upper()
    )

    # ==================================================
    # DEVICE
    #
    # IMPORTANT :
    # device doit exister AVANT tout device.id
    # ==================================================

    device = database.scalar(
        select(
            Device
        ).where(
            Device.device_uid
            == device_uid
        )
    )

    if device is None:

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            source_ip=source_ip,
            detail="Unknown device",
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown device",
        )

    # ==================================================
    # RATE LIMIT
    # ==================================================

    if is_rate_limited(
        database,
        source_ip=source_ip,
        device_id=device.id,
    ):

        record_audit_event(
            database,
            event_type="RATE_LIMIT_BLOCKED",
            outcome="FAILED",
            device_id=device.id,
            source_ip=source_ip,
            detail="Too many failed authentication attempts",
        )

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts",
        )

    # ==================================================
    # DEVICE STATUS
    # ==================================================

    if device.status != DeviceStatus.ACTIVE:

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            source_ip=source_ip,
            detail="Device is not active",
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device is not active",
        )

    if not device.rfid_enabled:

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            source_ip=source_ip,
            detail="RFID disabled",
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="RFID disabled",
        )

    if device.device_secret is None:

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            source_ip=source_ip,
            detail="Missing device authentication secret",
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing device secret",
        )

    # ==================================================
    # DOCUMENT ID
    # ==================================================

    try:
        document_id = uuid.UUID(
            x_document_id.strip()
        )

    except (
        ValueError,
        TypeError,
    ):

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            source_ip=source_ip,
            detail="Invalid document ID",
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid document ID",
        )

    document_id_string = str(
        document_id
    )

    # ==================================================
    # DOCUMENT HASH
    # ==================================================

    if len(document_hash) != 64:

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            source_ip=source_ip,
            detail="Invalid document SHA-256",
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid document SHA-256",
        )

    try:
        document_digest = bytes.fromhex(
            document_hash
        )

    except ValueError:

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            source_ip=source_ip,
            detail="Invalid document SHA-256",
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid document SHA-256",
        )

    if len(document_digest) != 32:

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            source_ip=source_ip,
            detail="Invalid document SHA-256",
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid document SHA-256",
        )

    # ==================================================
    # DECISION
    # ==================================================

    if decision != "APPROVE":

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            source_ip=source_ip,
            detail="Invalid signing decision",
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signing decision",
        )

    # ==================================================
    # HMAC
    #
    # Canonical :
    #
    # POST
    # /api/v1/auth/challenge
    # timestamp
    # nonce
    # RFID
    # document_id
    # document_hash
    # APPROVE
    # ==================================================

    extra_data = "\n".join(
        [
            rfid_uid,
            document_id_string,
            document_hash,
            decision,
        ]
    )

    valid = verify_device_hmac(
        device_secret=device.device_secret,
        method=request.method,
        path=request.url.path,
        timestamp=x_timestamp,
        nonce=x_nonce,
        received_signature=x_signature,
        extra_data=extra_data,
    )

    if not valid:

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            source_ip=source_ip,
            detail="Invalid device HMAC",
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device authentication",
        )

    # ==================================================
    # DOCUMENT POSTGRESQL
    # ==================================================

    document = database.get(
        Document,
        document_id,
    )

    if document is None:

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            source_ip=source_ip,
            detail="Document not found",
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    # ==================================================
    # DOCUMENT HASH / POSTGRESQL
    # ==================================================

    if (
        document.document_hash
        != document_hash
    ):

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            document_id=document.id,
            source_ip=source_ip,
            detail="Document hash mismatch",
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Document hash mismatch",
        )

    # ==================================================
    # RFID
    # ==================================================

    credential = database.scalar(
        select(
            AuthenticationCredential
        ).where(
            AuthenticationCredential.device_id
            == device.id,

            AuthenticationCredential.rfid_uid
            == rfid_uid,
        )
    )

    if credential is None:

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            document_id=document.id,
            source_ip=source_ip,
            detail="Unknown RFID credential",
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unknown RFID credential",
        )

    # ==================================================
    # USER
    # ==================================================

    user = database.get(
        User,
        credential.user_id,
    )

    if user is None:

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            document_id=document.id,
            source_ip=source_ip,
            detail="User not found",
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User not found",
        )

    if user.status != UserStatus.ACTIVE:

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            user_id=user.id,
            device_id=device.id,
            document_id=document.id,
            source_ip=source_ip,
            detail="User disabled",
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User disabled",
        )

    # ==================================================
    # NONCE POSTGRESQL
    # ==================================================

    nonce_accepted = consume_nonce(
        database=database,
        device_id=device.id,
        nonce=x_nonce,
    )

    if not nonce_accepted:

        record_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            user_id=user.id,
            device_id=device.id,
            document_id=document.id,
            source_ip=source_ip,
            detail="Challenge nonce replay detected",
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nonce already used",
        )

    # ==================================================
    # CHALLENGE 256 BITS
    # ==================================================

    challenge = secrets.token_hex(
        32
    )

    now = datetime.now(
        timezone.utc
    )

    expires_at = (
        now
        + timedelta(
            seconds=CHALLENGE_TTL_SECONDS
        )
    )

    # ==================================================
    # SESSION
    # ==================================================

    auth_session = AuthenticationSession(
        device_id=device.id,
        user_id=user.id,
        rfid_uid=rfid_uid,

        document_id=document.id,
        document_hash=document.document_hash,
        decision=decision,

        challenge=challenge,
        expires_at=expires_at,
    )

    database.add(
        auth_session
    )

    # Génère notamment auth_session.id
    # avant l'événement d'audit.
    database.flush()

    signature_request = try_attach_authentication_session(
        database,
        device_id=device.id,
        document_id=document.id,
        document_hash=document.document_hash,
        decision=decision,
        authentication_session=auth_session,
    )

    device.last_seen = now

    # ==================================================
    # AUDIT SUCCESS
    # ==================================================

    add_audit_event(
        database,
        event_type="AUTH_CHALLENGE_CREATED",
        outcome="SUCCESS",
        actor_type="DEVICE",
        actor_id=device.device_uid,
        user_id=user.id,
        device_id=device.id,
        session_id=auth_session.id,
        document_id=document.id,
        signature_request_id=(
            signature_request.id
            if signature_request is not None
            else None
        ),
        request=request,
        http_status=status.HTTP_200_OK,
        detail="Strong authentication challenge created",
    )

    # ==================================================
    # COMMIT
    # ==================================================

    database.commit()

    database.refresh(
        auth_session
    )

    # ==================================================
    # REPONSE
    # ==================================================

    return {
        "session_id":
            str(auth_session.id),

        "challenge":
            challenge,

        "document_id":
            str(auth_session.document_id),

        "document_hash":
            auth_session.document_hash,

        "decision":
            auth_session.decision,

        "expires_in":
            CHALLENGE_TTL_SECONDS,

        "message":
            "Fingerprint authentication required",
    }
# ======================================================
# COMPLETE
# ======================================================

@router.post(
    "/complete",
    status_code=status.HTTP_200_OK,
)
def complete_authentication(
    request: Request,

    x_device_uid: str = Header(...),
    x_timestamp: str = Header(...),
    x_nonce: str = Header(...),

    x_session_id: str = Header(...),
    x_challenge: str = Header(...),

    x_rfid_uid: str = Header(...),
    x_fingerprint_id: str = Header(...),

    x_document_id: str = Header(...),
    x_document_hash: str = Header(...),
    x_decision: str = Header(...),

    x_signature: str = Header(...),

    database: Session = Depends(get_db),
) -> dict:

    # ==================================================
    # NORMALISATION
    # ==================================================

    device_uid = (
        x_device_uid
        .strip()
        .upper()
    )

    rfid_uid = (
        x_rfid_uid
        .strip()
        .upper()
    )

    challenge = (
        x_challenge
        .strip()
        .lower()
    )

    document_hash = (
        x_document_hash
        .strip()
        .lower()
    )

    decision = (
        x_decision
        .strip()
        .upper()
    )

    # ==================================================
    # DOCUMENT ID
    # ==================================================

    try:
        document_id = uuid.UUID(
            x_document_id.strip()
        )

    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid document ID",
        )

    document_id_string = str(
        document_id
    )

    # ==================================================
    # DOCUMENT HASH
    # ==================================================

    if len(document_hash) != 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid document SHA-256",
        )

    try:
        document_digest = bytes.fromhex(
            document_hash
        )

    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid document SHA-256",
        )

    if len(document_digest) != 32:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid document SHA-256",
        )

    # ==================================================
    # DECISION
    # ==================================================

    if decision != "APPROVE":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signing decision",
        )

    # ==================================================
    # FINGERPRINT ID
    # ==================================================

    try:
        fingerprint_id = int(
            x_fingerprint_id
        )

    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid fingerprint ID",
        )

    if fingerprint_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid fingerprint ID",
        )

    # ==================================================
    # SESSION ID
    # ==================================================

    try:
        session_id = uuid.UUID(
            x_session_id.strip()
        )

    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session ID",
        )

    session_id_string = str(
        session_id
    )

    # ==================================================
    # DEVICE
    # ==================================================

    device = database.scalar(
        select(Device).where(
            Device.device_uid
            == device_uid
        )
    )

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown device",
        )

    # ==================================================
    # SOURCE IP
    # ==================================================

    source_ip = (
        request.client.host
        if request.client
        else None
    )
    if is_rate_limited(
        database,
        source_ip=source_ip,
        device_id=device.id,
    ):

        record_audit_event(
            database,
            event_type="RATE_LIMIT_BLOCKED",
            outcome="FAILED",
            device_id=device.id,
            source_ip=source_ip,
            detail="Too many failed authentication attempts",
        )

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts",
        )
    if device.status != DeviceStatus.ACTIVE:

        reject_complete(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Device is not active",
            audit_detail="Inactive device attempted complete authentication",
            source_ip=source_ip,
            device_id=device.id,
        )

    if not device.fingerprint_enabled:

        reject_complete(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Fingerprint disabled",
            audit_detail="Fingerprint authentication disabled on device",
            source_ip=source_ip,
            device_id=device.id,
        )

    if device.device_secret is None:

        reject_complete(
            database,
            status_code=status.HTTP_401_UNAUTHORIZED,
            response_detail="Missing device secret",
            audit_detail="Device authentication secret missing",
            source_ip=source_ip,
            device_id=device.id,
        )

    # ==================================================
    # HMAC
    #
    # POST
    # /api/v1/auth/complete
    # timestamp
    # nonce
    # session_id
    # challenge
    # RFID
    # fingerprint_id
    # document_id
    # document_hash
    # APPROVE
    # ==================================================

    extra_data = "\n".join(
        [
            session_id_string,
            challenge,
            rfid_uid,
            str(fingerprint_id),
            document_id_string,
            document_hash,
            decision,
        ]
    )

    valid = verify_device_hmac(
        device_secret=device.device_secret,
        method=request.method,
        path=request.url.path,
        timestamp=x_timestamp,
        nonce=x_nonce,
        received_signature=x_signature,
        extra_data=extra_data,
    )

    if not valid:

        reject_complete(
            database,
            status_code=status.HTTP_401_UNAUTHORIZED,
            response_detail="Invalid device authentication",
            audit_detail="Invalid device HMAC",
            source_ip=source_ip,
            device_id=device.id,
        )

    # ==================================================
    # SESSION + VERROU POSTGRESQL
    # ==================================================

    auth_session = database.scalar(
        select(
            AuthenticationSession
        )
        .where(
            AuthenticationSession.id
            == session_id
        )
        .with_for_update()
    )

    # ==================================================
    # SESSION INEXISTANTE
    # ==================================================

    if auth_session is None:

        reject_complete(
            database,
            status_code=status.HTTP_404_NOT_FOUND,
            response_detail="Authentication session not found",
            audit_detail="Authentication session not found",
            source_ip=source_ip,
            device_id=device.id,
        )

    # ==================================================
    # DEVICE DE LA SESSION
    # ==================================================

    if auth_session.device_id != device.id:

        reject_complete(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Session/device mismatch",
            audit_detail="Authentication session/device mismatch",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # EXPIRATION
    # ==================================================

    now = datetime.now(
        timezone.utc
    )

    if auth_session.expires_at <= now:

        reject_complete(
            database,
            status_code=status.HTTP_401_UNAUTHORIZED,
            response_detail="Challenge expired",
            audit_detail="Authentication challenge expired",
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # SESSION DEJA VERIFIEE
    # ==================================================

    if auth_session.verified_at is not None:

        reject_complete(
            database,
            status_code=status.HTTP_409_CONFLICT,
            response_detail="Authentication session already verified",
            audit_detail="Authentication session already verified",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # CHALLENGE
    # ==================================================

    if auth_session.challenge != challenge:

        reject_complete(
            database,
            status_code=status.HTTP_401_UNAUTHORIZED,
            response_detail="Invalid challenge",
            audit_detail="Invalid authentication challenge",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # RFID
    # ==================================================

    if auth_session.rfid_uid != rfid_uid:

        reject_complete(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="RFID mismatch",
            audit_detail="RFID does not match authentication session",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # DOCUMENT ID
    # ==================================================

    if auth_session.document_id != document_id:

        reject_complete(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Document ID mismatch",
            audit_detail="Document ID does not match authentication session",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # DOCUMENT HASH
    # ==================================================

    if auth_session.document_hash != document_hash:

        reject_complete(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Document hash mismatch",
            audit_detail="Document hash does not match authentication session",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # DECISION
    # ==================================================

    if auth_session.decision != decision:

        reject_complete(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Signing decision mismatch",
            audit_detail="Signing decision does not match authentication session",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # DOCUMENT POSTGRESQL
    # ==================================================

    document = database.get(
        Document,
        document_id,
    )

    if document is None:

        reject_complete(
            database,
            status_code=status.HTTP_404_NOT_FOUND,
            response_detail="Document not found",
            audit_detail="Document referenced by authentication session not found",
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
        )

    if document.document_hash != document_hash:

        reject_complete(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Stored document hash mismatch",
            audit_detail="Stored document hash does not match authentication session",
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
        )

    # ==================================================
    # RFID + FINGERPRINT
    # ==================================================

    credential = database.scalar(
        select(
            AuthenticationCredential
        ).where(
            AuthenticationCredential.device_id
            == device.id,

            AuthenticationCredential.user_id
            == auth_session.user_id,

            AuthenticationCredential.rfid_uid
            == rfid_uid,

            AuthenticationCredential.fingerprint_id
            == fingerprint_id,
        )
    )

    if credential is None:

        reject_complete(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="RFID and fingerprint do not match",
            audit_detail="RFID/fingerprint credential mismatch",
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # USER
    # ==================================================

    user = database.get(
        User,
        auth_session.user_id,
    )

    if user is None:

        reject_complete(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="User not found",
            audit_detail="Authentication session user not found",
            terminal_queue_failure=True,
            source_ip=source_ip,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    if user.status != UserStatus.ACTIVE:

        reject_complete(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="User disabled",
            audit_detail="Disabled user attempted strong authentication",
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=user.id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # USER DE LA DEMANDE WEB
    # ==================================================

    if not signature_request_is_authorized_for_session(
        database,
        authentication_session=auth_session,
        expected_status=SignatureRequestStatus.AUTHENTICATING,
    ):
        reject_complete(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail=(
                "Signature request is not authorized"
            ),
            audit_detail=(
                "Missing consent or signature request identity/document mismatch"
            ),
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=user.id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # NONCE POSTGRESQL
    # ==================================================

    nonce_accepted = consume_nonce(
        database=database,
        device_id=device.id,
        nonce=x_nonce,
    )

    if not nonce_accepted:

        reject_complete(
            database,
            status_code=status.HTTP_401_UNAUTHORIZED,
            response_detail="Nonce already used",
            audit_detail="Complete authentication nonce replay detected",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # AUTHENTIFICATION FORTE VALIDEE
    # ==================================================

    auth_session.verified_at = now

    signature_request = try_mark_signature_request_authenticated(
        database,
        authentication_session_id=auth_session.id,
    )

    device.last_seen = now

    add_audit_event(
        database,
        event_type="STRONG_AUTH_COMPLETED",
        outcome="SUCCESS",
        actor_type="DEVICE",
        actor_id=device.device_uid,
        user_id=auth_session.user_id,
        device_id=device.id,
        session_id=auth_session.id,
        document_id=document.id,
        signature_request_id=(
            signature_request.id
            if signature_request is not None
            else None
        ),
        request=request,
        http_status=status.HTTP_200_OK,
        detail="RFID and fingerprint authentication successful",
    )

    database.commit()

    # ==================================================
    # REPONSE
    # ==================================================

    return {
        "authenticated":
            True,

        "session_id":
            session_id_string,

        "document_id":
            document_id_string,

        "document_hash":
            document_hash,

        "decision":
            decision,

        "message":
            "Strong authentication successful",
    }
