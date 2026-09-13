import hashlib
import os
import tempfile
import uuid

from datetime import (
    datetime,
    timedelta,
    timezone,
)

from pathlib import Path

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
    AuthenticationSession,
    Device,
    DeviceStatus,
    Document,
    DocumentSignature,
    SignatureRequestStatus,
    User,
)

from app.security.device_auth import (
    verify_device_hmac,
)

from app.security.nonce_store import (
    consume_nonce,
)

from app.services.hsm_service import (
    HSMService,
    HSMServiceError,
)
from app.services.pades_service import (
    PAdESService,
    PAdESServiceError,
    SIGNED_DOCUMENT_STORAGE,
)

from app.services.audit_service import (
    add_audit_event,
    record_audit_event,
)
from app.services.signature_request_service import (
    persist_terminal_signature_request_failure,
    signature_request_is_authorized_for_session,
    try_mark_signature_request_signed,
)

from app.security.rate_limit import (
    is_rate_limited,
)


router = APIRouter(
    prefix="/api/v1/sign",
    tags=["Signing"],
)


SIGNING_AUTHORIZATION_TTL_SECONDS = 60


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

DOCUMENT_STORAGE = (
    PROJECT_ROOT
    / "storage"
    / "documents"
)


# ======================================================
# CENTRALIZED /sign REJECTION
# ======================================================

def reject_sign(
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
    audit_event_type: str = "SIGNATURE_FAILED",
    failure_code: str | None = None,
    request: Request | None = None,
) -> None:

    # Release the current transaction, including any
    # SELECT ... FOR UPDATE lock.
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
        event_type=audit_event_type,
        outcome=(
            "DENIED"
            if 400 <= status_code < 500
            else "FAILURE"
        ),
        actor_type="DEVICE",
        user_id=user_id,
        device_id=device_id,
        session_id=session_id,
        document_id=document_id,
        failure_code=failure_code,
        request=request,
        source_ip=source_ip,
        http_status=status_code,
        detail=audit_detail,
    )

    raise HTTPException(
        status_code=status_code,
        detail=response_detail,
    )


# ======================================================
# SIGN
# ======================================================

@router.post(
    "",
    status_code=status.HTTP_200_OK,
)
def sign_document(
    request: Request,

    x_device_uid: str = Header(...),
    x_timestamp: str = Header(...),
    x_nonce: str = Header(...),

    x_session_id: str = Header(...),

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
    # NORMALIZATION
    # ==================================================

    device_uid = (
        x_device_uid
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
    # IMPORTANT:
    # device must be loaded BEFORE any use of device.id
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
        reject_sign(
            database,
            status_code=status.HTTP_401_UNAUTHORIZED,
            response_detail="Unknown device",
            audit_detail="Unknown device",
            source_ip=source_ip,
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
            detail="Too many failed signing attempts",
        )

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts",
        )

    # ==================================================
    # DEVICE STATUS
    # ==================================================

    if device.status != DeviceStatus.ACTIVE:
        reject_sign(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Device is not active",
            audit_detail="Device is not active",
            source_ip=source_ip,
            device_id=device.id,
        )

    if device.device_secret is None:
        reject_sign(
            database,
            status_code=status.HTTP_401_UNAUTHORIZED,
            response_detail="Missing device secret",
            audit_detail="Missing device authentication secret",
            source_ip=source_ip,
            device_id=device.id,
        )

    # ==================================================
    # SESSION ID
    # ==================================================

    try:
        session_id = uuid.UUID(
            x_session_id.strip()
        )

    except (
        ValueError,
        TypeError,
    ):
        reject_sign(
            database,
            status_code=status.HTTP_400_BAD_REQUEST,
            response_detail="Invalid authentication session ID",
            audit_detail="Invalid authentication session ID",
            source_ip=source_ip,
            device_id=device.id,
        )

    session_id_string = str(
        session_id
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
        reject_sign(
            database,
            status_code=status.HTTP_400_BAD_REQUEST,
            response_detail="Invalid document ID",
            audit_detail="Invalid document ID",
            source_ip=source_ip,
            device_id=device.id,
        )

    document_id_string = str(
        document_id
    )

    # ==================================================
    # DOCUMENT HASH
    # ==================================================

    if len(document_hash) != 64:
        reject_sign(
            database,
            status_code=status.HTTP_400_BAD_REQUEST,
            response_detail="Invalid document SHA-256",
            audit_detail="Invalid document SHA-256",
            source_ip=source_ip,
            device_id=device.id,
        )

    try:
        supplied_digest = bytes.fromhex(
            document_hash
        )

    except ValueError:
        reject_sign(
            database,
            status_code=status.HTTP_400_BAD_REQUEST,
            response_detail="Invalid document SHA-256",
            audit_detail="Invalid document SHA-256",
            source_ip=source_ip,
            device_id=device.id,
        )

    if len(supplied_digest) != 32:
        reject_sign(
            database,
            status_code=status.HTTP_400_BAD_REQUEST,
            response_detail="Invalid document SHA-256",
            audit_detail="Invalid document SHA-256",
            source_ip=source_ip,
            device_id=device.id,
        )

    # ==================================================
    # DECISION
    # ==================================================

    if decision != "APPROVE":
        reject_sign(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Signing not approved",
            audit_detail="Signing not approved",
            source_ip=source_ip,
            device_id=device.id,
        )

    # ==================================================
    # HMAC
    #
    # POST
    # /api/v1/sign
    # timestamp
    # nonce
    # session_id
    # document_id
    # document_hash
    # APPROVE
    # ==================================================

    extra_data = "\n".join(
        [
            session_id_string,
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
        reject_sign(
            database,
            status_code=status.HTTP_401_UNAUTHORIZED,
            response_detail="Invalid device authentication",
            audit_detail="Invalid signing request HMAC",
            source_ip=source_ip,
            device_id=device.id,
        )

    # ==================================================
    # SESSION + POSTGRESQL LOCK
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

    if auth_session is None:
        reject_sign(
            database,
            status_code=status.HTTP_404_NOT_FOUND,
            response_detail="Authentication session not found",
            audit_detail="Authentication session not found",
            source_ip=source_ip,
            device_id=device.id,
        )

    # ==================================================
    # DEVICE / SESSION
    # ==================================================

    if auth_session.device_id != device.id:
        reject_sign(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Authentication session/device mismatch",
            audit_detail="Signing session/device mismatch",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # USER FROM THE WEB REQUEST
    # ==================================================

    if not signature_request_is_authorized_for_session(
        database,
        authentication_session=auth_session,
        expected_status=SignatureRequestStatus.AUTHENTICATED,
    ):
        reject_sign(
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
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # VERIFIED SESSION
    # ==================================================

    if auth_session.verified_at is None:
        reject_sign(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Authentication session not verified",
            audit_detail=(
                "Signing attempted without completed strong authentication"
            ),
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # SESSION ALREADY USED
    # ==================================================

    if auth_session.used_at is not None:
        reject_sign(
            database,
            status_code=status.HTTP_409_CONFLICT,
            response_detail="Authentication session already used",
            audit_detail="Signing session already consumed",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # DOUBLE PROTECTION: DOES A SIGNATURE ALREADY EXIST?
    # ==================================================

    existing_signature = database.scalar(
        select(
            DocumentSignature
        ).where(
            DocumentSignature.session_id
            == auth_session.id
        )
    )

    if existing_signature is not None:
        reject_sign(
            database,
            status_code=status.HTTP_409_CONFLICT,
            response_detail=(
                "Authentication session already has a signature"
            ),
            audit_detail=(
                "Authentication session already has a signature"
            ),
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # SESSION DOCUMENT ID
    # ==================================================

    if auth_session.document_id != document_id:
        reject_sign(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Document ID mismatch",
            audit_detail="Signing document ID mismatch",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # SESSION DOCUMENT HASH
    # ==================================================

    if auth_session.document_hash != document_hash:
        reject_sign(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Document hash mismatch",
            audit_detail="Signing document hash mismatch",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # SESSION DECISION
    # ==================================================

    if auth_session.decision != decision:
        reject_sign(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Signing decision mismatch",
            audit_detail="Signing decision mismatch",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # RECENT SIGNING AUTHORIZATION
    # ==================================================

    now = datetime.now(
        timezone.utc
    )

    signing_deadline = (
        auth_session.verified_at
        + timedelta(
            seconds=SIGNING_AUTHORIZATION_TTL_SECONDS
        )
    )

    if now > signing_deadline:
        reject_sign(
            database,
            status_code=status.HTTP_401_UNAUTHORIZED,
            response_detail="Signing authorization expired",
            audit_detail="Signing authorization expired",
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=auth_session.document_id,
        )

    # ==================================================
    # POSTGRESQL DOCUMENT
    # ==================================================

    document = database.get(
        Document,
        document_id,
    )

    if document is None:
        reject_sign(
            database,
            status_code=status.HTTP_404_NOT_FOUND,
            response_detail="Document not found",
            audit_detail="Signing document not found",
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
        )

    signing_user = database.get(
        User,
        auth_session.user_id,
    )

    if signing_user is None:
        reject_sign(
            database,
            status_code=status.HTTP_403_FORBIDDEN,
            response_detail="Signature user not found",
            audit_detail="Authenticated signature user not found",
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
        )

    # ==================================================
    # HASH POSTGRESQL
    # ==================================================

    if document.document_hash != document_hash:
        reject_sign(
            database,
            status_code=status.HTTP_409_CONFLICT,
            response_detail="Stored document hash mismatch",
            audit_detail="Stored document hash mismatch",
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
        )

    # ==================================================
    # ACTUAL FILE
    # ==================================================

    storage_root = (
        DOCUMENT_STORAGE
        .resolve()
    )

    document_path = (
        DOCUMENT_STORAGE
        / document.stored_filename
    ).resolve()

    if not document_path.is_relative_to(
        storage_root
    ):
        reject_sign(
            database,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            response_detail="Invalid stored document path",
            audit_detail="Invalid stored document path",
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
        )

    if not document_path.is_file():
        reject_sign(
            database,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            response_detail="Stored document file not found",
            audit_detail="Stored document file missing",
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
        )

    # ==================================================
    # RECALCULATE SHA-256 FOR THE ACTUAL PDF
    # ==================================================

    sha256 = hashlib.sha256()

    try:
        with document_path.open(
            "rb"
        ) as input_file:

            while True:
                chunk = input_file.read(
                    64 * 1024
                )

                if not chunk:
                    break

                sha256.update(
                    chunk
                )

    except OSError:
        reject_sign(
            database,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            response_detail="Unable to read stored document",
            audit_detail="Unable to read stored document",
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
        )

    actual_document_hash = (
        sha256.hexdigest()
    )

    # ==================================================
    # PDF / DB INTEGRITY
    # ==================================================

    if actual_document_hash != document.document_hash:
        reject_sign(
            database,
            status_code=status.HTTP_409_CONFLICT,
            response_detail="Document integrity verification failed",
            audit_detail=(
                "Stored document integrity verification failed"
            ),
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
        )

    # ==================================================
    # PDF / SESSION INTEGRITY
    # ==================================================

    if actual_document_hash != auth_session.document_hash:
        reject_sign(
            database,
            status_code=status.HTTP_409_CONFLICT,
            response_detail="Authentication document mismatch",
            audit_detail=(
                "Stored file does not match authenticated document"
            ),
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
        )

    # ==================================================
    # PDF / REQUEST INTEGRITY
    # ==================================================

    if actual_document_hash != document_hash:
        reject_sign(
            database,
            status_code=status.HTTP_409_CONFLICT,
            response_detail="Requested document hash mismatch",
            audit_detail=(
                "Stored file does not match requested document hash"
            ),
            terminal_queue_failure=True,
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
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
        reject_sign(
            database,
            status_code=status.HTTP_401_UNAUTHORIZED,
            response_detail="Nonce already used",
            audit_detail="Signing nonce replay detected",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
        )

    add_audit_event(
        database,
        event_type="SIGNATURE_STARTED",
        outcome="SUCCESS",
        actor_type="DEVICE",
        actor_id=device.device_uid,
        user_id=auth_session.user_id,
        device_id=device.id,
        session_id=auth_session.id,
        document_id=document.id,
        request=request,
        http_status=status.HTTP_200_OK,
        detail="Cryptographic signature workflow started",
    )

    # ==================================================
    # TRUSTED DIGEST
    # ==================================================

    document_digest = bytes.fromhex(
        actual_document_hash
    )

    # ==================================================
    # SOFTHSM
    # ==================================================

    try:
        hsm = HSMService()

        signature_result = (
            hsm.sign_sha256_digest_rsa_pkcs1(
                document_digest
            )
        )

    except HSMServiceError:
        reject_sign(
            database,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            response_detail="HSM signing failed",
            audit_detail="SoftHSM signing operation failed",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
            failure_code="HSM_SIGNING_FAILED",
            request=request,
        )

    # ==================================================
    # TEMPORARY PADES PDF + ATOMIC PUBLICATION
    # ==================================================

    signature_id = uuid.uuid4()
    signed_filename = (
        f"{document.id}-{signature_id}.pdf"
    )
    signed_storage_root = (
        SIGNED_DOCUMENT_STORAGE.resolve()
    )
    final_signed_path = (
        signed_storage_root / signed_filename
    ).resolve()

    if not final_signed_path.is_relative_to(
        signed_storage_root
    ):
        reject_sign(
            database,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            response_detail="Invalid signed document path",
            audit_detail="Invalid signed document path",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
        )

    try:
        signed_storage_root.mkdir(
            parents=True,
            exist_ok=True,
        )
        temporary_file = tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{signature_id}-",
            suffix=".pdf.tmp",
            dir=signed_storage_root,
            delete=False,
        )
        temporary_signed_path = Path(temporary_file.name)
        temporary_file.close()
    except OSError:
        reject_sign(
            database,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            response_detail="PAdES signing failed",
            audit_detail="Unable to prepare signed PDF storage",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
        )

    pades_service = PAdESService()

    try:
        pades_result = pades_service.sign_pdf(
            source_pdf_path=document_path,
            output_pdf_path=temporary_signed_path,
            signature_id=signature_id,
            signer_name=signing_user.full_name,
        )
        os.replace(
            temporary_signed_path,
            final_signed_path,
        )
    except (OSError, PAdESServiceError) as pades_error:
        temporary_signed_path.unlink(missing_ok=True)
        final_signed_path.unlink(missing_ok=True)
        pades_failure = str(pades_error).lower()
        tsa_failure = (
            "tsa" in pades_failure
            or "timestamp" in pades_failure
        )
        reject_sign(
            database,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            response_detail="PAdES signing failed",
            audit_detail="PAdES generation or validation failed",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
            audit_event_type=(
                "TSA_TIMESTAMP_FAILED"
                if tsa_failure
                else "PADES_VALIDATION_FAILED"
            ),
            failure_code=(
                "TSA_UNAVAILABLE"
                if tsa_failure
                else "PADES_CREATION_FAILED"
            ),
            request=request,
        )

    if not final_signed_path.is_file():
        reject_sign(
            database,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            response_detail="PAdES signing failed",
            audit_detail="Signed PAdES document was not published",
            source_ip=source_ip,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
            audit_event_type="PADES_VALIDATION_FAILED",
            failure_code="SIGNED_DOCUMENT_MISSING",
            request=request,
        )

    # ==================================================
    # SIGNATURE RECORD
    # ==================================================

    signature_record = DocumentSignature(
        id=signature_id,
        session_id=auth_session.id,
        document_id=document.id,
        user_id=auth_session.user_id,
        device_id=device.id,
        document_hash=actual_document_hash,
        algorithm=signature_result.algorithm,
        key_label=signature_result.key_label,
        signature_base64=signature_result.signature_base64,
        signed_document_path=signed_filename,
        pades_profile=pades_result.pades_profile,
        certificate_fingerprint_sha256=(
            pades_result.certificate_fingerprint_sha256
        ),
        certificate_subject=pades_result.certificate_subject,
        signing_time=pades_result.signing_time,
        timestamp_time=pades_result.timestamp_time,
        tsa_certificate_subject=(
            pades_result.tsa_certificate_subject
        ),
        tsa_certificate_fingerprint_sha256=(
            pades_result.tsa_certificate_fingerprint_sha256
        ),
    )

    try:
        database.add(
            signature_record
        )

        database.flush()

        signature_request = try_mark_signature_request_signed(
            database,
            authentication_session_id=auth_session.id,
            signature=signature_record,
        )

        if pades_result.timestamp_time is not None:
            add_audit_event(
                database,
                event_type="TSA_TIMESTAMP_SUCCESS",
                outcome="SUCCESS",
                actor_type="SYSTEM",
                user_id=auth_session.user_id,
                device_id=device.id,
                session_id=auth_session.id,
                document_id=document.id,
                signature_request_id=(
                    signature_request.id
                    if signature_request is not None
                    else None
                ),
                signature_id=signature_record.id,
                request=request,
                http_status=status.HTTP_200_OK,
                details={
                    "timestamp_time": pades_result.timestamp_time,
                    "tsa_subject": (
                        pades_result.tsa_certificate_subject
                    ),
                },
            )

        add_audit_event(
            database,
            event_type="PADES_CREATED",
            outcome="SUCCESS",
            actor_type="SYSTEM",
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
            signature_request_id=(
                signature_request.id
                if signature_request is not None
                else None
            ),
            signature_id=signature_record.id,
            request=request,
            http_status=status.HTTP_200_OK,
            details={"pades_profile": pades_result.pades_profile},
        )
        add_audit_event(
            database,
            event_type="PADES_VALIDATION_SUCCESS",
            outcome="SUCCESS",
            actor_type="SYSTEM",
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
            signature_request_id=(
                signature_request.id
                if signature_request is not None
                else None
            ),
            signature_id=signature_record.id,
            request=request,
            http_status=status.HTTP_200_OK,
            details={"pades_profile": pades_result.pades_profile},
        )

        # ==============================================
        # SESSION CONSUMPTION
        # ==============================================

        signed_at = datetime.now(
            timezone.utc
        )

        auth_session.used_at = (
            signed_at
        )

        device.last_seen = (
            signed_at
        )

        # ==============================================
        # AUDIT SUCCESS
        # ==============================================

        add_audit_event(
            database,
            event_type="SIGNATURE_SUCCESS",
            outcome="SUCCESS",
            actor_type="DEVICE",
            actor_id=device.device_uid,
            user_id=auth_session.user_id,
            device_id=device.id,
            session_id=auth_session.id,
            document_id=document.id,
            signature_id=signature_record.id,
            signature_request_id=(
                signature_request.id
                if signature_request is not None
                else None
            ),
            request=request,
            http_status=status.HTTP_200_OK,
            detail=(
                "Document signed using SoftHSM as "
                f"{pades_result.pades_profile}"
            ),
        )
    except Exception:
        database.rollback()
        final_signed_path.unlink(missing_ok=True)
        raise

    # The final file exists before the commit. If the commit outcome is
    # ambiguous (for example, a lost connection after PostgreSQL commits),
    # it is intentionally preserved so that a possibly committed row never
    # points to a deleted file.
    try:
        database.commit()
    except Exception:
        database.rollback()
        raise

    database.refresh(
        signature_record
    )

    # ==================================================
    # RESPONSE
    # ==================================================

    return {
        "signed":
            True,

        "signature_id":
            str(
                signature_record.id
            ),

        "session_id":
            str(
                auth_session.id
            ),

        "document_id":
            str(
                document.id
            ),

        "document_hash":
            actual_document_hash,

        "algorithm":
            signature_result.algorithm,

        "key_label":
            signature_result.key_label,

        "pades_profile":
            pades_result.pades_profile,

        "certificate_subject":
            pades_result.certificate_subject,

        "timestamp_time": (
            pades_result.timestamp_time.isoformat()
            if pades_result.timestamp_time is not None
            else None
        ),

        "tsa_subject":
            pades_result.tsa_certificate_subject,

        "signature_base64":
            signature_result.signature_base64,

        "message":
            "Stored document signed successfully",
    }
