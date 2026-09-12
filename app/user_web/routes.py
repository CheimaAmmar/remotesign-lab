import uuid

from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import (
    APIRouter,
    Depends,
    Form,
    HTTPException,
    Request,
    status,
)
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import (
    Device,
    DeviceStatus,
    Document,
    DocumentSignature,
    SignatureRequest,
    SignatureRequestStatus,
    User,
    UserStatus,
)
from app.security.passwords import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    normalize_email,
    verify_dummy_password,
    verify_password,
)
from app.security.user_session import (
    USER_SESSION_COOKIE_NAME,
    USER_SESSION_TTL_SECONDS,
    UserSession,
    create_user_session,
    delete_user_session,
    get_request_user_session,
    has_viewed_document,
    mark_document_viewed,
    remaining_user_session_seconds,
    require_user_csrf,
    require_user_session,
)
from app.services.audit_service import (
    add_audit_event,
    record_audit_event,
)
from app.services.document_service import DOCUMENT_STORAGE
from app.services.pades_service import SIGNED_DOCUMENT_STORAGE
from app.services.signature_request_service import (
    create_signature_request,
    get_user_signature_request,
    utc_now,
)


USER_WEB_ROOT = Path(__file__).resolve().parent
USER_WEB_TEMPLATES = USER_WEB_ROOT / "templates"
USER_WEB_STATIC = USER_WEB_ROOT / "static"
CONSENT_VERSION = "stage-hsm-consent-v1"

USER_SIGNATURE_REQUEST_MESSAGES = {
    SignatureRequestStatus.PENDING: (
        "Authentifiez-vous sur le terminal ESP32."
    ),
    SignatureRequestStatus.CLAIMED: (
        "Terminal connecté."
    ),
    SignatureRequestStatus.AUTHENTICATING: (
        "Authentification en cours."
    ),
    SignatureRequestStatus.AUTHENTICATED: (
        "Signature cryptographique en cours."
    ),
    SignatureRequestStatus.SIGNED: (
        "Document signé avec succès."
    ),
    SignatureRequestStatus.FAILED: "Signature refusée.",
    SignatureRequestStatus.EXPIRED: (
        "Demande expirée."
    ),
}

settings = get_settings()

PAGE_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'self'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}

router = APIRouter(
    prefix="/user",
    tags=["User Web"],
    include_in_schema=False,
)


class UserSignatureRequestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_id: uuid.UUID
    document_viewed: Literal[True]
    signature_confirmed: Literal[True]


def _page_response(filename: str) -> FileResponse:
    return FileResponse(
        USER_WEB_TEMPLATES / filename,
        media_type="text/html",
        headers=PAGE_SECURITY_HEADERS,
    )


def _redirect(location: str) -> RedirectResponse:
    return RedirectResponse(
        url=location,
        status_code=status.HTTP_303_SEE_OTHER,
        headers=PAGE_SECURITY_HEADERS,
    )


def _json_response(
    content: dict,
    *,
    status_code: int = status.HTTP_200_OK,
) -> JSONResponse:
    return JSONResponse(
        content=content,
        status_code=status_code,
        headers=NO_STORE_HEADERS,
    )


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _normalized_origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if (
        scheme not in {"http", "https"}
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None

    if port is None:
        port = 443 if scheme == "https" else 80

    return scheme, hostname.lower(), port


def _request_origin(request: Request) -> tuple[str, str, int] | None:
    try:
        scheme = request.url.scheme.lower()
        hostname = request.url.hostname
        port = request.url.port
    except ValueError:
        return None

    if scheme not in {"http", "https"} or hostname is None:
        return None

    if port is None:
        port = 443 if scheme == "https" else 80

    return scheme, hostname.lower(), port


def _reject_cross_site_login(request: Request) -> None:
    fetch_site = request.headers.get("Sec-Fetch-Site")
    origin = request.headers.get("Origin")

    if origin is not None and origin != "null":
        cross_site = (
            _normalized_origin(origin) != _request_origin(request)
        )
    else:
        cross_site = fetch_site != "same-origin"

    if cross_site:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-site login is not allowed",
        )


def _request_response(
    signature_request: SignatureRequest,
    *,
    document: Document | None = None,
    signature: DocumentSignature | None = None,
    signer_name: str | None = None,
) -> dict:
    response = {
        "request_id": str(signature_request.id),
        "document_id": str(signature_request.document_id),
        "state": signature_request.status.value,
        "message": USER_SIGNATURE_REQUEST_MESSAGES[
            signature_request.status
        ],
    }

    if signature_request.signature_id is not None:
        response["signature_id"] = str(signature_request.signature_id)

    if signature_request.status == SignatureRequestStatus.SIGNED:
        completed_at = getattr(
            signature_request,
            "completed_at",
            None,
        )

        if document is not None:
            response["filename"] = document.original_filename

        if signature is not None:
            response["algorithm"] = signature.algorithm
            signing_time = getattr(
                signature,
                "signing_time",
                None,
            )
            response["signed_document_available"] = bool(
                getattr(
                    signature,
                    "signed_document_path",
                    None,
                )
            )

            if signing_time is not None:
                response["signed_at"] = signing_time.isoformat()
            elif completed_at is not None:
                response["signed_at"] = completed_at.isoformat()

            for field in (
                "pades_profile",
                "certificate_subject",
                "tsa_certificate_subject",
            ):
                value = getattr(signature, field, None)

                if value:
                    response[field] = value

            if signer_name:
                response["signer_name"] = signer_name

            timestamp_time = getattr(
                signature,
                "timestamp_time",
                None,
            )

            if timestamp_time is not None:
                response["timestamp_time"] = (
                    timestamp_time.isoformat()
                )
        elif completed_at is not None:
            response["signed_at"] = completed_at.isoformat()

    return response


@router.get("/login")
def user_login_page(request: Request) -> Response:
    if get_request_user_session(request) is not None:
        return _redirect("/user")

    return _page_response("login.html")


@router.post("/login")
def create_user_web_session(
    request: Request,
    email: Annotated[str, Form(...)],
    password: Annotated[str, Form(...)],
    database: Session = Depends(get_db),
) -> Response:
    _reject_cross_site_login(request)
    user = None

    try:
        normalized_email = normalize_email(email)
        user = database.scalar(
            select(User)
            .where(User.email == normalized_email)
            .limit(1)
        )
    except ValueError:
        normalized_email = None

    valid_password = False
    password_length_valid = (
        PASSWORD_MIN_LENGTH
        <= len(password)
        <= PASSWORD_MAX_LENGTH
    )
    password_candidate = (
        password
        if password_length_valid
        else "invalid-password-length"
    )

    if (
        user is not None
        and user.password_hash
        and password_length_valid
    ):
        valid_password = verify_password(
            password_candidate,
            user.password_hash,
        )
    else:
        verify_dummy_password(password_candidate)

    if (
        normalized_email is None
        or user is None
        or user.status != UserStatus.ACTIVE
        or not valid_password
    ):
        record_audit_event(
            database,
            event_type="USER_LOGIN_FAILED",
            outcome="DENIED",
            actor_type="USER",
            actor_id=(
                str(user.id)
                if user is not None
                else None
            ),
            user_id=(user.id if user is not None else None),
            failure_code="INVALID_USER_CREDENTIALS",
            request=request,
            http_status=status.HTTP_303_SEE_OTHER,
            detail="User Web login rejected",
        )
        return _redirect("/user/login?error=invalid")

    delete_user_session(
        request.cookies.get(USER_SESSION_COOKIE_NAME)
    )
    session_token, _session = create_user_session(user.id)
    response = _redirect("/user")
    response.set_cookie(
        key=USER_SESSION_COOKIE_NAME,
        value=session_token,
        max_age=USER_SESSION_TTL_SECONDS,
        secure=True,
        httponly=True,
        samesite="strict",
        path="/user",
    )

    add_audit_event(
        database,
        event_type="USER_WEB_LOGIN",
        outcome="SUCCESS",
        actor_type="USER",
        user_id=user.id,
        request=request,
        http_status=status.HTTP_303_SEE_OTHER,
        detail="User Web session created",
    )
    database.commit()

    return response


@router.get("")
def user_interface(request: Request) -> Response:
    if get_request_user_session(request) is None:
        return _redirect("/user/login")

    return _page_response("index.html")


@router.get("/api/session")
def user_session_information(
    session: UserSession = Depends(require_user_session),
    database: Session = Depends(get_db),
) -> JSONResponse:
    user = database.get(User, session.user_id)

    if user is None or user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User session is no longer valid",
        )

    return _json_response(
        {
            "authenticated": True,
            "user": {
                "user_id": str(user.id),
                "full_name": user.full_name,
                "email": user.email,
            },
            "csrf_token": session.csrf_token,
            "expires_in": remaining_user_session_seconds(session),
        }
    )


@router.post("/logout")
def user_logout(
    request: Request,
    session: UserSession = Depends(require_user_csrf),
    database: Session = Depends(get_db),
) -> JSONResponse:
    delete_user_session(
        request.cookies.get(USER_SESSION_COOKIE_NAME)
    )
    response = _json_response({"logged_out": True})
    response.delete_cookie(
        key=USER_SESSION_COOKIE_NAME,
        path="/user",
        secure=True,
        httponly=True,
        samesite="strict",
    )

    if hasattr(database, "add"):
        add_audit_event(
            database,
            event_type="USER_LOGOUT",
            outcome="SUCCESS",
            actor_type="USER",
            user_id=session.user_id,
            request=request,
            http_status=status.HTTP_200_OK,
        )
        database.commit()

    return response


@router.get("/api/documents")
def list_user_documents(
    session: UserSession = Depends(require_user_session),
    database: Session = Depends(get_db),
) -> JSONResponse:
    documents = list(
        database.scalars(
            select(Document)
            .where(Document.user_id == session.user_id)
            .order_by(Document.created_at.desc(), Document.id.desc())
        ).all()
    )
    document_ids = [document.id for document in documents]
    latest_by_document: dict[uuid.UUID, SignatureRequest] = {}

    if document_ids:
        requests = database.scalars(
            select(SignatureRequest)
            .where(
                SignatureRequest.user_id == session.user_id,
                SignatureRequest.document_id.in_(document_ids),
            )
            .order_by(
                SignatureRequest.created_at.desc(),
                SignatureRequest.id.desc(),
            )
        ).all()

        for signature_request in requests:
            latest_by_document.setdefault(
                signature_request.document_id,
                signature_request,
            )

    signature_ids = [
        signature_request.signature_id
        for signature_request in latest_by_document.values()
        if signature_request.signature_id is not None
    ]
    signatures_by_id: dict[uuid.UUID, DocumentSignature] = {}
    current_user = (
        database.get(User, session.user_id)
        if signature_ids
        else None
    )

    if signature_ids:
        signatures = database.scalars(
            select(DocumentSignature).where(
                DocumentSignature.id.in_(signature_ids)
            )
        ).all()
        signatures_by_id = {
            signature.id: signature for signature in signatures
        }

    return _json_response(
        {
            "documents": [
                {
                    "document_id": str(document.id),
                    "filename": document.original_filename,
                    "size_bytes": document.size_bytes,
                    "document_hash": document.document_hash,
                    "created_at": document.created_at.isoformat(),
                    "request": (
                        _request_response(
                            latest_by_document[document.id],
                            document=document,
                            signature=signatures_by_id.get(
                                latest_by_document[
                                    document.id
                                ].signature_id
                            ),
                            signer_name=(
                                current_user.full_name
                                if current_user is not None
                                else None
                            ),
                        )
                        if document.id in latest_by_document
                        else None
                    ),
                }
                for document in documents
            ]
        }
    )


@router.get("/documents/{document_id}/view")
def view_user_document(
    document_id: uuid.UUID,
    request: Request,
    session: UserSession = Depends(require_user_session),
    database: Session = Depends(get_db),
) -> FileResponse:
    document = database.scalar(
        select(Document).where(
            Document.id == document_id,
            Document.user_id == session.user_id,
        )
    )

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    storage_root = DOCUMENT_STORAGE.resolve()
    document_path = (
        DOCUMENT_STORAGE / document.stored_filename
    ).resolve()

    if (
        not document_path.is_relative_to(storage_root)
        or not document_path.is_file()
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document file not found",
        )

    mark_document_viewed(session, document.id)

    record_audit_event(
        database,
        event_type="DOCUMENT_VIEWED",
        outcome="SUCCESS",
        actor_type="USER",
        user_id=session.user_id,
        document_id=document.id,
        request=request,
        http_status=status.HTTP_200_OK,
        details={"delivery": "inline"},
    )

    return FileResponse(
        document_path,
        media_type="application/pdf",
        filename=document.original_filename,
        content_disposition_type="inline",
        headers=NO_STORE_HEADERS,
    )


@router.get("/documents/{document_id}/signed")
def download_user_signed_document(
    document_id: uuid.UUID,
    request: Request,
    session: UserSession = Depends(require_user_session),
    database: Session = Depends(get_db),
) -> FileResponse:
    document = database.scalar(
        select(Document).where(
            Document.id == document_id,
            Document.user_id == session.user_id,
        )
    )

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Signed document not found",
        )

    signature = database.scalar(
        select(DocumentSignature)
        .where(
            DocumentSignature.document_id == document.id,
            DocumentSignature.user_id == session.user_id,
            DocumentSignature.signed_document_path.is_not(None),
        )
        .order_by(
            DocumentSignature.created_at.desc(),
            DocumentSignature.id.desc(),
        )
        .limit(1)
    )

    if signature is None or not signature.signed_document_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Signed document not found",
        )

    storage_root = SIGNED_DOCUMENT_STORAGE.resolve()
    signed_document_path = (
        SIGNED_DOCUMENT_STORAGE
        / signature.signed_document_path
    ).resolve()

    if (
        not signed_document_path.is_relative_to(storage_root)
        or not signed_document_path.is_file()
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Signed document file not found",
        )

    record_audit_event(
        database,
        event_type="SIGNED_DOCUMENT_DOWNLOADED",
        outcome="SUCCESS",
        actor_type="USER",
        user_id=session.user_id,
        document_id=document.id,
        signature_id=getattr(signature, "id", None),
        request=request,
        http_status=status.HTTP_200_OK,
        details={"delivery": "attachment"},
    )

    return FileResponse(
        signed_document_path,
        media_type="application/pdf",
        filename=f"signed-{document.id}.pdf",
        content_disposition_type="attachment",
        headers=NO_STORE_HEADERS,
    )


@router.post(
    "/api/signature-requests",
    status_code=status.HTTP_202_ACCEPTED,
)
def create_user_signature_request(
    payload: UserSignatureRequestCreate,
    request: Request,
    session: UserSession = Depends(require_user_csrf),
    database: Session = Depends(get_db),
) -> JSONResponse:
    document = database.scalar(
        select(Document).where(
            Document.id == payload.document_id,
            Document.user_id == session.user_id,
        ).with_for_update()
    )

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    if not has_viewed_document(session, document.id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The document must be viewed before signing",
        )

    existing_request = database.scalar(
        select(SignatureRequest)
        .where(
            SignatureRequest.user_id == session.user_id,
            SignatureRequest.document_id == document.id,
            SignatureRequest.status.in_(
                (
                    SignatureRequestStatus.PENDING,
                    SignatureRequestStatus.CLAIMED,
                    SignatureRequestStatus.AUTHENTICATING,
                    SignatureRequestStatus.AUTHENTICATED,
                )
            ),
        )
        .with_for_update()
        .limit(1)
    )

    if existing_request is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A signature request is already in progress",
        )

    target_device_uid = settings.signature_device_uid.strip().upper()
    device = database.scalar(
        select(Device)
        .where(Device.device_uid == target_device_uid)
        .limit(1)
    )

    if (
        device is None
        or device.status != DeviceStatus.ACTIVE
        or device.device_secret is None
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configured signature device is unavailable",
        )

    consented_at = utc_now()
    signature_request = create_signature_request(
        database,
        owner_session_id=session.id,
        user_id=session.user_id,
        device=device,
        document=document,
        consented_at=consented_at,
        consent_version=CONSENT_VERSION,
    )
    database.flush()
    add_audit_event(
        database,
        event_type="CONSENT_RECORDED",
        outcome="SUCCESS",
        actor_type="USER",
        user_id=session.user_id,
        device_id=device.id,
        document_id=document.id,
        signature_request_id=signature_request.id,
        request=request,
        http_status=status.HTTP_202_ACCEPTED,
        details={"consent_version": CONSENT_VERSION},
    )
    add_audit_event(
        database,
        event_type="SIGNATURE_REQUEST_CREATED",
        outcome="SUCCESS",
        actor_type="USER",
        user_id=session.user_id,
        device_id=device.id,
        document_id=document.id,
        signature_request_id=signature_request.id,
        request=request,
        http_status=status.HTTP_202_ACCEPTED,
        detail="User signature request created",
    )
    database.commit()

    return _json_response(
        _request_response(signature_request),
        status_code=status.HTTP_202_ACCEPTED,
    )


@router.get("/api/signature-requests/{request_id}")
def user_signature_request_status(
    request_id: uuid.UUID,
    session: UserSession = Depends(require_user_session),
    database: Session = Depends(get_db),
) -> JSONResponse:
    signature_request = get_user_signature_request(
        database,
        request_id=request_id,
        user_id=session.user_id,
    )

    if signature_request is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Signature request not found",
        )

    document = database.get(
        Document,
        signature_request.document_id,
    )
    signature = (
        database.get(
            DocumentSignature,
            signature_request.signature_id,
        )
        if signature_request.signature_id is not None
        else None
    )
    current_user = (
        database.get(User, session.user_id)
        if signature is not None
        else None
    )
    response = _json_response(
        _request_response(
            signature_request,
            document=document,
            signature=signature,
            signer_name=(
                current_user.full_name
                if current_user is not None
                else None
            ),
        )
    )
    database.commit()

    return response
