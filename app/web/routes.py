import uuid

from pathlib import Path
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    Document,
    DocumentSignature,
    SignatureRequestStatus,
    User,
    UserStatus,
)
from app.security.admin_auth import require_admin
from app.security.ui_session import (
    UI_SESSION_COOKIE_NAME,
    UI_SESSION_TTL_SECONDS,
    UiSession,
    create_ui_session,
    delete_ui_session,
    get_request_ui_session,
    remaining_session_seconds,
    require_ui_csrf,
    require_ui_session,
)
from app.services.document_service import store_document
from app.services.audit_service import (
    add_audit_event,
    record_audit_event,
)
from app.services.signature_request_service import (
    get_latest_signature_request_for_document,
)


WEB_ROOT = Path(__file__).resolve().parent
WEB_TEMPLATES = WEB_ROOT / "templates"
WEB_STATIC = WEB_ROOT / "static"

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
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=()"
    ),
}

NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}

router = APIRouter(
    prefix="/ui",
    tags=["Web UI"],
    include_in_schema=False,
)


SIGNATURE_REQUEST_MESSAGES = {
    SignatureRequestStatus.PENDING: (
        "Demande créée par l'utilisateur. "
        "En attente d'authentification forte."
    ),
    SignatureRequestStatus.CLAIMED: (
        "Demande récupérée par le terminal."
    ),
    SignatureRequestStatus.AUTHENTICATING: (
        "Authentification forte en cours."
    ),
    SignatureRequestStatus.AUTHENTICATED: (
        "Identité vérifiée. Signature cryptographique en cours."
    ),
    SignatureRequestStatus.SIGNED: (
        "Signature réussie."
    ),
    SignatureRequestStatus.FAILED: (
        "Signature refusée."
    ),
    SignatureRequestStatus.EXPIRED: (
        "Demande expirée."
    ),
}


def _signature_request_content(
    signature_request,
    database: Session,
) -> dict:
    content = {
        "request_id": str(signature_request.id),
        "document_id": str(signature_request.document_id),
        "state": signature_request.status.value,
        "message": SIGNATURE_REQUEST_MESSAGES[
            signature_request.status
        ],
    }

    if signature_request.signature_id is not None:
        content["signature_id"] = str(
            signature_request.signature_id
        )
        signature = database.get(
            DocumentSignature,
            signature_request.signature_id,
        )

        if signature is not None:
            content["algorithm"] = signature.algorithm
            signer = database.get(User, signature.user_id)

            if signer is not None:
                content["signer_name"] = signer.full_name
            signing_time = getattr(
                signature,
                "signing_time",
                None,
            )

            if signing_time is not None:
                content["signed_at"] = (
                    signing_time.isoformat()
                )
            elif signature.created_at is not None:
                content["signed_at"] = (
                    signature.created_at.isoformat()
                )

            for field in (
                "pades_profile",
                "certificate_subject",
                "tsa_certificate_subject",
            ):
                value = getattr(signature, field, None)

                if value:
                    content[field] = value

            timestamp_time = getattr(
                signature,
                "timestamp_time",
                None,
            )

            if timestamp_time is not None:
                content["timestamp_time"] = (
                    timestamp_time.isoformat()
                )

    return content


def _page_response(filename: str) -> FileResponse:
    return FileResponse(
        WEB_TEMPLATES / filename,
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


@router.get("/login")
def login_page(request: Request) -> Response:
    if get_request_ui_session(request) is not None:
        return _redirect("/ui")

    return _page_response("login.html")


@router.post("/login")
def create_web_session(
    request: Request,
    admin_key: Annotated[str, Form(...)],
    database: Session = Depends(get_db),
) -> Response:
    try:
        require_admin(admin_key)
    except HTTPException:
        if hasattr(database, "get_bind"):
            record_audit_event(
                database,
                event_type="ADMIN_LOGIN_FAILED",
                outcome="DENIED",
                actor_type="ADMIN",
                failure_code="INVALID_ADMIN_CREDENTIALS",
                request=request,
                http_status=status.HTTP_303_SEE_OTHER,
                detail="Administrator Web login rejected",
            )
        return _redirect("/ui/login?error=1")

    delete_ui_session(
        request.cookies.get(
            UI_SESSION_COOKIE_NAME
        )
    )

    session_token, _session = create_ui_session()
    response = _redirect("/ui")

    response.set_cookie(
        key=UI_SESSION_COOKIE_NAME,
        value=session_token,
        max_age=UI_SESSION_TTL_SECONDS,
        secure=True,
        httponly=True,
        samesite="strict",
        path="/ui",
    )

    if hasattr(database, "add"):
        add_audit_event(
            database,
            event_type="ADMIN_LOGIN_SUCCESS",
            outcome="SUCCESS",
            actor_type="ADMIN",
            actor_id="prototype-admin",
            request=request,
            http_status=status.HTTP_303_SEE_OTHER,
            detail="Administrator Web session created",
        )
        database.commit()

    return response


@router.get("")
def web_interface(request: Request) -> Response:
    if get_request_ui_session(request) is None:
        return _redirect("/ui/login")

    return _page_response("index.html")


@router.get("/api/session")
def session_information(
    session: UiSession = Depends(
        require_ui_session
    ),
) -> JSONResponse:
    return _json_response(
        {
            "authenticated": True,
            "csrf_token": session.csrf_token,
            "expires_in": remaining_session_seconds(
                session
            ),
        }
    )


@router.post("/logout")
def logout(
    request: Request,
    session: UiSession = Depends(
        require_ui_csrf
    ),
    database: Session = Depends(get_db),
) -> JSONResponse:
    delete_ui_session(
        request.cookies.get(
            UI_SESSION_COOKIE_NAME
        )
    )

    response = _json_response(
        {"logged_out": True}
    )
    response.delete_cookie(
        key=UI_SESSION_COOKIE_NAME,
        path="/ui",
        secure=True,
        httponly=True,
        samesite="strict",
    )

    if hasattr(database, "add"):
        add_audit_event(
            database,
            event_type="ADMIN_LOGOUT",
            outcome="SUCCESS",
            actor_type="ADMIN",
            actor_id="prototype-admin",
            request=request,
            http_status=status.HTTP_200_OK,
        )
        database.commit()

    return response


@router.post(
    "/api/documents/upload",
    status_code=status.HTTP_201_CREATED,
)
def upload_document_from_web(
    request: Request,
    file: UploadFile = File(...),
    user_id: uuid.UUID = Form(...),
    _session: UiSession = Depends(
        require_ui_csrf
    ),
    database: Session = Depends(get_db),
) -> JSONResponse:
    user = database.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot assign a document to an inactive user",
        )

    result = store_document(
        file=file,
        database=database,
        user_id=user.id,
    )
    result["user_id"] = str(user.id)
    result["message"] = (
        "Document attribué à l'utilisateur. "
        "En attente d'une demande de signature depuis "
        "l'espace utilisateur."
    )

    document_id = uuid.UUID(result["document_id"])
    add_audit_event(
        database,
        event_type="DOCUMENT_UPLOADED",
        outcome="SUCCESS",
        actor_type="ADMIN",
        actor_id="prototype-admin",
        user_id=user.id,
        document_id=document_id,
        request=request,
        http_status=status.HTTP_201_CREATED,
        details={
            "filename": result.get("filename"),
            "size_bytes": result.get("size_bytes"),
        },
    )
    add_audit_event(
        database,
        event_type="DOCUMENT_ASSIGNED",
        outcome="SUCCESS",
        actor_type="ADMIN",
        actor_id="prototype-admin",
        user_id=user.id,
        document_id=document_id,
        request=request,
        http_status=status.HTTP_201_CREATED,
        detail="Document assigned to its owner",
    )
    database.commit()

    return _json_response(
        result,
        status_code=status.HTTP_201_CREATED,
    )


@router.get("/api/users")
def active_users_for_document_assignment(
    _session: UiSession = Depends(
        require_ui_session
    ),
    database: Session = Depends(get_db),
) -> JSONResponse:
    users = database.scalars(
        select(User)
        .where(User.status == UserStatus.ACTIVE)
        .order_by(User.full_name.asc(), User.username.asc())
    ).all()

    return _json_response(
        {
            "users": [
                {
                    "user_id": str(user.id),
                    "username": user.username,
                    "full_name": user.full_name,
                    "email": user.email,
                }
                for user in users
            ]
        }
    )


@router.get(
    "/api/documents/{document_id}",
)
def document_details_for_admin(
    document_id: uuid.UUID,
    _session: UiSession = Depends(
        require_ui_session
    ),
    database: Session = Depends(get_db),
) -> JSONResponse:
    document = database.get(Document, document_id)

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    return _json_response(
        {
            "document_id": str(document.id),
            "filename": document.original_filename,
            "size_bytes": document.size_bytes,
            "document_hash": document.document_hash,
            "user_id": (
                str(document.user_id)
                if document.user_id is not None
                else None
            ),
            "algorithm": "SHA-256",
        }
    )


@router.get(
    "/api/documents/{document_id}/signature-request",
)
def document_signature_request_status(
    document_id: uuid.UUID,
    _session: UiSession = Depends(
        require_ui_session
    ),
    database: Session = Depends(get_db),
) -> Response:
    document = database.get(Document, document_id)

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    signature_request = (
        get_latest_signature_request_for_document(
            database,
            document_id=document.id,
        )
    )

    if signature_request is None:
        return Response(
            status_code=status.HTTP_204_NO_CONTENT,
            headers=NO_STORE_HEADERS,
        )

    response_content = _signature_request_content(
        signature_request,
        database,
    )

    return _json_response(response_content)
