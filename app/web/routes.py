import hmac
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
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import (
    Device,
    DeviceStatus,
    Document,
    SignatureRequestStatus,
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
from app.services.audit_service import add_audit_event
from app.services.signature_request_service import (
    create_signature_request,
    get_owned_signature_request,
)


WEB_ROOT = Path(__file__).resolve().parent
WEB_TEMPLATES = WEB_ROOT / "templates"
WEB_STATIC = WEB_ROOT / "static"

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


class SignatureRequestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_id: uuid.UUID
    document_hash: str = Field(
        pattern=r"^[0-9a-fA-F]{64}$",
    )


SIGNATURE_REQUEST_MESSAGES = {
    SignatureRequestStatus.PENDING: (
        "Waiting for the target ESP32 to claim the request"
    ),
    SignatureRequestStatus.CLAIMED: (
        "The target ESP32 claimed the request"
    ),
    SignatureRequestStatus.AUTHENTICATING: (
        "RFID and DY50 authentication is in progress"
    ),
    SignatureRequestStatus.AUTHENTICATED: (
        "RFID and DY50 authentication succeeded"
    ),
    SignatureRequestStatus.SIGNED: (
        "Document signature completed"
    ),
    SignatureRequestStatus.FAILED: (
        "The signature request failed"
    ),
    SignatureRequestStatus.EXPIRED: (
        "The signature request expired"
    ),
}


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
) -> Response:
    try:
        require_admin(admin_key)
    except HTTPException:
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
    _session: UiSession = Depends(
        require_ui_csrf
    ),
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

    return response


@router.post(
    "/api/documents/upload",
    status_code=status.HTTP_201_CREATED,
)
def upload_document_from_web(
    file: UploadFile = File(...),
    _session: UiSession = Depends(
        require_ui_csrf
    ),
    database: Session = Depends(get_db),
) -> JSONResponse:
    result = store_document(
        file=file,
        database=database,
    )

    return _json_response(
        result,
        status_code=status.HTTP_201_CREATED,
    )


@router.post(
    "/api/signature-requests",
    status_code=status.HTTP_202_ACCEPTED,
)
def request_signature_from_web(
    payload: SignatureRequestCreate,
    session: UiSession = Depends(
        require_ui_csrf
    ),
    database: Session = Depends(get_db),
) -> JSONResponse:
    document = database.get(
        Document,
        payload.document_id,
    )

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    supplied_hash = payload.document_hash.lower()

    if not hmac.compare_digest(
        supplied_hash,
        document.document_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Document hash mismatch",
        )

    target_device_uid = (
        settings.signature_device_uid.strip().upper()
    )
    device = database.scalar(
        select(Device)
        .where(Device.device_uid == target_device_uid)
        .limit(1)
    )

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configured signature device is unavailable",
        )

    if (
        device.status != DeviceStatus.ACTIVE
        or device.device_secret is None
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configured signature device is unavailable",
        )

    signature_request = create_signature_request(
        database,
        owner_session_id=session.id,
        device=device,
        document=document,
    )
    database.flush()

    add_audit_event(
        database,
        event_type="SIGNATURE_REQUEST_CREATED",
        outcome="SUCCESS",
        device_id=device.id,
        document_id=document.id,
        detail="Signature request queued for target device",
    )

    response_content = {
        "request_id": str(signature_request.id),
        "document_id": str(document.id),
        "state": signature_request.status.value,
        "message": SIGNATURE_REQUEST_MESSAGES[
            signature_request.status
        ],
    }
    database.commit()

    return _json_response(
        response_content,
        status_code=status.HTTP_202_ACCEPTED,
    )


@router.get(
    "/api/signature-requests/{request_id}",
)
def signature_request_status(
    request_id: uuid.UUID,
    session: UiSession = Depends(
        require_ui_session
    ),
    database: Session = Depends(get_db),
) -> JSONResponse:
    signature_request = get_owned_signature_request(
        database,
        request_id=request_id,
        owner_session_id=session.id,
    )

    if signature_request is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Signature request not found",
        )

    response_content = {
        "request_id": str(signature_request.id),
        "document_id": str(signature_request.document_id),
        "state": signature_request.status.value,
        "message": SIGNATURE_REQUEST_MESSAGES[
            signature_request.status
        ],
    }

    if signature_request.signature_id is not None:
        response_content["signature_id"] = str(
            signature_request.signature_id
        )

    database.commit()

    return _json_response(response_content)
