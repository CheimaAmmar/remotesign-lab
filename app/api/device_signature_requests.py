import uuid

from typing import Literal

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    Device,
    DeviceStatus,
    SignatureRequestStatus,
)
from app.security.device_auth import verify_device_hmac
from app.security.nonce_store import consume_nonce
from app.security.rate_limit import is_rate_limited
from app.services.audit_service import (
    add_audit_event,
    record_audit_event,
)
from app.services.signature_request_service import (
    claim_next_signature_request,
    mark_signature_request_failed,
    utc_now,
)


router = APIRouter(
    prefix="/api/v1/device/signature-requests",
    tags=["Device Signature Requests"],
)


class ClaimedSignatureRequestResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: uuid.UUID
    document_id: uuid.UUID
    document_hash: str = Field(
        pattern=r"^[0-9a-f]{64}$",
    )
    decision: Literal["APPROVE"]


class SignatureRequestStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: Literal["FAILED"]
    failure_code: str = Field(
        min_length=3,
        max_length=64,
        pattern=r"^[A-Z0-9_]+$",
    )


class SignatureRequestStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: uuid.UUID
    status: Literal["FAILED", "EXPIRED"]


def _source_ip(request: Request) -> str | None:
    return (
        request.client.host
        if request.client
        else None
    )


def _authenticate_device(
    database: Session,
    *,
    request: Request,
    x_device_uid: str,
    x_timestamp: str,
    x_nonce: str,
    x_signature: str,
    extra_data: str,
) -> Device:
    device_uid = x_device_uid.strip().upper()
    source_ip = _source_ip(request)
    device = database.scalar(
        select(Device).where(
            Device.device_uid == device_uid
        )
    )

    if device is None:
        record_audit_event(
            database,
            event_type="SIGNATURE_QUEUE_AUTH_REJECTED",
            outcome="FAILED",
            actor_type="DEVICE",
            actor_id=device_uid,
            request=request,
            http_status=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown device",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown device",
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
            actor_type="DEVICE",
            actor_id=device.device_uid,
            request=request,
            http_status=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed device queue requests",
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts",
        )

    if device.status != DeviceStatus.ACTIVE:
        record_audit_event(
            database,
            event_type="SIGNATURE_QUEUE_AUTH_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            actor_type="DEVICE",
            actor_id=device.device_uid,
            request=request,
            http_status=status.HTTP_403_FORBIDDEN,
            detail="Device is not active",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device is not active",
        )

    if device.device_secret is None:
        record_audit_event(
            database,
            event_type="SIGNATURE_QUEUE_AUTH_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            actor_type="DEVICE",
            actor_id=device.device_uid,
            request=request,
            http_status=status.HTTP_401_UNAUTHORIZED,
            detail="Missing device authentication secret",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing device secret",
        )

    valid_hmac = verify_device_hmac(
        device_secret=device.device_secret,
        method=request.method,
        path=request.url.path,
        timestamp=x_timestamp,
        nonce=x_nonce,
        received_signature=x_signature,
        extra_data=extra_data,
    )

    if not valid_hmac:
        record_audit_event(
            database,
            event_type="SIGNATURE_QUEUE_AUTH_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            actor_type="DEVICE",
            actor_id=device.device_uid,
            request=request,
            http_status=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device HMAC",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device authentication",
        )

    nonce_accepted = consume_nonce(
        database=database,
        device_id=device.id,
        nonce=x_nonce,
    )

    if not nonce_accepted:
        record_audit_event(
            database,
            event_type="SIGNATURE_QUEUE_AUTH_REJECTED",
            outcome="FAILED",
            device_id=device.id,
            actor_type="DEVICE",
            actor_id=device.device_uid,
            request=request,
            http_status=status.HTTP_401_UNAUTHORIZED,
            detail="Device queue nonce replay detected",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nonce already used",
        )

    return device


@router.post(
    "/next",
    response_model=ClaimedSignatureRequestResponse,
    responses={
        status.HTTP_204_NO_CONTENT: {
            "description": "No pending request for this device",
        }
    },
)
def claim_next_request(
    request: Request,
    x_device_uid: str = Header(
        ...,
        alias="X-Device-UID",
    ),
    x_timestamp: str = Header(
        ...,
        alias="X-Timestamp",
    ),
    x_nonce: str = Header(
        ...,
        alias="X-Nonce",
    ),
    x_signature: str = Header(
        ...,
        alias="X-Signature",
    ),
    database: Session = Depends(get_db),
) -> ClaimedSignatureRequestResponse | Response:
    """Claim the next pending request for one HMAC device.

    Canonical HMAC fields are METHOD, request path, the exact timestamp,
    the exact nonce and the normalized device UID, joined by LF without a
    trailing LF. The existing authentication/signing canonicals are not
    changed by this endpoint.
    """
    device_uid = x_device_uid.strip().upper()
    device = _authenticate_device(
        database,
        request=request,
        x_device_uid=x_device_uid,
        x_timestamp=x_timestamp,
        x_nonce=x_nonce,
        x_signature=x_signature,
        extra_data=device_uid,
    )
    signature_request = claim_next_signature_request(
        database,
        device=device,
    )
    device.last_seen = utc_now()

    if signature_request is None:
        database.commit()

        return Response(
            status_code=status.HTTP_204_NO_CONTENT
        )

    add_audit_event(
        database,
        event_type="SIGNATURE_REQUEST_CLAIMED",
        outcome="SUCCESS",
        actor_type="DEVICE",
        actor_id=device.device_uid,
        device_id=device.id,
        document_id=signature_request.document_id,
        signature_request_id=signature_request.id,
        request=request,
        http_status=status.HTTP_200_OK,
        detail=(
            "Signature request claimed by target device"
        ),
    )
    database.commit()
    database.refresh(signature_request)

    return ClaimedSignatureRequestResponse(
        request_id=signature_request.id,
        document_id=signature_request.document_id,
        document_hash=signature_request.document_hash,
        decision=signature_request.decision,
    )


@router.post(
    "/{request_id}/status",
    response_model=SignatureRequestStatusResponse,
)
def report_request_status(
    request_id: uuid.UUID,
    payload: SignatureRequestStatusUpdate,
    request: Request,
    x_device_uid: str = Header(
        ...,
        alias="X-Device-UID",
    ),
    x_timestamp: str = Header(
        ...,
        alias="X-Timestamp",
    ),
    x_nonce: str = Header(
        ...,
        alias="X-Nonce",
    ),
    x_signature: str = Header(
        ...,
        alias="X-Signature",
    ),
    database: Session = Depends(get_db),
) -> SignatureRequestStatusResponse:
    """Report a definitive queue failure with a fresh HMAC nonce.

    The canonical appends normalized device UID, `FAILED`, and the
    uppercase failure code after the common METHOD/path/timestamp/nonce
    fields. All fields are separated by LF, with no trailing LF.
    """
    device_uid = x_device_uid.strip().upper()
    failure_code = payload.failure_code.strip().upper()
    canonical_data = "\n".join(
        [
            device_uid,
            payload.state,
            failure_code,
        ]
    )
    device = _authenticate_device(
        database,
        request=request,
        x_device_uid=x_device_uid,
        x_timestamp=x_timestamp,
        x_nonce=x_nonce,
        x_signature=x_signature,
        extra_data=canonical_data,
    )
    signature_request = mark_signature_request_failed(
        database,
        request_id=request_id,
        device_id=device.id,
        failure_detail=(
            f"Device reported failure: {failure_code}"
        ),
    )

    if signature_request is None:
        database.commit()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Signature request not found for this device",
        )

    if signature_request.status not in (
        SignatureRequestStatus.FAILED,
        SignatureRequestStatus.EXPIRED,
    ):
        database.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Signature request cannot be failed in its current state",
        )

    add_audit_event(
        database,
        event_type="SIGNATURE_REQUEST_FAILED",
        outcome="FAILURE",
        actor_type="DEVICE",
        actor_id=device.device_uid,
        device_id=device.id,
        document_id=signature_request.document_id,
        signature_request_id=signature_request.id,
        failure_code=failure_code,
        request=request,
        http_status=status.HTTP_200_OK,
        detail=f"Failure state recorded: {failure_code}",
    )
    device.last_seen = utc_now()
    database.commit()
    database.refresh(signature_request)

    return SignatureRequestStatusResponse(
        request_id=signature_request.id,
        status=signature_request.status.value,
    )
