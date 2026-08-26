import secrets
import uuid

from datetime import datetime, timezone

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    status,
)

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db

from app.models import (
    Device,
    DeviceStatus,
    User,
    UserStatus,
)

from app.schemas import (
    DeviceCreate,
    DeviceRead,
)

from app.security.device_auth import (
    verify_device_hmac,
)

from app.security.nonce_store import (
    is_nonce_used,
    store_nonce,
)

router = APIRouter(
    prefix="/api/v1/devices",
    tags=["Devices"],
)


@router.post(
    "",
    response_model=DeviceRead,
    status_code=status.HTTP_201_CREATED,
)
def create_device(
    payload: DeviceCreate,
    database: Session = Depends(get_db),
) -> Device:
    normalized_device_uid = payload.device_uid.strip().upper()
    normalized_display_name = payload.display_name.strip()

    user = database.get(User, payload.user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot assign a device to an inactive user",
        )

    existing_device = database.scalar(
        select(Device).where(
            Device.device_uid == normalized_device_uid
        )
    )

    if existing_device is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Device UID already exists",
        )

    device = Device(
        device_uid=normalized_device_uid,
        display_name=normalized_display_name,
        user_id=user.id,
        rfid_enabled=payload.rfid_enabled,
        fingerprint_enabled=payload.fingerprint_enabled,
    )

    database.add(device)

    try:
        database.commit()
        database.refresh(device)

    except IntegrityError as error:
        database.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to create device",
        ) from error

    return device


@router.get(
    "",
    response_model=list[DeviceRead],
)
def list_devices(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    database: Session = Depends(get_db),
) -> list[Device]:
    query = (
        select(Device)
        .order_by(Device.created_at.desc())
        .offset(offset)
        .limit(limit)
    )

    return list(database.scalars(query).all())


@router.post(
    "/{device_id}/enroll",
    status_code=status.HTTP_200_OK,
)
def enroll_device(
    device_id: uuid.UUID,
    database: Session = Depends(get_db),
) -> dict:
    device = database.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    if device.status == DeviceStatus.REVOKED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device is revoked",
        )

    if device.status == DeviceStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Device is already enrolled",
        )

    device_secret = secrets.token_hex(32)

    device.device_secret = device_secret
    device.status = DeviceStatus.ACTIVE
    device.last_seen = datetime.now(timezone.utc)

    database.commit()
    database.refresh(device)

    return {
        "device_uid": device.device_uid,
        "device_secret": device_secret,
        "status": device.status,
        "last_seen": device.last_seen,
    }

@router.post(
    "/auth-test",
    status_code=status.HTTP_200_OK,
)
def authenticated_device_test(
    request: Request,
    x_device_uid: str = Header(...),
    x_timestamp: str = Header(...),
    x_nonce: str = Header(...),
    x_signature: str = Header(...),
    database: Session = Depends(get_db),
) -> dict:

    normalized_uid = x_device_uid.strip().upper()

    device = database.scalar(
        select(Device).where(
            Device.device_uid == normalized_uid
        )
    )

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown device",
        )

    if device.status != DeviceStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device is not active",
        )

    if device.device_secret is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device has no authentication secret",
        )

    # --------------------------------------------------
    # Anti-replay : nonce déjà utilisé ?
    # --------------------------------------------------

    if is_nonce_used(
        device.device_uid,
        x_nonce,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nonce already used",
        )

    # --------------------------------------------------
    # Vérification HMAC
    # --------------------------------------------------

    valid = verify_device_hmac(
        device_secret=device.device_secret,
        method=request.method,
        path=request.url.path,
        timestamp=x_timestamp,
        nonce=x_nonce,
        received_signature=x_signature,
    )

    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device authentication",
        )

    # --------------------------------------------------
    # HMAC valide → nonce consommé
    # --------------------------------------------------

    store_nonce(
        device.device_uid,
        x_nonce,
    )

    # --------------------------------------------------
    # Mise à jour dernière connexion
    # --------------------------------------------------

    device.last_seen = datetime.now(timezone.utc)

    database.commit()

    return {
        "authenticated": True,
        "device_uid": device.device_uid,
        "message": "ESP32-C3 authenticated successfully",
    }

@router.get(
    "/{device_id}",
    response_model=DeviceRead,
)
def get_device(
    device_id: uuid.UUID,
    database: Session = Depends(get_db),
) -> Device:
    device = database.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    return device

@router.post(
    "/local-auth",
    status_code=status.HTTP_200_OK,
)
def local_auth(
    request: Request,
    x_device_uid: str = Header(...),
    x_timestamp: str = Header(...),
    x_nonce: str = Header(...),
    x_rfid_uid: str = Header(...),
    x_fingerprint_id: str = Header(...),
    x_signature: str = Header(...),
    database: Session = Depends(get_db),
) -> dict:

    normalized_device_uid = x_device_uid.strip().upper()
    normalized_rfid_uid = x_rfid_uid.strip().upper()
    fingerprint_id = x_fingerprint_id.strip()

    device = database.scalar(
        select(Device).where(
            Device.device_uid == normalized_device_uid
        )
    )

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown device",
        )

    if device.status != DeviceStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device is not active",
        )

    if not device.rfid_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="RFID disabled",
        )

    if not device.fingerprint_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Fingerprint disabled",
        )

    if device.device_secret is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing device secret",
        )

    if is_nonce_used(
        device.device_uid,
        x_nonce,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nonce already used",
        )

    extra_data = (
        normalized_rfid_uid
        + "\n"
        + fingerprint_id
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device authentication",
        )

    store_nonce(
        device.device_uid,
        x_nonce,
    )

    device.last_seen = datetime.now(timezone.utc)

    database.commit()

    return {
        "authenticated": True,
        "device_uid": device.device_uid,
        "rfid_uid": normalized_rfid_uid,
        "fingerprint_id": fingerprint_id,
        "message": "Local authentication proof accepted",
    }
