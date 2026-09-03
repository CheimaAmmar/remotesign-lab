import secrets
import uuid

from datetime import datetime, timezone

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
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

from app.security.admin_auth import (
    require_admin,
)

router = APIRouter(
    prefix="/api/v1/devices",
    tags=["Devices"],
)


@router.post(
    "",
    response_model=DeviceRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
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
    dependencies=[Depends(require_admin)],
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
    dependencies=[Depends(require_admin)],
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


@router.get(
    "/{device_id}",
    response_model=DeviceRead,
    dependencies=[Depends(require_admin)],
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
