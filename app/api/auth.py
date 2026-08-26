import secrets
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
    User,
    UserStatus,
)

from app.security.device_auth import (
    verify_device_hmac,
)

from app.security.nonce_store import (
    is_nonce_used,
    store_nonce,
)


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
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
    x_signature: str = Header(...),

    database: Session = Depends(get_db),
) -> dict:

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

    if device.device_secret is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing device secret",
        )

    # ==================================================
    # ANTI REPLAY
    # ==================================================

    if is_nonce_used(
        device.device_uid,
        x_nonce,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nonce already used",
        )

    # ==================================================
    # HMAC
    #
    # POST
    # /api/v1/auth/challenge
    # timestamp
    # nonce
    # RFID
    # ==================================================

    valid = verify_device_hmac(
        device_secret=device.device_secret,
        method=request.method,
        path=request.url.path,
        timestamp=x_timestamp,
        nonce=x_nonce,
        received_signature=x_signature,
        extra_data=rfid_uid,
    )

    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device authentication",
        )

    # ==================================================
    # VERIFICATION RFID
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
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User not found",
        )

    if user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User disabled",
        )

    # HMAC valide :
    # consommation du nonce

    store_nonce(
        device.device_uid,
        x_nonce,
    )

    # ==================================================
    # CHALLENGE 256 BITS
    # ==================================================

    challenge = secrets.token_hex(32)

    now = datetime.now(
        timezone.utc
    )

    expires_at = (
        now
        + timedelta(seconds=60)
    )

    auth_session = AuthenticationSession(
        device_id=device.id,
        user_id=user.id,
        rfid_uid=rfid_uid,
        challenge=challenge,
        expires_at=expires_at,
    )

    database.add(
        auth_session
    )

    device.last_seen = now

    database.commit()

    database.refresh(
        auth_session
    )

    return {
        "session_id": str(
            auth_session.id
        ),
        "challenge": challenge,
        "expires_in": 60,
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

    x_signature: str = Header(...),

    database: Session = Depends(get_db),
) -> dict:

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

    # ==================================================
    # FINGERPRINT
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
    # SESSION UUID
    # ==================================================

    try:
        session_id = uuid.UUID(
            x_session_id
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

    if device.status != DeviceStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device is not active",
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

    # ==================================================
    # ANTI REPLAY
    # ==================================================

    if is_nonce_used(
        device.device_uid,
        x_nonce,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nonce already used",
        )

    # ==================================================
    # HMAC AVANT CONSULTATION DE LA SESSION
    #
    # POST
    # /api/v1/auth/complete
    # timestamp
    # nonce
    # session_id
    # challenge
    # RFID
    # fingerprint_id
    # ==================================================

    extra_data = "\n".join(
        [
            session_id_string,
            challenge,
            rfid_uid,
            str(fingerprint_id),
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device authentication",
        )

    # ==================================================
    # SESSION
    # ==================================================

    auth_session = database.get(
        AuthenticationSession,
        session_id,
    )

    if auth_session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Authentication session not found",
        )

    if (
        auth_session.device_id
        != device.id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session/device mismatch",
        )

    now = datetime.now(
        timezone.utc
    )

    # ==================================================
    # EXPIRATION
    # ==================================================

    if auth_session.expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Challenge expired",
        )

    # ==================================================
    # DEJA VERIFIE ?
    # ==================================================

    if (
        auth_session.verified_at
        is not None
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Authentication session already verified",
        )

    # ==================================================
    # CHALLENGE
    # ==================================================

    if (
        auth_session.challenge
        != challenge
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid challenge",
        )

    # ==================================================
    # RFID
    # ==================================================

    if (
        auth_session.rfid_uid
        != rfid_uid
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="RFID mismatch",
        )

    # ==================================================
    # RFID + FINGERPRINT = MEME UTILISATEUR
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
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="RFID and fingerprint do not match",
        )

    # ==================================================
    # AUTHENTIFICATION REUSSIE
    # ==================================================

    store_nonce(
        device.device_uid,
        x_nonce,
    )

    auth_session.verified_at = now

    device.last_seen = now

    database.commit()

    return {
        "authenticated": True,
        "session_id": session_id_string,
        "message":
            "Strong authentication successful",
    }