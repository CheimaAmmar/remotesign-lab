import re

from datetime import (
    datetime,
    timedelta,
    timezone,
)

from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import UsedNonce


# Period during which timestamp/HMAC validation normally
# considers the request recent.
NONCE_TTL_SECONDS = 120

# Additional database retention before cleanup.
NONCE_RETENTION_SECONDS = 600


# ======================================================
# OLD NONCE CLEANUP
# ======================================================

def cleanup_old_nonces(
    database: Session,
) -> None:

    now = datetime.now(
        timezone.utc
    )

    threshold = (
        now
        - timedelta(
            seconds=NONCE_RETENTION_SECONDS
        )
    )

    database.execute(
        delete(
            UsedNonce
        ).where(
            UsedNonce.expires_at
            < threshold
        )
    )


# ======================================================
# ATOMIC NONCE CONSUMPTION
# ======================================================

def consume_nonce(
    database: Session,
    device_id,
    nonce: str,
) -> bool:
    """
    Consume a nonce atomically.

    Returns:
        True  -> nonce accepted
        False -> nonce invalid or already used

    The PostgreSQL constraint:

        UNIQUE(device_id, nonce)

    prevents two concurrent uses of the same nonce.
    """

    # ==================================================
    # NORMALIZATION
    # ==================================================

    normalized_nonce = (
        nonce
        .strip()
        .lower()
    )

    # ==================================================
    # FORMAT
    #
    # Firmware:
    # 16 random bytes
    # = 32 hexadecimal characters
    # ==================================================

    if not re.fullmatch(
        r"[0-9a-f]{32}",
        normalized_nonce,
    ):
        return False

    # ==================================================
    # CLEANUP
    # ==================================================

    cleanup_old_nonces(
        database
    )

    # ==================================================
    # EXPIRATION
    # ==================================================

    now = datetime.now(
        timezone.utc
    )

    expires_at = (
        now
        + timedelta(
            seconds=NONCE_TTL_SECONDS
        )
    )

    used_nonce = UsedNonce(
        device_id=device_id,
        nonce=normalized_nonce,
        expires_at=expires_at,
    )

    # ==================================================
    # ATOMIC INSERT
    # ==================================================

    try:

        # SAVEPOINT SQLAlchemy/PostgreSQL.
        #
        # If UNIQUE(device_id, nonce) fails,
        # only this nested transaction is rolled back.

        with database.begin_nested():

            database.add(
                used_nonce
            )

            database.flush()

    except IntegrityError:

        return False

    return True
