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


# Durée pendant laquelle le timestamp/HMAC
# considère normalement la requête comme récente.
NONCE_TTL_SECONDS = 120

# Conservation supplémentaire en base avant nettoyage.
NONCE_RETENTION_SECONDS = 600


# ======================================================
# NETTOYAGE DES ANCIENS NONCES
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
# CONSOMMATION ATOMIQUE DU NONCE
# ======================================================

def consume_nonce(
    database: Session,
    device_id,
    nonce: str,
) -> bool:
    """
    Consomme un nonce de manière atomique.

    Retour :
        True  -> nonce accepté
        False -> nonce invalide ou déjà utilisé

    La contrainte PostgreSQL :

        UNIQUE(device_id, nonce)

    protège contre deux utilisations concurrentes
    du même nonce.
    """

    # ==================================================
    # NORMALISATION
    # ==================================================

    normalized_nonce = (
        nonce
        .strip()
        .lower()
    )

    # ==================================================
    # FORMAT
    #
    # Firmware :
    # 16 octets aléatoires
    # = 32 caractères hexadécimaux
    # ==================================================

    if not re.fullmatch(
        r"[0-9a-f]{32}",
        normalized_nonce,
    ):
        return False

    # ==================================================
    # NETTOYAGE
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
    # INSERTION ATOMIQUE
    # ==================================================

    try:

        # SAVEPOINT SQLAlchemy/PostgreSQL.
        #
        # Si UNIQUE(device_id, nonce) échoue,
        # seule cette sous-transaction est annulée.

        with database.begin_nested():

            database.add(
                used_nonce
            )

            database.flush()

    except IntegrityError:

        return False

    return True