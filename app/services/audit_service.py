import logging

from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from app.models import (
    SecurityAuditEvent,
)


logger = logging.getLogger(
    __name__
)


# ======================================================
# AUDIT DANS LA TRANSACTION PRINCIPALE
#
# Utilisé pour les SUCCESS.
# Si l'opération principale échoue,
# l'audit SUCCESS est également annulé.
# ======================================================

def add_audit_event(
    database: Session,
    *,
    event_type: str,
    outcome: str,
    user_id=None,
    device_id=None,
    session_id=None,
    document_id=None,
    signature_id=None,
    source_ip: str | None = None,
    detail: str | None = None,
) -> SecurityAuditEvent:

    event = SecurityAuditEvent(
        event_type=event_type,
        outcome=outcome,
        user_id=user_id,
        device_id=device_id,
        session_id=session_id,
        document_id=document_id,
        signature_id=signature_id,
        source_ip=source_ip,
        detail=detail,
    )

    database.add(
        event
    )

    return event


# ======================================================
# AUDIT DANS UNE TRANSACTION INDEPENDANTE
#
# Utilisé principalement pour FAILED.
#
# Même si la requête principale fait rollback,
# cet événement reste dans PostgreSQL.
# ======================================================

def record_audit_event(
    database: Session,
    *,
    event_type: str,
    outcome: str,
    user_id=None,
    device_id=None,
    session_id=None,
    document_id=None,
    signature_id=None,
    source_ip: str | None = None,
    detail: str | None = None,
) -> bool:

    # --------------------------------------------------
    # Récupérer le bind SQLAlchemy
    # --------------------------------------------------

    bind = database.get_bind()

    # Si get_bind() retourne une Connection liée
    # à la transaction actuelle, on récupère son Engine.
    #
    # Cela garantit qu'on ouvre une NOUVELLE connexion
    # PostgreSQL pour l'audit.
    # --------------------------------------------------

    engine = getattr(
        bind,
        "engine",
        bind,
    )

    AuditSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    audit_database = (
        AuditSessionLocal()
    )

    try:

        event = SecurityAuditEvent(
            event_type=event_type,
            outcome=outcome,
            user_id=user_id,
            device_id=device_id,
            session_id=session_id,
            document_id=document_id,
            signature_id=signature_id,
            source_ip=source_ip,
            detail=detail,
        )

        audit_database.add(
            event
        )

        audit_database.commit()

        return True

    except Exception:

        audit_database.rollback()

        logger.exception(
            "Unable to persist security audit event: %s",
            event_type,
        )

        return False

    finally:

        audit_database.close()