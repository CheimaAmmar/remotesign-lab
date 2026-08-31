import uuid

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.security.admin_auth import require_admin

from app.models import (
    AuthenticationSession,
    Device,
    Document,
    DocumentSignature,
    SecurityAuditEvent,
    User,
)


router = APIRouter(
    prefix="/api/v1/audit",
    tags=["Audit"],
    dependencies=[Depends(require_admin)],
)


# ======================================================
# HISTORIQUE COMPLET D'UNE SIGNATURE
# ======================================================

@router.get(
    "/signatures/{signature_id}",
    status_code=status.HTTP_200_OK,
)
def get_signature_audit(
    signature_id: str,
    database: Session = Depends(get_db),
) -> dict:

    # ==================================================
    # SIGNATURE ID
    # ==================================================

    try:
        signature_uuid = uuid.UUID(
            signature_id
        )

    except (
        ValueError,
        TypeError,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signature ID",
        )

    # ==================================================
    # SIGNATURE
    # ==================================================

    signature_record = database.get(
        DocumentSignature,
        signature_uuid,
    )

    if signature_record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Signature not found",
        )

    # ==================================================
    # SESSION
    # ==================================================

    auth_session = database.get(
        AuthenticationSession,
        signature_record.session_id,
    )

    if auth_session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Authentication session not found",
        )

    # ==================================================
    # DOCUMENT
    # ==================================================

    document = database.get(
        Document,
        signature_record.document_id,
    )

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    # ==================================================
    # USER
    # ==================================================

    user = database.get(
        User,
        signature_record.user_id,
    )

    # ==================================================
    # DEVICE
    # ==================================================

    device = database.get(
        Device,
        signature_record.device_id,
    )

    # ==================================================
    # EVENEMENTS D'AUDIT
    #
    # On utilise session_id afin de récupérer :
    #
    # AUTH_CHALLENGE_CREATED
    # STRONG_AUTH_COMPLETED
    # DOCUMENT_SIGNED
    # ==================================================

    events = database.scalars(
        select(
            SecurityAuditEvent
        )
        .where(
            SecurityAuditEvent.session_id
            == auth_session.id
        )
        .order_by(
            SecurityAuditEvent.created_at.asc()
        )
    ).all()

    # ==================================================
    # CONSTRUCTION TIMELINE
    # ==================================================

    timeline = []

    for event in events:

        timeline.append(
            {
                "event_id":
                    str(event.id),

                "event_type":
                    event.event_type,

                "outcome":
                    event.outcome,

                "source_ip":
                    event.source_ip,

                "detail":
                    event.detail,

                "created_at":
                    (
                        event.created_at.isoformat()
                        if event.created_at
                        else None
                    ),
            }
        )

    # ==================================================
    # REPONSE
    # ==================================================

    return {

        "signature": {
            "signature_id":
                str(signature_record.id),

            "algorithm":
                signature_record.algorithm,

            "key_label":
                signature_record.key_label,

            "created_at":
                (
                    signature_record.created_at.isoformat()
                    if signature_record.created_at
                    else None
                ),
        },

        "document": {
            "document_id":
                str(document.id),

            "filename":
                document.original_filename,

            "size_bytes":
                document.size_bytes,

            "document_hash":
                document.document_hash,
        },

        "authentication": {
            "session_id":
                str(auth_session.id),

            "decision":
                auth_session.decision,

            "rfid_uid":
                auth_session.rfid_uid,

            "verified_at":
                (
                    auth_session.verified_at.isoformat()
                    if auth_session.verified_at
                    else None
                ),

            "used_at":
                (
                    auth_session.used_at.isoformat()
                    if auth_session.used_at
                    else None
                ),
        },

        "user": {
            "user_id":
                str(signature_record.user_id),

            "username":
                (
                    user.username
                    if user is not None
                    else None
                ),
        },

        "device": {
            "device_id":
                str(signature_record.device_id),

            "device_uid":
                (
                    device.device_uid
                    if device is not None
                    else None
                ),
        },

        "timeline":
            timeline,
    }
