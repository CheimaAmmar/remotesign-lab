import uuid

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

from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserStatus
from app.security.admin_auth import require_admin
from app.services.document_service import store_document
from app.services.audit_service import add_audit_event


router = APIRouter(
    prefix="/api/v1/documents",
    tags=["Documents"],
    dependencies=[Depends(require_admin)],
)


@router.post(
    "/upload",
    status_code=status.HTTP_201_CREATED,
)
def upload_document(
    request: Request,
    file: UploadFile = File(...),
    user_id: uuid.UUID | None = Form(default=None),
    database: Session = Depends(get_db),
) -> dict:
    if user_id is not None:
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
        user_id=user_id,
    )
    add_audit_event(
        database,
        event_type="DOCUMENT_UPLOADED",
        outcome="SUCCESS",
        actor_type="ADMIN",
        actor_id="prototype-admin",
        user_id=user_id,
        document_id=uuid.UUID(result["document_id"]),
        request=request,
        http_status=status.HTTP_201_CREATED,
        details={
            "filename": result.get("filename"),
            "size_bytes": result.get("size_bytes"),
        },
    )

    if user_id is not None:
        add_audit_event(
            database,
            event_type="DOCUMENT_ASSIGNED",
            outcome="SUCCESS",
            actor_type="ADMIN",
            actor_id="prototype-admin",
            user_id=user_id,
            document_id=uuid.UUID(result["document_id"]),
            request=request,
            http_status=status.HTTP_201_CREATED,
            detail="Document assigned to its owner",
        )

    database.commit()

    return result
