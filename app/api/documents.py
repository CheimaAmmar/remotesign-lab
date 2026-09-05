import uuid

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)

from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserStatus
from app.security.admin_auth import require_admin
from app.services.document_service import store_document


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

    return store_document(
        file=file,
        database=database,
        user_id=user_id,
    )
