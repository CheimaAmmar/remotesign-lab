from fastapi import (
    APIRouter,
    Depends,
    File,
    UploadFile,
    status,
)

from sqlalchemy.orm import Session

from app.database import get_db
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
    database: Session = Depends(get_db),
) -> dict:
    return store_document(
        file=file,
        database=database,
    )
