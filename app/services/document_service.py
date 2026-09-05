import hashlib
import uuid

from pathlib import Path

from fastapi import HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.models import Document


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOCUMENT_STORAGE = PROJECT_ROOT / "storage" / "documents"
MAX_DOCUMENT_SIZE = 20 * 1024 * 1024


def store_document(
    file: UploadFile,
    database: Session,
    *,
    user_id: uuid.UUID | None = None,
) -> dict:
    original_filename = file.filename or "document.pdf"

    if not original_filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PDF documents are accepted",
        )

    document_id = uuid.uuid4()
    stored_filename = f"{document_id}.pdf"

    DOCUMENT_STORAGE.mkdir(
        parents=True,
        exist_ok=True,
    )

    destination = DOCUMENT_STORAGE / stored_filename
    sha256 = hashlib.sha256()
    total_size = 0

    try:
        with destination.open("wb") as output_file:
            while True:
                chunk = file.file.read(64 * 1024)

                if not chunk:
                    break

                total_size += len(chunk)

                if total_size > MAX_DOCUMENT_SIZE:
                    raise HTTPException(
                        status_code=(
                            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
                        ),
                        detail="Document too large",
                    )

                sha256.update(chunk)
                output_file.write(chunk)

    except HTTPException:
        destination.unlink(missing_ok=True)
        raise

    except OSError as error:
        destination.unlink(missing_ok=True)

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to store document",
        ) from error

    finally:
        file.file.close()

    if total_size == 0:
        destination.unlink(missing_ok=True)

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty document",
        )

    document = Document(
        id=document_id,
        original_filename=original_filename,
        stored_filename=stored_filename,
        content_type=file.content_type,
        size_bytes=total_size,
        document_hash=sha256.hexdigest(),
        user_id=user_id,
    )

    database.add(document)
    database.commit()
    database.refresh(document)

    return {
        "document_id": str(document.id),
        "filename": document.original_filename,
        "size_bytes": document.size_bytes,
        "document_hash": document.document_hash,
        "algorithm": "SHA-256",
        "message": "Document uploaded and hashed successfully",
    }
