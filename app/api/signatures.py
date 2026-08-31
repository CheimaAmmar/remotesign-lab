import base64
import binascii
import hashlib
import uuid

from pathlib import Path

from cryptography.exceptions import (
    InvalidSignature,
)

from cryptography.hazmat.primitives import (
    hashes,
    serialization,
)

from cryptography.hazmat.primitives.asymmetric import (
    padding,
    utils,
)

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)

from sqlalchemy.orm import Session

from app.database import get_db

from app.models import (
    Document,
    DocumentSignature,
)

from app.services.hsm_service import (
    HSMService,
    HSMServiceError,
)


router = APIRouter(
    prefix="/api/v1/signatures",
    tags=["Signatures"],
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

DOCUMENT_STORAGE = (
    PROJECT_ROOT
    / "storage"
    / "documents"
)


# ======================================================
# VERIFY SIGNATURE
# ======================================================

@router.get(
    "/{signature_id}/verify",
    status_code=status.HTTP_200_OK,
)
def verify_signature(
    signature_id: str,
    database: Session = Depends(get_db),
) -> dict:

    # ==================================================
    # SIGNATURE UUID
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
            status_code=
                status.HTTP_400_BAD_REQUEST,
            detail="Invalid signature ID",
        )

    # ==================================================
    # SIGNATURE POSTGRESQL
    # ==================================================

    signature_record = database.get(
        DocumentSignature,
        signature_uuid,
    )

    if signature_record is None:

        raise HTTPException(
            status_code=
                status.HTTP_404_NOT_FOUND,
            detail="Signature not found",
        )

    # ==================================================
    # ALGORITHME
    # ==================================================

    if (
        signature_record.algorithm
        != "RSASSA-PKCS1-v1_5-SHA256"
    ):

        raise HTTPException(
            status_code=
                status.HTTP_400_BAD_REQUEST,
            detail="Unsupported signature algorithm",
        )

    # ==================================================
    # DOCUMENT POSTGRESQL
    # ==================================================

    document = database.get(
        Document,
        signature_record.document_id,
    )

    if document is None:

        raise HTTPException(
            status_code=
                status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    # ==================================================
    # DOCUMENT SUR DISQUE
    # ==================================================

    document_path = (
        DOCUMENT_STORAGE
        / document.stored_filename
    )

    if not document_path.is_file():

        raise HTTPException(
            status_code=
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stored document file not found",
        )

    # ==================================================
    # RECALCUL SHA-256
    # ==================================================

    sha256 = hashlib.sha256()

    try:

        with document_path.open(
            "rb"
        ) as input_file:

            while True:

                chunk = input_file.read(
                    64 * 1024
                )

                if not chunk:
                    break

                sha256.update(
                    chunk
                )

    except OSError as error:

        raise HTTPException(
            status_code=
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to read stored document",
        ) from error

    actual_document_hash = (
        sha256.hexdigest()
    )

    # ==================================================
    # INTEGRITE DOCUMENT
    # ==================================================

    if (
        actual_document_hash
        != document.document_hash
    ):

        return {
            "valid": False,

            "signature_id":
                str(signature_record.id),

            "document_id":
                str(document.id),

            "reason":
                "Stored document has been modified",
        }

    if (
        actual_document_hash
        != signature_record.document_hash
    ):

        return {
            "valid": False,

            "signature_id":
                str(signature_record.id),

            "document_id":
                str(document.id),

            "reason":
                "Signed document hash mismatch",
        }

    # ==================================================
    # SIGNATURE BASE64
    # ==================================================

    try:

        signature_bytes = (
            base64.b64decode(
                signature_record.signature_base64,
                validate=True,
            )
        )

    except (
        binascii.Error,
        ValueError,
    ):

        return {
            "valid": False,

            "signature_id":
                str(signature_record.id),

            "document_id":
                str(document.id),

            "reason":
                "Invalid stored signature encoding",
        }

    # ==================================================
    # CLE PUBLIQUE SOFTHSM
    # ==================================================

    try:

        hsm = HSMService()

        public_key_der = (
            hsm.get_public_key_der()
        )

    except HSMServiceError as error:

        raise HTTPException(
            status_code=
                status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=
                "Unable to access HSM public key",
        ) from error

    try:

        public_key = (
            serialization
            .load_der_public_key(
                public_key_der
            )
        )

    except ValueError as error:

        raise HTTPException(
            status_code=
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid HSM public key",
        ) from error

    # ==================================================
    # DIGEST DU VRAI PDF
    # ==================================================

    document_digest = bytes.fromhex(
        actual_document_hash
    )

    # ==================================================
    # VERIFICATION CRYPTOGRAPHIQUE
    # ==================================================

    try:

        public_key.verify(
            signature_bytes,

            document_digest,

            padding.PKCS1v15(),

            utils.Prehashed(
                hashes.SHA256()
            ),
        )

    except InvalidSignature:

        return {
            "valid": False,

            "signature_id":
                str(signature_record.id),

            "document_id":
                str(document.id),

            "document_hash":
                actual_document_hash,

            "reason":
                "Cryptographic signature verification failed",
        }

    # ==================================================
    # SIGNATURE VALIDE
    # ==================================================

    return {
        "valid": True,

        "signature_id":
            str(signature_record.id),

        "session_id":
            str(signature_record.session_id),

        "document_id":
            str(document.id),

        "document_hash":
            actual_document_hash,

        "algorithm":
            signature_record.algorithm,

        "key_label":
            signature_record.key_label,

        "message":
            "Signature is cryptographically valid",
    }