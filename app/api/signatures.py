import base64
import binascii
import hashlib
import hmac
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

from app.security.admin_auth import require_admin

from app.services.hsm_service import (
    HSMService,
    HSMServiceError,
)
from app.services.pades_service import (
    PAdESService,
    PAdESServiceError,
    SIGNED_DOCUMENT_STORAGE,
)


router = APIRouter(
    prefix="/api/v1/signatures",
    tags=["Signatures"],
    dependencies=[Depends(require_admin)],
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
    # VERIFICATION PADES (NOUVELLES SIGNATURES)
    # ==================================================

    pades_details = {}
    signed_document_path = getattr(
        signature_record,
        "signed_document_path",
        None,
    )

    if signed_document_path:
        signed_storage_root = SIGNED_DOCUMENT_STORAGE.resolve()
        signed_pdf_path = (
            SIGNED_DOCUMENT_STORAGE
            / signed_document_path
        ).resolve()

        if (
            not signed_pdf_path.is_relative_to(
                signed_storage_root
            )
            or not signed_pdf_path.is_file()
        ):
            return {
                "valid": False,
                "signature_id": str(signature_record.id),
                "document_id": str(document.id),
                "reason": "Signed PAdES document file not found",
            }

        try:
            pades_verification = PAdESService().verify_pdf(
                signed_pdf_path,
                expected_profile=signature_record.pades_profile,
            )
        except PAdESServiceError as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to validate PAdES document",
            ) from error

        stored_fingerprint = getattr(
            signature_record,
            "certificate_fingerprint_sha256",
            None,
        )
        fingerprint_matches = (
            isinstance(stored_fingerprint, str)
            and hmac.compare_digest(
                stored_fingerprint,
                pades_verification
                .certificate_fingerprint_sha256,
            )
        )
        stored_timestamp_time = getattr(
            signature_record,
            "timestamp_time",
            None,
        )
        stored_tsa_subject = getattr(
            signature_record,
            "tsa_certificate_subject",
            None,
        )
        stored_tsa_fingerprint = getattr(
            signature_record,
            "tsa_certificate_fingerprint_sha256",
            None,
        )
        timestamp_metadata_matches = True

        if signature_record.pades_profile == "PAdES-B-T":
            timestamp_metadata_matches = (
                stored_timestamp_time
                == pades_verification.timestamp_time
                and stored_tsa_subject
                == pades_verification.tsa_certificate_subject
                and isinstance(stored_tsa_fingerprint, str)
                and isinstance(
                    pades_verification
                    .tsa_certificate_fingerprint_sha256,
                    str,
                )
                and hmac.compare_digest(
                    stored_tsa_fingerprint,
                    pades_verification
                    .tsa_certificate_fingerprint_sha256,
                )
            )

        pades_details = {
            "pades_profile": pades_verification.pades_profile,
            "certificate_fingerprint_sha256": (
                pades_verification
                .certificate_fingerprint_sha256
            ),
            "certificate_subject": (
                pades_verification.certificate_subject
            ),
            "signing_time": (
                pades_verification.signing_time.isoformat()
                if pades_verification.signing_time is not None
                else None
            ),
            "document_intact": pades_verification.intact,
            "signer_certificate_trusted": (
                pades_verification.trusted
            ),
            # Compatibility aliases retained for existing API clients.
            "pdf_signature_intact": pades_verification.intact,
            "certificate_trusted": pades_verification.trusted,
            "timestamp_present": (
                pades_verification.timestamp_present
            ),
            "timestamp_valid": (
                pades_verification.timestamp_valid is True
                and pades_verification.timestamp_trusted is True
                if pades_verification.timestamp_present
                else None
            ),
            "timestamp_trusted": (
                pades_verification.timestamp_trusted
            ),
            "timestamp_time": (
                pades_verification.timestamp_time.isoformat()
                if pades_verification.timestamp_time is not None
                else None
            ),
            "tsa_subject": (
                pades_verification.tsa_certificate_subject
            ),
            "development_certificate": True,
        }

        if not (
            pades_verification.valid
            and pades_verification.intact
            and pades_verification.trusted
            and fingerprint_matches
            and timestamp_metadata_matches
        ):
            return {
                "valid": False,
                "signature_id": str(signature_record.id),
                "document_id": str(document.id),
                "reason": "PAdES signature validation failed",
                **pades_details,
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

        **pades_details,
    }
