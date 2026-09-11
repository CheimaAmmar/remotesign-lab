import hmac
import math
import os
import uuid

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator
from urllib.parse import urlsplit

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from pyhanko import stamp
from pyhanko.config.pkcs11 import TokenCriteria
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import (
    IncrementalPdfFileWriter,
)
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, pkcs11, signers, timestamps
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.general import (
    load_cert_from_pemder,
    load_certs_from_pemder,
)
from pyhanko.sign.validation import (
    SignatureCoverageLevel,
    validate_pdf_signature,
)
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko_certvalidator import ValidationContext

from app.config import Settings, get_settings
from app.services.hsm_service import HSMService


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SIGNED_DOCUMENT_STORAGE = PROJECT_ROOT / "storage" / "signed"
PADES_B_B_PROFILE = "PAdES-B-B"
PADES_B_T_PROFILE = "PAdES-B-T"
PADES_PROFILE = PADES_B_B_PROFILE
SUPPORTED_PADES_PROFILES = {
    PADES_B_B_PROFILE,
    PADES_B_T_PROFILE,
}
PADES_SUBFILTER = "/ETSI.CAdES.detached"
VISIBLE_SIGNATURE_WIDTH = 250
VISIBLE_SIGNATURE_HEIGHT = 110
VISIBLE_SIGNATURE_MARGIN = 18


class PAdESServiceError(RuntimeError):
    """Controlled error while producing or validating a PAdES PDF."""


class StageHSMPKCS11Signer(pkcs11.PKCS11Signer):
    """PKCS11Signer variant that keeps token handles on one thread.

    pyHanko's default implementation delegates handle loading and signing to
    an executor. The SoftHSM/python-pkcs11 combination used by this prototype
    requires the session and its handles to remain on their opening thread.
    """

    async def async_sign_raw(
        self,
        data: bytes,
        digest_algorithm: str,
        dry_run: bool = False,
    ) -> bytes:
        if dry_run:
            return self.estimate_raw_signature_size_bytes() * b"0"

        if not self._loaded:
            self._load_objects()

        assert self._key_handle is not None
        specification = self._select_pkcs11_signing_params(
            digest_algorithm,
            sign_kwargs=self.sign_kwargs(data),
        )

        if specification.pre_sign_transform is not None:
            data = specification.pre_sign_transform(data)

        signature = self._key_handle.sign(
            data,
            **specification.sign_kwargs,
        )

        if specification.post_sign_transform is not None:
            signature = specification.post_sign_transform(signature)

        return bytes(signature)


@dataclass(frozen=True)
class PAdESVerificationResult:
    valid: bool
    intact: bool
    trusted: bool
    pades_profile: str
    certificate_fingerprint_sha256: str
    certificate_subject: str
    signing_time: datetime | None
    signature_count: int
    timestamp_present: bool
    timestamp_valid: bool | None
    timestamp_trusted: bool | None
    timestamp_time: datetime | None
    tsa_certificate_subject: str | None
    tsa_certificate_fingerprint_sha256: str | None


@dataclass(frozen=True)
class PAdESSignatureResult:
    pades_profile: str
    certificate_fingerprint_sha256: str
    certificate_subject: str
    signing_time: datetime
    timestamp_time: datetime | None
    tsa_certificate_subject: str | None
    tsa_certificate_fingerprint_sha256: str | None


class PAdESService:
    def __init__(
        self,
        *,
        settings: Settings | None = None,
        public_key_der_supplier: Callable[[], bytes] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._public_key_der_supplier = (
            public_key_der_supplier
            or (lambda: HSMService().get_public_key_der())
        )

    @staticmethod
    def _resolve_public_file(path: Path) -> Path:
        resolved = (
            path if path.is_absolute() else PROJECT_ROOT / path
        ).resolve()

        if not resolved.is_file():
            raise PAdESServiceError(
                "Configured PAdES certificate file is missing"
            )

        return resolved

    def _configured_profile(self) -> str:
        profile = str(
            getattr(
                self.settings,
                "pades_profile",
                PADES_B_B_PROFILE,
            )
        ).strip()

        if profile not in SUPPORTED_PADES_PROFILES:
            raise PAdESServiceError(
                "Unsupported configured PAdES profile"
            )

        return profile

    @staticmethod
    def _load_public_certificates(
        path: Path,
        *,
        description: str,
    ) -> list:
        try:
            certificates = list(load_certs_from_pemder([path]))
        except (OSError, ValueError) as error:
            raise PAdESServiceError(
                f"Unable to load the {description}"
            ) from error

        if not certificates:
            raise PAdESServiceError(
                f"The {description} is empty"
            )

        return certificates

    def _load_certificate_material(self):
        certificate_path = self._resolve_public_file(
            self.settings.pades_signing_certificate
        )

        try:
            signing_certificate = load_cert_from_pemder(
                certificate_path
            )
            cryptography_certificate = (
                crypto_x509.load_der_x509_certificate(
                    signing_certificate.dump()
                )
            )
        except (OSError, ValueError) as error:
            raise PAdESServiceError(
                "Unable to load the PAdES signing certificate"
            ) from error

        certificate_public_key = (
            cryptography_certificate.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=(
                    serialization.PublicFormat.SubjectPublicKeyInfo
                ),
            )
        )
        hsm_public_key = self._public_key_der_supplier()

        if not hmac.compare_digest(
            certificate_public_key,
            hsm_public_key,
        ):
            raise PAdESServiceError(
                "PAdES certificate does not match the HSM key"
            )

        certificate_chain = []
        chain_path = self.settings.pades_certificate_chain

        if chain_path is not None:
            resolved_chain_path = self._resolve_public_file(
                chain_path
            )

            certificate_chain = self._load_public_certificates(
                resolved_chain_path,
                description="PAdES certificate chain",
            )

        return (
            signing_certificate,
            cryptography_certificate,
            certificate_chain,
        )

    def _tsa_validation_context(self) -> ValidationContext:
        configured_path = getattr(
            self.settings,
            "tsa_ca_certificate",
            None,
        )

        if configured_path is None:
            raise PAdESServiceError(
                "PAdES-B-T requires a TSA trust anchor"
            )

        certificate_path = self._resolve_public_file(
            Path(configured_path)
        )
        certificates = self._load_public_certificates(
            certificate_path,
            description="TSA certificate chain",
        )

        return ValidationContext(
            trust_roots=[certificates[-1]],
            other_certs=certificates[:-1],
            allow_fetching=False,
            revocation_mode="soft-fail",
        )

    def _build_timestamper(self) -> timestamps.TimeStamper:
        configured_url = getattr(self.settings, "tsa_url", None)
        url = (
            configured_url.strip()
            if isinstance(configured_url, str)
            else ""
        )
        parsed = urlsplit(url)

        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise PAdESServiceError(
                "PAdES-B-T requires a valid RFC 3161 TSA URL"
            )

        try:
            timeout = float(
                getattr(self.settings, "tsa_timeout_seconds", 5.0)
            )
        except (TypeError, ValueError) as error:
            raise PAdESServiceError(
                "Invalid TSA timeout configuration"
            ) from error

        if not math.isfinite(timeout) or timeout <= 0 or timeout > 60:
            raise PAdESServiceError(
                "Invalid TSA timeout configuration"
            )

        # Fail before opening the PDF if the TSA trust material is absent.
        self._tsa_validation_context()

        return timestamps.HTTPTimeStamper(
            url,
            https=parsed.scheme == "https",
            timeout=timeout,
        )

    @contextmanager
    def _open_signer(
        self,
        signing_certificate,
        certificate_chain,
    ) -> Iterator[signers.Signer]:
        session = None

        try:
            session = pkcs11.open_pkcs11_session(
                self.settings.softhsm_module,
                token_criteria=TokenCriteria(
                    label=self.settings.softhsm_token_label
                ),
                user_pin=(
                    self.settings
                    .softhsm_user_pin
                    .get_secret_value()
                ),
            )
            signer = StageHSMPKCS11Signer(
                pkcs11_session=session,
                signing_cert=signing_certificate,
                ca_chain=certificate_chain,
                key_label=self.settings.softhsm_key_label,
                prefer_pss=False,
                embed_roots=False,
                other_certs_to_pull=(),
                bulk_fetch=False,
            )
            yield signer
        finally:
            if session is not None:
                session.close()

    @staticmethod
    def _validation_context(
        signing_certificate,
        certificate_chain,
    ) -> ValidationContext:
        if certificate_chain:
            trust_roots = [certificate_chain[-1]]
            other_certs = certificate_chain[:-1]
        else:
            trust_roots = [signing_certificate]
            other_certs = []

        return ValidationContext(
            trust_roots=trust_roots,
            other_certs=other_certs,
            allow_fetching=False,
            revocation_mode="soft-fail",
        )

    @staticmethod
    def _page_box_value(page_object, key: str) -> tuple[float, ...] | None:
        current = page_object

        while isinstance(current, generic.DictionaryObject):
            try:
                value = current[key]
            except KeyError:
                value = None

            if value is not None:
                try:
                    coordinates = tuple(float(item) for item in value)
                except (TypeError, ValueError):
                    return None

                if len(coordinates) == 4:
                    return coordinates

                return None

            try:
                parent = current.raw_get("/Parent")
            except KeyError:
                break

            current = parent.get_object()

        return None

    @classmethod
    def _visible_signature_box(
        cls,
        writer: IncrementalPdfFileWriter,
    ) -> tuple[int, int, int, int]:
        page_reference, _ = writer.find_page_for_modification(-1)
        page_object = page_reference.get_object()
        page_box = (
            cls._page_box_value(page_object, "/CropBox")
            or cls._page_box_value(page_object, "/MediaBox")
        )

        if page_box is None:
            raise PAdESServiceError(
                "The last PDF page has no usable page box"
            )

        x_one, y_one, x_two, y_two = page_box
        page_left = min(x_one, x_two)
        page_right = max(x_one, x_two)
        page_bottom = min(y_one, y_two)
        page_top = max(y_one, y_two)
        page_width = page_right - page_left
        page_height = page_top - page_bottom

        if page_width < 4 or page_height < 4:
            raise PAdESServiceError(
                "The last PDF page is too small for a signature field"
            )

        margin = min(
            VISIBLE_SIGNATURE_MARGIN,
            max(1.0, page_width * 0.04),
            max(1.0, page_height * 0.04),
        )
        left_limit = math.ceil(page_left + margin)
        right_limit = math.floor(page_right - margin)
        bottom_limit = math.ceil(page_bottom + margin)
        top_limit = math.floor(page_top - margin)

        if right_limit <= left_limit or top_limit <= bottom_limit:
            raise PAdESServiceError(
                "The last PDF page is too small for a signature field"
            )

        width = min(
            VISIBLE_SIGNATURE_WIDTH,
            right_limit - left_limit,
        )
        height = min(
            VISIBLE_SIGNATURE_HEIGHT,
            top_limit - bottom_limit,
        )

        return (
            right_limit - width,
            bottom_limit,
            right_limit,
            bottom_limit + height,
        )

    @staticmethod
    def _safe_visible_text(value: str) -> str:
        one_line = " ".join(str(value).split())
        # pyHanko's controlled built-in Courier font uses WinAnsi.
        return one_line.encode(
            "cp1252",
            errors="replace",
        ).decode("cp1252")

    @staticmethod
    def _certificate_display_name(
        certificate: crypto_x509.Certificate,
    ) -> str:
        common_names = certificate.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )

        if common_names:
            return str(common_names[0].value)

        return certificate.subject.rfc4514_string()

    def _verify_with_material(
        self,
        signed_pdf_path: Path,
        signing_certificate,
        cryptography_certificate,
        certificate_chain,
        *,
        expected_profile: str,
    ) -> PAdESVerificationResult:
        tsa_validation_context = (
            self._tsa_validation_context()
            if expected_profile == PADES_B_T_PROFILE
            else None
        )

        with signed_pdf_path.open("rb") as signed_pdf:
            reader = PdfFileReader(signed_pdf, strict=True)
            embedded_signatures = reader.embedded_signatures

            if not embedded_signatures:
                raise PAdESServiceError(
                    "The generated PDF contains no embedded signature"
                )

            embedded_signature = embedded_signatures[-1]
            subfilter = str(
                embedded_signature.sig_object["/SubFilter"]
            )

            if subfilter != PADES_SUBFILTER:
                raise PAdESServiceError(
                    "The generated PDF is not a PAdES signature"
                )

            validation_status = validate_pdf_signature(
                embedded_signature,
                signer_validation_context=(
                    self._validation_context(
                        signing_certificate,
                        certificate_chain,
                    )
                ),
                ts_validation_context=tsa_validation_context,
                key_usage_settings=KeyUsageConstraints(
                    key_usage={"non_repudiation"}
                ),
            )

            embedded_certificate = (
                crypto_x509.load_der_x509_certificate(
                    embedded_signature.signer_cert.dump()
                )
            )
            expected_fingerprint = (
                cryptography_certificate.fingerprint(
                    hashes.SHA256()
                ).hex()
            )
            embedded_fingerprint = (
                embedded_certificate.fingerprint(
                    hashes.SHA256()
                ).hex()
            )
            certificate_matches = hmac.compare_digest(
                embedded_fingerprint,
                expected_fingerprint,
            )
            timestamp_status = validation_status.timestamp_validity
            timestamp_present = timestamp_status is not None
            timestamp_valid = (
                bool(timestamp_status.intact and timestamp_status.valid)
                if timestamp_status is not None
                else None
            )
            timestamp_trusted = (
                bool(timestamp_status.trusted)
                if timestamp_status is not None
                else None
            )
            timestamp_time = (
                timestamp_status.timestamp
                if timestamp_status is not None
                else None
            )
            tsa_subject = None
            tsa_fingerprint = None

            if timestamp_status is not None:
                tsa_certificate = (
                    crypto_x509.load_der_x509_certificate(
                        timestamp_status.signing_cert.dump()
                    )
                )
                tsa_subject = (
                    tsa_certificate.subject.rfc4514_string()
                )
                tsa_fingerprint = tsa_certificate.fingerprint(
                    hashes.SHA256()
                ).hex()

            actual_profile = (
                PADES_B_T_PROFILE
                if timestamp_present
                else PADES_B_B_PROFILE
            )
            document_intact = bool(
                validation_status.intact
                and validation_status.coverage
                == SignatureCoverageLevel.ENTIRE_FILE
            )
            timestamp_requirement_met = (
                expected_profile == PADES_B_B_PROFILE
                and not timestamp_present
            ) or (
                expected_profile == PADES_B_T_PROFILE
                and timestamp_valid is True
                and timestamp_trusted is True
            )

            return PAdESVerificationResult(
                valid=(
                    bool(validation_status.valid)
                    and bool(validation_status.trusted)
                    and document_intact
                    and certificate_matches
                    and actual_profile == expected_profile
                    and timestamp_requirement_met
                ),
                intact=document_intact,
                trusted=bool(validation_status.trusted),
                pades_profile=actual_profile,
                certificate_fingerprint_sha256=(
                    embedded_fingerprint
                ),
                certificate_subject=(
                    embedded_certificate.subject.rfc4514_string()
                ),
                signing_time=validation_status.signer_reported_dt,
                signature_count=len(embedded_signatures),
                timestamp_present=timestamp_present,
                timestamp_valid=timestamp_valid,
                timestamp_trusted=timestamp_trusted,
                timestamp_time=timestamp_time,
                tsa_certificate_subject=tsa_subject,
                tsa_certificate_fingerprint_sha256=tsa_fingerprint,
            )

    def verify_pdf(
        self,
        signed_pdf_path: Path,
        *,
        expected_profile: str | None = None,
    ) -> PAdESVerificationResult:
        try:
            profile = expected_profile or self._configured_profile()

            if profile not in SUPPORTED_PADES_PROFILES:
                raise PAdESServiceError(
                    "Unsupported expected PAdES profile"
                )

            material = self._load_certificate_material()
            return self._verify_with_material(
                signed_pdf_path.resolve(),
                *material,
                expected_profile=profile,
            )
        except PAdESServiceError:
            raise
        except Exception as error:
            raise PAdESServiceError(
                "Unable to validate the PAdES document"
            ) from error

    def sign_pdf(
        self,
        *,
        source_pdf_path: Path,
        output_pdf_path: Path,
        signature_id: uuid.UUID,
        signer_name: str,
    ) -> PAdESSignatureResult:
        try:
            profile = self._configured_profile()
            material = self._load_certificate_material()
            (
                signing_certificate,
                cryptography_certificate,
                certificate_chain,
            ) = material
            timestamper = (
                self._build_timestamper()
                if profile == PADES_B_T_PROFILE
                else None
            )
            server_signing_time = datetime.now(timezone.utc)
            certificate_name = self._certificate_display_name(
                cryptography_certificate
            )
            output_pdf_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with (
                self._open_signer(
                    signing_certificate,
                    certificate_chain,
                ) as signer,
                source_pdf_path.open("rb") as source_pdf,
                output_pdf_path.open("wb") as output_pdf,
            ):
                writer = IncrementalPdfFileWriter(source_pdf)
                field_name = f"StageHSM_{signature_id.hex}"
                field_spec = fields.SigFieldSpec(
                    sig_field_name=field_name,
                    on_page=-1,
                    box=self._visible_signature_box(writer),
                    readable_field_name=(
                        "Stage-HSM electronic signature"
                    ),
                )
                metadata = signers.PdfSignatureMetadata(
                    field_name=field_name,
                    md_algorithm="sha256",
                    reason="Stage-HSM user-approved signature",
                    name=self._safe_visible_text(signer_name),
                    subfilter=SigSeedSubFilter.PADES,
                    embed_validation_info=False,
                    use_pades_lta=False,
                )
                signers.PdfSigner(
                    metadata,
                    signer=signer,
                    timestamper=timestamper,
                    stamp_style=stamp.TextStampStyle(
                        stamp_text=(
                            "SIGNÉ ÉLECTRONIQUEMENT\n"
                            "Stage-HSM\n"
                            "Signataire : %(stage_signer)s\n"
                            "Certificat : %(stage_certificate)s\n"
                            "Profil : %(stage_profile)s\n"
                            "Date : %(stage_date)s\n"
                            "Signature ID : %(stage_signature_id)s"
                        ),
                    ),
                    new_field_spec=field_spec,
                ).sign_pdf(
                    writer,
                    appearance_text_params={
                        "stage_signer": self._safe_visible_text(
                            signer_name
                        ),
                        "stage_certificate": self._safe_visible_text(
                            certificate_name
                        ),
                        "stage_profile": profile,
                        "stage_date": server_signing_time.strftime(
                            "%Y-%m-%d %H:%M:%S UTC"
                        ),
                        "stage_signature_id": str(signature_id),
                    },
                    output=output_pdf,
                )
                output_pdf.flush()
                os.fsync(output_pdf.fileno())

            verification = self._verify_with_material(
                output_pdf_path,
                *material,
                expected_profile=profile,
            )

            if not (
                verification.valid
                and verification.intact
                and verification.trusted
            ):
                raise PAdESServiceError(
                    "Generated PAdES signature validation failed"
                )

            signing_time = (
                verification.signing_time
                or datetime.now(timezone.utc)
            )

            return PAdESSignatureResult(
                pades_profile=verification.pades_profile,
                certificate_fingerprint_sha256=(
                    verification.certificate_fingerprint_sha256
                ),
                certificate_subject=(
                    verification.certificate_subject
                ),
                signing_time=signing_time,
                timestamp_time=verification.timestamp_time,
                tsa_certificate_subject=(
                    verification.tsa_certificate_subject
                ),
                tsa_certificate_fingerprint_sha256=(
                    verification.tsa_certificate_fingerprint_sha256
                ),
            )
        except PAdESServiceError:
            output_pdf_path.unlink(missing_ok=True)
            raise
        except Exception as error:
            output_pdf_path.unlink(missing_ok=True)
            raise PAdESServiceError(
                "PAdES generation failed"
            ) from error
