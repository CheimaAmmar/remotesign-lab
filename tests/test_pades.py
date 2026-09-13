import base64
import hashlib
import inspect
import json
import unittest
import uuid

from asn1crypto import cms, keys as asn1_keys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from pydantic import SecretStr
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import (
    IncrementalPdfFileWriter,
)
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign import fields, signers, timestamps
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko_certvalidator.registry import SimpleCertificateStore
from sqlalchemy.dialects import postgresql

from app.api import signatures as signature_api
from app.api import signing
from app.models import (
    DeviceStatus,
    DocumentSignature,
    SignatureRequestStatus,
    User,
)
from app.security.user_session import UserSession
from app.services.hsm_service import SignatureResult
from app.services.pades_service import (
    PADES_B_B_PROFILE,
    PADES_B_T_PROFILE,
    PADES_PROFILE,
    PAdESService,
    PAdESServiceError,
    RemoteSignLabPKCS11Signer,
)
from app.user_web.routes import (
    _request_response,
    download_user_signed_document,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _issue_certificate(
    *,
    subject: x509.Name,
    public_key,
    issuer: x509.Name,
    issuer_key,
    is_ca: bool,
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.BasicConstraints(
                ca=is_ca,
                path_length=None,
            ),
            critical=True,
        )
    )

    if not is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )

    return builder.sign(issuer_key, hashes.SHA256())


def _write_valid_pdf(path: Path) -> None:
    _write_pdf_with_page_boxes(
        path,
        [(0, 0, 595, 842)],
    )


def _write_pdf_with_page_boxes(
    path: Path,
    page_boxes: list[tuple[int, int, int, int]],
) -> None:
    writer = PdfFileWriter()
    for page_box in page_boxes:
        writer.insert_page(
            generic.DictionaryObject(
                {
                    generic.pdf_name("/Type"): generic.pdf_name(
                        "/Page"
                    ),
                    generic.pdf_name("/MediaBox"): (
                        generic.ArrayObject(
                            [
                                generic.NumberObject(value)
                                for value in page_box
                            ]
                        )
                    ),
                    generic.pdf_name("/CropBox"): (
                        generic.ArrayObject(
                            [
                                generic.NumberObject(value)
                                for value in page_box
                            ]
                        )
                    ),
                    generic.pdf_name("/Resources"): (
                        generic.DictionaryObject()
                    ),
                }
            )
        )

    with path.open("wb") as output:
        writer.write(output)


class DevelopmentCertificateMaterial:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        ca_subject = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME,
                    "RemoteSignLab Development CA",
                )
            ]
        )
        self.ca_certificate = _issue_certificate(
            subject=ca_subject,
            public_key=self.ca_key.public_key(),
            issuer=ca_subject,
            issuer_key=self.ca_key,
            is_ca=True,
        )
        self.signing_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.signing_certificate = _issue_certificate(
            subject=x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        "RemoteSignLab Development Signer",
                    )
                ]
            ),
            public_key=self.signing_key.public_key(),
            issuer=ca_subject,
            issuer_key=self.ca_key,
            is_ca=False,
        )
        self.ca_path = root / "test-ca.crt"
        self.certificate_path = root / "signing.crt"
        self.test_key_path = root / "test-only-signing.key"
        self.ca_path.write_bytes(
            self.ca_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )
        self.certificate_path.write_bytes(
            self.signing_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )
        self.test_key_path.write_bytes(
            self.signing_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.settings = SimpleNamespace(
            pades_signing_certificate=self.certificate_path,
            pades_certificate_chain=self.ca_path,
            softhsm_module="test-only",
            softhsm_token_label="test-only",
            softhsm_user_pin=SecretStr("test-only"),
            softhsm_key_label="test-only",
            pades_profile=PADES_B_B_PROFILE,
            tsa_url=None,
            tsa_ca_certificate=None,
            tsa_timeout_seconds=1,
        )

    def public_key_der(self) -> bytes:
        return self.signing_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def service(
        self,
        *,
        profile: str = PADES_B_B_PROFILE,
        tsa_ca_certificate: Path | None = None,
        timestamper=None,
    ) -> PAdESService:
        settings = SimpleNamespace(**vars(self.settings))
        settings.pades_profile = profile
        settings.tsa_ca_certificate = tsa_ca_certificate
        service = PAdESService(
            settings=settings,
            public_key_der_supplier=self.public_key_der,
        )

        @contextmanager
        def software_signer(_certificate, _chain):
            # Test-only key material. Production PAdESService uses
            # PKCS11Signer and never loads a private key from disk.
            yield signers.SimpleSigner.load(
                str(self.test_key_path),
                str(self.certificate_path),
                ca_chain_files=(str(self.ca_path),),
            )

        service._open_signer = software_signer

        if timestamper is not None:
            service._build_timestamper = lambda: timestamper

        return service


class DevelopmentTSAMaterial:
    def __init__(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        ca_subject = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME,
                    "RemoteSignLab Development TSA CA",
                )
            ]
        )
        self.ca_certificate = _issue_certificate(
            subject=ca_subject,
            public_key=self.ca_key.public_key(),
            issuer=ca_subject,
            issuer_key=self.ca_key,
            is_ca=True,
        )
        self.tsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        now = datetime.now(timezone.utc)
        self.tsa_certificate = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME,
                            "RemoteSignLab Development TSA",
                        )
                    ]
                )
            )
            .issuer_name(ca_subject)
            .public_key(self.tsa_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]
                ),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )
        self.ca_path = root / "tsa-ca.crt"
        self.tsa_path = root / "tsa.crt"
        self.ca_path.write_bytes(
            self.ca_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )
        self.tsa_path.write_bytes(
            self.tsa_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )

    def timestamper(self, *, fixed_dt: datetime | None = None):
        tsa_certificate = load_cert_from_pemder(self.tsa_path)
        ca_certificate = load_cert_from_pemder(self.ca_path)
        tsa_key = asn1_keys.PrivateKeyInfo.load(
            self.tsa_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

        return timestamps.DummyTimeStamper(
            tsa_certificate,
            tsa_key,
            certs_to_embed=SimpleCertificateStore.from_certs(
                [ca_certificate]
            ),
            fixed_dt=fixed_dt,
        )


class PAdESGenerationTests(unittest.TestCase):
    def test_valid_pdf_creates_verified_pades_and_preserves_original(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            material = DevelopmentCertificateMaterial(root)
            source = root / "original.pdf"
            signed = root / "signed.pdf"
            _write_valid_pdf(source)
            original_bytes = source.read_bytes()

            result = material.service().sign_pdf(
                source_pdf_path=source,
                output_pdf_path=signed,
                signature_id=uuid.uuid4(),
                signer_name="Test User",
            )
            verification = material.service().verify_pdf(signed)

            self.assertEqual(source.read_bytes(), original_bytes)
            self.assertTrue(signed.is_file())
            self.assertEqual(result.pades_profile, PADES_PROFILE)
            self.assertTrue(verification.valid)
            self.assertTrue(verification.intact)
            self.assertTrue(verification.trusted)
            self.assertEqual(verification.signature_count, 1)
            self.assertEqual(
                result.certificate_fingerprint_sha256,
                verification.certificate_fingerprint_sha256,
            )

    def test_visible_signature_is_on_last_page_and_uses_server_data(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            material = DevelopmentCertificateMaterial(root)
            source = root / "two-pages.pdf"
            signed = root / "signed.pdf"
            second_page_box = (50, 100, 350, 300)
            _write_pdf_with_page_boxes(
                source,
                [(0, 0, 595, 842), second_page_box],
            )
            signature_id = uuid.uuid4()
            server_user_name = "Alice Martin"

            material.service().sign_pdf(
                source_pdf_path=source,
                output_pdf_path=signed,
                signature_id=signature_id,
                signer_name=server_user_name,
            )

            with signed.open("rb") as signed_pdf:
                reader = PdfFileReader(signed_pdf)
                signature_fields = list(
                    fields.enumerate_sig_fields(
                        reader,
                        filled_status=True,
                    )
                )
                self.assertEqual(len(signature_fields), 1)
                _, _, field_reference = signature_fields[0]
                field = field_reference.get_object()
                last_page_reference, _ = (
                    reader.find_page_for_modification(-1)
                )
                first_page_reference, _ = (
                    reader.find_page_for_modification(0)
                )
                self.assertEqual(
                    field.raw_get("/P").reference,
                    last_page_reference.reference,
                )
                self.assertNotEqual(
                    field.raw_get("/P").reference,
                    first_page_reference.reference,
                )
                left, bottom, right, top = map(
                    float,
                    field["/Rect"],
                )
                crop_left, crop_bottom, crop_right, crop_top = (
                    second_page_box
                )
                self.assertGreaterEqual(left, crop_left)
                self.assertGreaterEqual(bottom, crop_bottom)
                self.assertLessEqual(right, crop_right)
                self.assertLessEqual(top, crop_top)

                appearance = field["/AP"]["/N"].data.replace(
                    b"\\055",
                    b"-",
                )
                self.assertIn(b"RemoteSignLab", appearance)
                self.assertIn(server_user_name.encode(), appearance)
                self.assertIn(str(signature_id).encode(), appearance)

    def test_pades_b_t_contains_a_valid_trusted_rfc3161_timestamp(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            material = DevelopmentCertificateMaterial(root)
            tsa_material = DevelopmentTSAMaterial(root)
            source = root / "original.pdf"
            signed = root / "signed-b-t.pdf"
            _write_valid_pdf(source)
            fixed_timestamp = datetime(
                2026,
                9,
                5,
                15,
                30,
                tzinfo=timezone.utc,
            )
            service = material.service(
                profile=PADES_B_T_PROFILE,
                tsa_ca_certificate=tsa_material.ca_path,
                timestamper=tsa_material.timestamper(
                    fixed_dt=fixed_timestamp
                ),
            )

            result = service.sign_pdf(
                source_pdf_path=source,
                output_pdf_path=signed,
                signature_id=uuid.uuid4(),
                signer_name="Alice Martin",
            )
            verification = service.verify_pdf(
                signed,
                expected_profile=PADES_B_T_PROFILE,
            )

            self.assertEqual(result.pades_profile, PADES_B_T_PROFILE)
            self.assertTrue(verification.valid)
            self.assertTrue(verification.timestamp_present)
            self.assertTrue(verification.timestamp_valid)
            self.assertTrue(verification.timestamp_trusted)
            self.assertEqual(
                verification.timestamp_time,
                fixed_timestamp,
            )
            self.assertIn(
                "RemoteSignLab Development TSA",
                verification.tsa_certificate_subject,
            )
            self.assertEqual(
                len(
                    verification
                    .tsa_certificate_fingerprint_sha256
                ),
                64,
            )

    def test_b_t_configuration_builds_http_timestamper_0_37(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            material = DevelopmentCertificateMaterial(root)
            tsa_material = DevelopmentTSAMaterial(root)
            service = material.service(
                profile=PADES_B_T_PROFILE,
                tsa_ca_certificate=tsa_material.ca_path,
            )
            service.settings.tsa_url = "https://tsa.example.test/rfc3161"
            service.settings.tsa_timeout_seconds = 7

            timestamper = service._build_timestamper()

            self.assertIsInstance(
                timestamper,
                timestamps.HTTPTimeStamper,
            )
            self.assertEqual(
                timestamper.url,
                "https://tsa.example.test/rfc3161",
            )
            self.assertEqual(timestamper.timeout, 7)

    def test_pades_b_t_does_not_fall_back_when_tsa_is_unavailable(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            material = DevelopmentCertificateMaterial(root)
            tsa_material = DevelopmentTSAMaterial(root)
            source = root / "original.pdf"
            signed = root / "signed-b-t.pdf"
            _write_valid_pdf(source)
            service = material.service(
                profile=PADES_B_T_PROFILE,
                tsa_ca_certificate=tsa_material.ca_path,
            )

            with self.assertRaises(PAdESServiceError):
                service.sign_pdf(
                    source_pdf_path=source,
                    output_pdf_path=signed,
                    signature_id=uuid.uuid4(),
                    signer_name="Alice Martin",
                )

            self.assertFalse(signed.exists())

    def test_pades_b_t_rejects_malformed_tsa_response(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            material = DevelopmentCertificateMaterial(root)
            tsa_material = DevelopmentTSAMaterial(root)
            source = root / "original.pdf"
            signed = root / "signed-b-t.pdf"
            _write_valid_pdf(source)
            malformed_timestamper = Mock()
            malformed_timestamper.async_dummy_response = AsyncMock(
                side_effect=ValueError("test-only malformed TSA response")
            )
            service = material.service(
                profile=PADES_B_T_PROFILE,
                tsa_ca_certificate=tsa_material.ca_path,
                timestamper=malformed_timestamper,
            )

            with self.assertRaises(PAdESServiceError):
                service.sign_pdf(
                    source_pdf_path=source,
                    output_pdf_path=signed,
                    signature_id=uuid.uuid4(),
                    signer_name="Alice Martin",
                )

            self.assertFalse(signed.exists())

    def test_pades_b_t_rejects_wrong_tsa_trust_anchor(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            material = DevelopmentCertificateMaterial(root)
            tsa_material = DevelopmentTSAMaterial(root)
            wrong_tsa_material = DevelopmentTSAMaterial(root / "wrong")
            source = root / "original.pdf"
            signed = root / "signed-b-t.pdf"
            _write_valid_pdf(source)
            signer_service = material.service(
                profile=PADES_B_T_PROFILE,
                tsa_ca_certificate=tsa_material.ca_path,
                timestamper=tsa_material.timestamper(),
            )
            signer_service.sign_pdf(
                source_pdf_path=source,
                output_pdf_path=signed,
                signature_id=uuid.uuid4(),
                signer_name="Alice Martin",
            )
            verifier = material.service(
                profile=PADES_B_T_PROFILE,
                tsa_ca_certificate=wrong_tsa_material.ca_path,
            )

            try:
                verification = verifier.verify_pdf(
                    signed,
                    expected_profile=PADES_B_T_PROFILE,
                )
            except PAdESServiceError:
                pass
            else:
                self.assertFalse(verification.valid)

    def test_declared_pades_b_t_without_timestamp_is_invalid(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            material = DevelopmentCertificateMaterial(root)
            tsa_material = DevelopmentTSAMaterial(root)
            source = root / "original.pdf"
            signed = root / "signed-b-b.pdf"
            _write_valid_pdf(source)
            material.service().sign_pdf(
                source_pdf_path=source,
                output_pdf_path=signed,
                signature_id=uuid.uuid4(),
                signer_name="Alice Martin",
            )
            verifier = material.service(
                profile=PADES_B_T_PROFILE,
                tsa_ca_certificate=tsa_material.ca_path,
            )

            verification = verifier.verify_pdf(
                signed,
                expected_profile=PADES_B_T_PROFILE,
            )

            self.assertFalse(verification.valid)
            self.assertFalse(verification.timestamp_present)

    def test_invalid_rfc3161_token_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            material = DevelopmentCertificateMaterial(root)
            tsa_material = DevelopmentTSAMaterial(root)
            source = root / "original.pdf"
            signed = root / "signed-b-t.pdf"
            _write_valid_pdf(source)
            service = material.service(
                profile=PADES_B_T_PROFILE,
                tsa_ca_certificate=tsa_material.ca_path,
                timestamper=tsa_material.timestamper(),
            )
            service.sign_pdf(
                source_pdf_path=source,
                output_pdf_path=signed,
                signature_id=uuid.uuid4(),
                signer_name="Alice Martin",
            )

            with signed.open("rb") as signed_pdf:
                embedded = PdfFileReader(
                    signed_pdf
                ).embedded_signatures[-1]
                cms_object = cms.ContentInfo.load(
                    bytes(embedded.pkcs7_content)
                )
                unsigned_attributes = (
                    cms_object["content"]["signer_infos"][0][
                        "unsigned_attrs"
                    ]
                )
                timestamp_token = next(
                    attribute["values"][0]
                    for attribute in unsigned_attributes
                    if attribute["type"].native
                    == "signature_time_stamp_token"
                )
                timestamp_signature = bytes(
                    timestamp_token["content"]["signer_infos"][0][
                        "signature"
                    ]
                )

            signed_bytes = bytearray(signed.read_bytes())
            encoded_timestamp_signature = (
                timestamp_signature.hex().upper().encode("ascii")
            )
            timestamp_offset = signed_bytes.find(
                encoded_timestamp_signature
            )
            self.assertGreaterEqual(timestamp_offset, 0)
            signed_bytes[timestamp_offset] = (
                ord("0")
                if signed_bytes[timestamp_offset] != ord("0")
                else ord("1")
            )
            signed.write_bytes(signed_bytes)

            verification = service.verify_pdf(
                signed,
                expected_profile=PADES_B_T_PROFILE,
            )

            self.assertTrue(verification.intact)
            self.assertTrue(verification.timestamp_present)
            self.assertFalse(verification.timestamp_valid)
            self.assertFalse(verification.valid)

    def test_old_invisible_pades_b_b_remains_valid(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            material = DevelopmentCertificateMaterial(root)
            source = root / "original.pdf"
            signed = root / "old-invisible-b-b.pdf"
            _write_valid_pdf(source)
            service = material.service()
            signature_material = service._load_certificate_material()
            certificate, _, chain = signature_material

            with (
                service._open_signer(certificate, chain) as signer,
                source.open("rb") as source_pdf,
                signed.open("wb") as output_pdf,
            ):
                writer = IncrementalPdfFileWriter(source_pdf)
                signers.PdfSigner(
                    signers.PdfSignatureMetadata(
                        field_name="HistoricalInvisibleSignature",
                        md_algorithm="sha256",
                        subfilter=fields.SigSeedSubFilter.PADES,
                    ),
                    signer=signer,
                ).sign_pdf(writer, output=output_pdf)

            verification = service.verify_pdf(
                signed,
                expected_profile=PADES_B_B_PROFILE,
            )

            self.assertTrue(verification.valid)
            self.assertFalse(verification.timestamp_present)

    def test_modified_signed_pdf_fails_cryptographic_validation(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            material = DevelopmentCertificateMaterial(root)
            source = root / "original.pdf"
            signed = root / "signed.pdf"
            _write_valid_pdf(source)
            service = material.service()
            service.sign_pdf(
                source_pdf_path=source,
                output_pdf_path=signed,
                signature_id=uuid.uuid4(),
                signer_name="Test User",
            )
            signed_bytes = signed.read_bytes()
            marker = signed_bytes.index(b"%PDF-1.") + len(b"%PDF-1.")
            tampered = bytearray(signed_bytes)
            tampered[marker] = (
                ord("6") if tampered[marker] != ord("6") else ord("5")
            )
            signed.write_bytes(tampered)

            verification = service.verify_pdf(signed)

            self.assertFalse(
                verification.valid and verification.intact
            )

    def test_certificate_must_match_hsm_public_key(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            material = DevelopmentCertificateMaterial(root)
            source = root / "original.pdf"
            signed = root / "signed.pdf"
            _write_valid_pdf(source)
            wrong_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            service = PAdESService(
                settings=material.settings,
                public_key_der_supplier=lambda: (
                    wrong_key.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                ),
            )

            with self.assertRaises(PAdESServiceError):
                service.sign_pdf(
                    source_pdf_path=source,
                    output_pdf_path=signed,
                    signature_id=uuid.uuid4(),
                    signer_name="Test User",
                )

            self.assertFalse(signed.exists())

    def test_production_service_uses_pkcs11_and_not_tls_or_private_key(
        self,
    ) -> None:
        source = inspect.getsource(PAdESService)

        self.assertIn("PKCS11Signer", source)
        self.assertIn("open_pkcs11_session", source)
        self.assertNotIn("server.crt", source)
        self.assertNotIn("server.key", source)
        self.assertNotIn("load_private_key", source)
        self.assertNotIn("ObjectClass.PRIVATE_KEY", source)

        raw_signing = inspect.getsource(
            RemoteSignLabPKCS11Signer.async_sign_raw
        )
        self.assertIn("self._key_handle.sign", raw_signing)
        self.assertNotIn("run_in_executor", raw_signing)


class SignatureVerificationEndpointTests(unittest.TestCase):
    def test_verify_endpoint_reports_valid_b_t_timestamp(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            document_storage = root / "documents"
            signed_storage = root / "signed"
            document_storage.mkdir()
            signed_storage.mkdir()
            source = document_storage / "original.pdf"
            _write_valid_pdf(source)
            document_hash = hashlib.sha256(
                source.read_bytes()
            ).hexdigest()
            material = DevelopmentCertificateMaterial(root)
            tsa_material = DevelopmentTSAMaterial(root)
            service = material.service(
                profile=PADES_B_T_PROFILE,
                tsa_ca_certificate=tsa_material.ca_path,
                timestamper=tsa_material.timestamper(),
            )
            signature_id = uuid.uuid4()
            signed_filename = f"signed-{signature_id}.pdf"
            signed_path = signed_storage / signed_filename
            pades_result = service.sign_pdf(
                source_pdf_path=source,
                output_pdf_path=signed_path,
                signature_id=signature_id,
                signer_name="Alice Martin",
            )
            detached_signature = material.signing_key.sign(
                bytes.fromhex(document_hash),
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )
            document = SimpleNamespace(
                id=uuid.uuid4(),
                stored_filename=source.name,
                document_hash=document_hash,
            )
            signature_record = SimpleNamespace(
                id=signature_id,
                session_id=uuid.uuid4(),
                document_id=document.id,
                algorithm="RSASSA-PKCS1-v1_5-SHA256",
                key_label="test-only",
                document_hash=document_hash,
                signature_base64=base64.b64encode(
                    detached_signature
                ).decode("ascii"),
                signed_document_path=signed_filename,
                pades_profile=PADES_B_T_PROFILE,
                certificate_fingerprint_sha256=(
                    pades_result.certificate_fingerprint_sha256
                ),
                timestamp_time=pades_result.timestamp_time,
                tsa_certificate_subject=(
                    pades_result.tsa_certificate_subject
                ),
                tsa_certificate_fingerprint_sha256=(
                    pades_result
                    .tsa_certificate_fingerprint_sha256
                ),
            )

            class VerificationDatabase:
                @staticmethod
                def get(model, record_id):
                    if (
                        model is DocumentSignature
                        and record_id == signature_record.id
                    ):
                        return signature_record

                    if model.__name__ == "Document" and record_id == document.id:
                        return document

                    return None

            fake_hsm = SimpleNamespace(
                get_public_key_der=material.public_key_der
            )

            with (
                patch.object(
                    signature_api,
                    "DOCUMENT_STORAGE",
                    document_storage,
                ),
                patch.object(
                    signature_api,
                    "SIGNED_DOCUMENT_STORAGE",
                    signed_storage,
                ),
                patch.object(
                    signature_api,
                    "HSMService",
                    return_value=fake_hsm,
                ),
                patch.object(
                    signature_api,
                    "PAdESService",
                    return_value=service,
                ),
                patch.object(
                    signature_api,
                    "_record_verification_event",
                ) as audit,
            ):
                response = signature_api.verify_signature(
                    str(signature_id),
                    SimpleNamespace(
                        client=None,
                        method="GET",
                        url=SimpleNamespace(
                            path=(
                                "/api/v1/signatures/"
                                f"{signature_id}/verify"
                            )
                        ),
                        headers={},
                    ),
                    VerificationDatabase(),
                )

            self.assertTrue(response["valid"])
            self.assertEqual(
                response["pades_profile"],
                PADES_B_T_PROFILE,
            )
            self.assertTrue(response["document_intact"])
            self.assertTrue(response["signer_certificate_trusted"])
            self.assertTrue(response["timestamp_present"])
            self.assertTrue(response["timestamp_valid"])
            self.assertIsNotNone(response["timestamp_time"])
            self.assertIn(
                "RemoteSignLab Development TSA",
                response["tsa_subject"],
            )
            self.assertEqual(
                [
                    call.kwargs["event_type"]
                    for call in audit.call_args_list
                ],
                [
                    "SIGNATURE_VERIFY_REQUESTED",
                    "SIGNATURE_VERIFY_SUCCESS",
                ],
            )


class SigningDatabase:
    def __init__(self, device, auth_session, document) -> None:
        self.scalar_results = iter(
            [device, auth_session, None]
        )
        self.document = document
        self.user = SimpleNamespace(
            id=document.user_id,
            full_name="Test User",
        )
        self.added = []
        self.rollback_count = 0
        self.commit_count = 0
        self.refresh_count = 0
        self.on_commit = None

    def scalar(self, _statement):
        return next(self.scalar_results)

    def get(self, model, record_id):
        if model is User and record_id == self.user.id:
            return self.user

        return self.document if record_id == self.document.id else None

    def add(self, record) -> None:
        self.added.append(record)

    def flush(self) -> None:
        pass

    def commit(self) -> None:
        self.commit_count += 1

        if self.on_commit is not None:
            self.on_commit()

    def rollback(self) -> None:
        self.rollback_count += 1

    def refresh(self, _record) -> None:
        self.refresh_count += 1


class FakeHSMService:
    def sign_sha256_digest_rsa_pkcs1(
        self,
        digest: bytes,
    ) -> SignatureResult:
        if len(digest) != 32:
            raise AssertionError("Expected SHA-256 digest")

        raw_signature = b"test-only-detached-signature"
        return SignatureResult(
            signature=raw_signature,
            signature_base64=base64.b64encode(
                raw_signature
            ).decode("ascii"),
            algorithm="RSASSA-PKCS1-v1_5-SHA256",
            key_label="test-only",
        )


class PAdESSigningWorkflowTests(unittest.TestCase):
    def _workflow_records(self, source: Path):
        document_hash = hashlib.sha256(
            source.read_bytes()
        ).hexdigest()
        user_id = uuid.uuid4()
        device = SimpleNamespace(
            id=uuid.uuid4(),
            device_uid="ESP32-001",
            device_secret="11" * 32,
            status=DeviceStatus.ACTIVE,
            last_seen=None,
        )
        document = SimpleNamespace(
            id=uuid.uuid4(),
            user_id=user_id,
            stored_filename=source.name,
            document_hash=document_hash,
        )
        auth_session = SimpleNamespace(
            id=uuid.uuid4(),
            user_id=user_id,
            device_id=device.id,
            document_id=document.id,
            document_hash=document_hash,
            decision="APPROVE",
            verified_at=datetime.now(timezone.utc),
            used_at=None,
        )
        queue_request = SimpleNamespace(
            status=SignatureRequestStatus.AUTHENTICATED,
        )
        return device, document, auth_session, queue_request

    def _call_sign(
        self,
        *,
        database,
        device,
        document,
        auth_session,
        document_storage: Path,
        signed_storage: Path,
        pades_service,
        mark_signed,
    ):
        request = SimpleNamespace(
            client=None,
            method="POST",
            url=SimpleNamespace(path="/api/v1/sign"),
        )

        with (
            patch.object(signing, "DOCUMENT_STORAGE", document_storage),
            patch.object(
                signing,
                "SIGNED_DOCUMENT_STORAGE",
                signed_storage,
            ),
            patch.object(signing, "is_rate_limited", return_value=False),
            patch.object(signing, "verify_device_hmac", return_value=True),
            patch.object(
                signing,
                "signature_request_is_authorized_for_session",
                return_value=True,
            ),
            patch.object(signing, "consume_nonce", return_value=True),
            patch.object(signing, "HSMService", return_value=FakeHSMService()),
            patch.object(signing, "PAdESService", return_value=pades_service),
            patch.object(
                signing,
                "try_mark_signature_request_signed",
                side_effect=mark_signed,
            ),
            patch.object(signing, "record_audit_event", return_value=True),
        ):
            return signing.sign_document(
                request,
                device.device_uid,
                "1700000000",
                "00112233445566778899aabbccddeeff",
                str(auth_session.id),
                str(document.id),
                document.document_hash,
                "APPROVE",
                "00" * 32,
                database,
            )

    def test_authenticated_workflow_publishes_pdf_before_signed_state(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            document_storage = root / "documents"
            signed_storage = root / "signed"
            document_storage.mkdir()
            source = document_storage / "original.pdf"
            _write_valid_pdf(source)
            original_bytes = source.read_bytes()
            material = DevelopmentCertificateMaterial(root)
            device, document, auth_session, queue_request = (
                self._workflow_records(source)
            )
            database = SigningDatabase(
                device,
                auth_session,
                document,
            )

            def mark_signed(
                _database,
                *,
                authentication_session_id,
                signature,
            ):
                self.assertEqual(
                    authentication_session_id,
                    auth_session.id,
                )
                self.assertTrue(
                    (signed_storage / signature.signed_document_path)
                    .is_file()
                )
                queue_request.status = SignatureRequestStatus.SIGNED

            database.on_commit = lambda: self.assertEqual(
                queue_request.status,
                SignatureRequestStatus.SIGNED,
            )
            pades_service = Mock(wraps=material.service())

            response = self._call_sign(
                database=database,
                device=device,
                document=document,
                auth_session=auth_session,
                document_storage=document_storage,
                signed_storage=signed_storage,
                pades_service=pades_service,
                mark_signed=mark_signed,
            )

            signature_record = next(
                record
                for record in database.added
                if isinstance(record, DocumentSignature)
            )
            signed_path = (
                signed_storage
                / signature_record.signed_document_path
            )
            self.assertEqual(source.read_bytes(), original_bytes)
            self.assertTrue(signed_path.is_file())
            self.assertEqual(
                signature_record.pades_profile,
                PADES_PROFILE,
            )
            self.assertEqual(response["pades_profile"], PADES_PROFILE)
            self.assertEqual(
                queue_request.status,
                SignatureRequestStatus.SIGNED,
            )
            self.assertEqual(database.commit_count, 1)
            self.assertEqual(
                pades_service.sign_pdf.call_args.kwargs[
                    "signer_name"
                ],
                database.user.full_name,
            )

    def test_pades_failure_never_marks_request_signed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            document_storage = root / "documents"
            signed_storage = root / "signed"
            document_storage.mkdir()
            source = document_storage / "original.pdf"
            _write_valid_pdf(source)
            device, document, auth_session, queue_request = (
                self._workflow_records(source)
            )
            database = SigningDatabase(
                device,
                auth_session,
                document,
            )
            failed_service = SimpleNamespace(
                sign_pdf=Mock(
                    side_effect=PAdESServiceError(
                        "test-only failure"
                    )
                )
            )
            mark_signed = Mock()

            with self.assertRaises(HTTPException) as rejected:
                self._call_sign(
                    database=database,
                    device=device,
                    document=document,
                    auth_session=auth_session,
                    document_storage=document_storage,
                    signed_storage=signed_storage,
                    pades_service=failed_service,
                    mark_signed=mark_signed,
                )

            self.assertEqual(rejected.exception.status_code, 503)
            self.assertEqual(
                queue_request.status,
                SignatureRequestStatus.AUTHENTICATED,
            )
            mark_signed.assert_not_called()
            self.assertFalse(
                any(
                    isinstance(record, DocumentSignature)
                    for record in database.added
                )
            )
            self.assertEqual(list(signed_storage.glob("*")), [])

    def test_authenticated_workflow_stores_b_t_metadata_before_signed(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            document_storage = root / "documents"
            signed_storage = root / "signed"
            document_storage.mkdir()
            source = document_storage / "original.pdf"
            _write_valid_pdf(source)
            material = DevelopmentCertificateMaterial(root)
            tsa_material = DevelopmentTSAMaterial(root)
            device, document, auth_session, queue_request = (
                self._workflow_records(source)
            )
            database = SigningDatabase(
                device,
                auth_session,
                document,
            )
            pades_service = material.service(
                profile=PADES_B_T_PROFILE,
                tsa_ca_certificate=tsa_material.ca_path,
                timestamper=tsa_material.timestamper(),
            )

            def mark_signed(
                _database,
                *,
                authentication_session_id,
                signature,
            ):
                self.assertEqual(
                    authentication_session_id,
                    auth_session.id,
                )
                self.assertEqual(
                    signature.pades_profile,
                    PADES_B_T_PROFILE,
                )
                self.assertIsNotNone(signature.timestamp_time)
                self.assertIn(
                    "RemoteSignLab Development TSA",
                    signature.tsa_certificate_subject,
                )
                self.assertEqual(
                    len(
                        signature
                        .tsa_certificate_fingerprint_sha256
                    ),
                    64,
                )
                self.assertTrue(
                    (signed_storage / signature.signed_document_path)
                    .is_file()
                )
                queue_request.status = SignatureRequestStatus.SIGNED

            response = self._call_sign(
                database=database,
                device=device,
                document=document,
                auth_session=auth_session,
                document_storage=document_storage,
                signed_storage=signed_storage,
                pades_service=pades_service,
                mark_signed=mark_signed,
            )

            self.assertEqual(
                queue_request.status,
                SignatureRequestStatus.SIGNED,
            )
            self.assertEqual(
                response["pades_profile"],
                PADES_B_T_PROFILE,
            )
            self.assertIsNotNone(response["timestamp_time"])
            self.assertIn(
                    "RemoteSignLab Development TSA",
                response["tsa_subject"],
            )

    def test_wrong_file_hash_is_rejected_before_pades(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            document_storage = root / "documents"
            document_storage.mkdir()
            source = document_storage / "original.pdf"
            _write_valid_pdf(source)
            device, document, auth_session, queue_request = (
                self._workflow_records(source)
            )
            source.write_bytes(source.read_bytes() + b"tampered")
            database = SigningDatabase(
                device,
                auth_session,
                document,
            )
            pades_service = SimpleNamespace(sign_pdf=Mock())

            with (
                patch.object(
                    signing,
                    "persist_terminal_signature_request_failure",
                    return_value=True,
                ),
                self.assertRaises(HTTPException) as rejected,
            ):
                self._call_sign(
                    database=database,
                    device=device,
                    document=document,
                    auth_session=auth_session,
                    document_storage=document_storage,
                    signed_storage=root / "signed",
                    pades_service=pades_service,
                    mark_signed=Mock(),
                )

            self.assertEqual(rejected.exception.status_code, 409)
            pades_service.sign_pdf.assert_not_called()
            self.assertEqual(
                queue_request.status,
                SignatureRequestStatus.AUTHENTICATED,
            )


class SignedDownloadDatabase:
    def __init__(self, document, signature) -> None:
        self.document = document
        self.signature = signature
        self.statements = []

    def scalar(self, statement):
        self.statements.append(statement)
        entity = statement.column_descriptions[0].get("entity")
        parameters = statement.compile(
            dialect=postgresql.dialect()
        ).params.values()

        if entity is not None and entity.__name__ == "Document":
            return (
                self.document
                if self.document.user_id in parameters
                else None
            )

        if entity is DocumentSignature:
            return self.signature

        return None


class SignedDocumentDownloadTests(unittest.TestCase):
    def test_owner_can_download_server_selected_signed_pdf(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            user_id = uuid.uuid4()
            document = SimpleNamespace(
                id=uuid.uuid4(),
                user_id=user_id,
            )
            signed_filename = f"{document.id}-{uuid.uuid4()}.pdf"
            signed_path = root / signed_filename
            signed_path.write_bytes(b"signed-pdf-test")
            signature = SimpleNamespace(
                signed_document_path=signed_filename,
            )
            session = UserSession(
                id="session-a",
                user_id=user_id,
                csrf_token="csrf-a",
                expires_at=999999999.0,
            )

            with (
                patch(
                    "app.user_web.routes.SIGNED_DOCUMENT_STORAGE",
                    root,
                ),
                patch(
                    "app.user_web.routes.record_audit_event",
                    return_value=True,
                ) as audit,
            ):
                response = download_user_signed_document(
                    document.id,
                    SimpleNamespace(
                        client=None,
                        method="GET",
                        url=SimpleNamespace(
                            path=f"/user/documents/{document.id}/signed"
                        ),
                        headers={},
                    ),
                    session,
                    SignedDownloadDatabase(document, signature),
                )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(Path(response.path), signed_path)
            self.assertEqual(
                response.media_type,
                "application/pdf",
            )
            self.assertEqual(
                audit.call_args.kwargs["event_type"],
                "SIGNED_DOCUMENT_DOWNLOADED",
            )

    def test_user_cannot_download_another_users_signed_pdf(
        self,
    ) -> None:
        owner_id = uuid.uuid4()
        document = SimpleNamespace(
            id=uuid.uuid4(),
            user_id=owner_id,
        )
        session = UserSession(
            id="session-b",
            user_id=uuid.uuid4(),
            csrf_token="csrf-b",
            expires_at=999999999.0,
        )

        with self.assertRaises(HTTPException) as rejected:
            download_user_signed_document(
                document.id,
                SimpleNamespace(
                    client=None,
                    method="GET",
                    url=SimpleNamespace(
                        path=f"/user/documents/{document.id}/signed"
                    ),
                    headers={},
                ),
                session,
                SignedDownloadDatabase(
                    document,
                    SimpleNamespace(
                        signed_document_path="must-not-be-used.pdf"
                    ),
                ),
            )

        self.assertEqual(rejected.exception.status_code, 404)

    def test_historical_signature_without_pades_remains_readable(
        self,
    ) -> None:
        completed_at = datetime.now(timezone.utc)
        response = _request_response(
            SimpleNamespace(
                id=uuid.uuid4(),
                document_id=uuid.uuid4(),
                status=SignatureRequestStatus.SIGNED,
                signature_id=uuid.uuid4(),
                completed_at=completed_at,
            ),
            document=SimpleNamespace(
                original_filename="historical.pdf"
            ),
            signature=SimpleNamespace(
                algorithm="RSASSA-PKCS1-v1_5-SHA256"
            ),
        )

        self.assertEqual(response["state"], "SIGNED")
        self.assertFalse(response["signed_document_available"])
        self.assertNotIn("pades_profile", response)
        self.assertEqual(
            response["signed_at"],
            completed_at.isoformat(),
        )


class PAdESMigrationTests(unittest.TestCase):
    def test_migration_is_nullable_and_preserves_historical_rows(
        self,
    ) -> None:
        migration = (
            PROJECT_ROOT
            / "alembic/versions/c31d7e9f4b22_add_pades_signature_metadata.py"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'down_revision: Union[str, Sequence[str], None] = "b8127e4c9a30"',
            migration,
        )

        for column in (
            "signed_document_path",
            "pades_profile",
            "certificate_fingerprint_sha256",
            "certificate_subject",
            "signing_time",
        ):
            self.assertIn(f'"{column}"', migration)

        self.assertGreaterEqual(
            migration.count("nullable=True"),
            5,
        )
        self.assertNotIn("UPDATE document_signatures", migration)
        self.assertIn(
            "ck_document_signature_pades_metadata_complete",
            migration,
        )

    def test_user_ui_offers_download_only_for_pades_pdf(self) -> None:
        javascript = (
            PROJECT_ROOT / "app/user_web/static/app.js"
        ).read_text(encoding="utf-8")

        self.assertIn("Download signed PDF", javascript)
        self.assertIn(
            "item.request.signed_document_available === true",
            javascript,
        )
        self.assertIn(
            "/user/documents/${encodeURIComponent(item.document_id)}/signed",
            javascript,
        )

    def test_timestamp_migration_is_nullable_and_has_no_backfill(
        self,
    ) -> None:
        migration = (
            PROJECT_ROOT
            / "alembic/versions/e74a1c6d902f_add_pades_timestamp_metadata.py"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'down_revision: Union[str, Sequence[str], None] = "c31d7e9f4b22"',
            migration,
        )

        for column in (
            "timestamp_time",
            "tsa_certificate_subject",
            "tsa_certificate_fingerprint_sha256",
        ):
            self.assertIn(f'"{column}"', migration)

        self.assertGreaterEqual(migration.count("nullable=True"), 3)
        self.assertNotIn("UPDATE document_signatures", migration)
        self.assertIn(
            "ck_document_signature_tsa_metadata_complete",
            migration,
        )
        self.assertIn("pades_profile = 'PAdES-B-T'", migration)

    def test_user_and_admin_ui_display_b_t_metadata(self) -> None:
        user_javascript = (
            PROJECT_ROOT / "app/user_web/static/app.js"
        ).read_text(encoding="utf-8")
        admin_javascript = (
            PROJECT_ROOT / "app/web/static/app.js"
        ).read_text(encoding="utf-8")

        for javascript in (user_javascript, admin_javascript):
            self.assertIn("Signer:", javascript)
            self.assertIn("Timestamp:", javascript)
            self.assertIn("TSA:", javascript)


if __name__ == "__main__":
    unittest.main()
