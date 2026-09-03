import hashlib
import hmac
import importlib.util
import json
import sys
import types
import unittest
import uuid

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import FastAPI, HTTPException
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase

from app.security.device_auth import (
    build_canonical_message,
    verify_device_hmac,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Fixed test material only. These tests deliberately never load Settings or
# dotenv files, so no configured device or administrator secret is involved.
TEST_ONLY_DEVICE_SECRET_HEX = "11" * 32
TEST_TIMESTAMP = "1700000000"
TEST_NONCE = "00112233445566778899aabbccddeeff"
DEVICE_UID = "ESP32-QUEUE-TEST"
REQUEST_ID = uuid.UUID("12345678-1234-5678-9234-567812345678")

NEXT_PATH = "/api/v1/device/signature-requests/next"
STATUS_PATH = (
    "/api/v1/device/signature-requests/"
    f"{REQUEST_ID}/status"
)


class _IsolatedBase(DeclarativeBase):
    pass


def _load_source_module(
    module_name: str,
    relative_path: str,
):
    spec = importlib.util.spec_from_file_location(
        module_name,
        PROJECT_ROOT / relative_path,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Unable to load test target {relative_path}"
        )

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    return module


def _load_queue_modules_without_settings():
    """Load queue code without importing app.database or app.config."""

    fake_database = types.ModuleType("app.database")

    def fake_get_db():
        yield None

    fake_database.Base = _IsolatedBase
    fake_database.get_db = fake_get_db

    with patch.dict(
        sys.modules,
        {"app.database": fake_database},
    ):
        models = _load_source_module(
            "_queue_test_models",
            "app/models.py",
        )

    with patch.dict(
        sys.modules,
        {
            "app.database": fake_database,
            "app.models": models,
        },
    ):
        service = _load_source_module(
            "_queue_test_service",
            "app/services/signature_request_service.py",
        )

    fake_nonce_store = types.ModuleType(
        "app.security.nonce_store"
    )
    fake_nonce_store.consume_nonce = lambda **_kwargs: True

    fake_rate_limit = types.ModuleType(
        "app.security.rate_limit"
    )
    fake_rate_limit.is_rate_limited = (
        lambda *_args, **_kwargs: False
    )

    fake_audit_service = types.ModuleType(
        "app.services.audit_service"
    )
    fake_audit_service.add_audit_event = (
        lambda *_args, **_kwargs: None
    )
    fake_audit_service.record_audit_event = (
        lambda *_args, **_kwargs: True
    )

    with patch.dict(
        sys.modules,
        {
            "app.database": fake_database,
            "app.models": models,
            "app.security.nonce_store": fake_nonce_store,
            "app.security.rate_limit": fake_rate_limit,
            "app.services.audit_service": fake_audit_service,
            "app.services.signature_request_service": service,
        },
    ):
        routes = _load_source_module(
            "_queue_test_routes",
            "app/api/device_signature_requests.py",
        )

    return models, service, routes


QUEUE_MODELS, QUEUE_SERVICE, QUEUE_ROUTES = (
    _load_queue_modules_without_settings()
)


def _test_signature(canonical_message: bytes) -> str:
    return hmac.new(
        bytes.fromhex(TEST_ONLY_DEVICE_SECRET_HEX),
        canonical_message,
        hashlib.sha256,
    ).hexdigest()


class DeviceQueueCanonicalTests(unittest.TestCase):
    def test_next_canonical_message_is_byte_exact(self) -> None:
        canonical = build_canonical_message(
            method="POST",
            path=NEXT_PATH,
            timestamp=TEST_TIMESTAMP,
            nonce=TEST_NONCE,
            extra_data=DEVICE_UID,
        )

        self.assertEqual(
            canonical,
            (
                "POST\n"
                "/api/v1/device/signature-requests/next\n"
                "1700000000\n"
                "00112233445566778899aabbccddeeff\n"
                "ESP32-QUEUE-TEST"
            ).encode("utf-8"),
        )
        self.assertFalse(canonical.endswith(b"\n"))

    def test_status_canonical_message_is_byte_exact(self) -> None:
        extra_data = "\n".join(
            [
                DEVICE_UID,
                "FAILED",
                "RFID_REJECTED",
            ]
        )
        canonical = build_canonical_message(
            method="POST",
            path=STATUS_PATH,
            timestamp=TEST_TIMESTAMP,
            nonce=TEST_NONCE,
            extra_data=extra_data,
        )

        self.assertEqual(
            canonical,
            (
                "POST\n"
                "/api/v1/device/signature-requests/"
                "12345678-1234-5678-9234-567812345678/status\n"
                "1700000000\n"
                "00112233445566778899aabbccddeeff\n"
                "ESP32-QUEUE-TEST\n"
                "FAILED\n"
                "RFID_REJECTED"
            ).encode("utf-8"),
        )
        self.assertFalse(canonical.endswith(b"\n"))

    def test_fixed_test_hmac_is_accepted_and_tampering_is_rejected(
        self,
    ) -> None:
        canonical = build_canonical_message(
            method="POST",
            path=NEXT_PATH,
            timestamp=TEST_TIMESTAMP,
            nonce=TEST_NONCE,
            extra_data=DEVICE_UID,
        )
        signature = _test_signature(canonical)

        with patch(
            "app.security.device_auth.time.time",
            return_value=int(TEST_TIMESTAMP),
        ):
            self.assertTrue(
                verify_device_hmac(
                    device_secret=(
                        TEST_ONLY_DEVICE_SECRET_HEX
                    ),
                    method="POST",
                    path=NEXT_PATH,
                    timestamp=TEST_TIMESTAMP,
                    nonce=TEST_NONCE,
                    received_signature=signature,
                    extra_data=DEVICE_UID,
                )
            )
            self.assertFalse(
                verify_device_hmac(
                    device_secret=(
                        TEST_ONLY_DEVICE_SECRET_HEX
                    ),
                    method="POST",
                    path=NEXT_PATH,
                    timestamp=TEST_TIMESTAMP,
                    nonce=TEST_NONCE,
                    received_signature=(
                        "0" * len(signature)
                    ),
                    extra_data=DEVICE_UID,
                )
            )
            self.assertFalse(
                verify_device_hmac(
                    device_secret=(
                        TEST_ONLY_DEVICE_SECRET_HEX
                    ),
                    method="POST",
                    path=NEXT_PATH,
                    timestamp=TEST_TIMESTAMP,
                    nonce=TEST_NONCE,
                    received_signature=signature,
                    extra_data="ANOTHER-DEVICE",
                )
            )

    def test_existing_hmac_canonicals_are_byte_exact(self) -> None:
        challenge = build_canonical_message(
            method="POST",
            path="/api/v1/auth/challenge",
            timestamp="1700000001",
            nonce="11112222333344445555666677778888",
            extra_data="\n".join(
                [
                    "04AABBCCDD",
                    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "ab" * 32,
                    "APPROVE",
                ]
            ),
        )
        complete = build_canonical_message(
            method="POST",
            path="/api/v1/auth/complete",
            timestamp="1700000002",
            nonce="22223333444455556666777788889999",
            extra_data="\n".join(
                [
                    "12345678-1234-4678-9234-567812345678",
                    "cd" * 32,
                    "04AABBCCDD",
                    "7",
                    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "ab" * 32,
                    "APPROVE",
                ]
            ),
        )
        signing = build_canonical_message(
            method="POST",
            path="/api/v1/sign",
            timestamp="1700000003",
            nonce="3333444455556666777788889999aaaa",
            extra_data="\n".join(
                [
                    "12345678-1234-4678-9234-567812345678",
                    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "ab" * 32,
                    "APPROVE",
                ]
            ),
        )

        self.assertEqual(
            challenge.decode("utf-8").splitlines(),
            [
                "POST",
                "/api/v1/auth/challenge",
                "1700000001",
                "11112222333344445555666677778888",
                "04AABBCCDD",
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "ab" * 32,
                "APPROVE",
            ],
        )
        self.assertEqual(
            complete.decode("utf-8").splitlines(),
            [
                "POST",
                "/api/v1/auth/complete",
                "1700000002",
                "22223333444455556666777788889999",
                "12345678-1234-4678-9234-567812345678",
                "cd" * 32,
                "04AABBCCDD",
                "7",
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "ab" * 32,
                "APPROVE",
            ],
        )
        self.assertEqual(
            signing.decode("utf-8").splitlines(),
            [
                "POST",
                "/api/v1/sign",
                "1700000003",
                "3333444455556666777788889999aaaa",
                "12345678-1234-4678-9234-567812345678",
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "ab" * 32,
                "APPROVE",
            ],
        )


class DeviceQueueContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        application = FastAPI()
        application.include_router(QUEUE_ROUTES.router)
        cls.openapi = application.openapi()

    def test_claim_response_has_exactly_four_fields(self) -> None:
        model = QUEUE_ROUTES.ClaimedSignatureRequestResponse(
            request_id=REQUEST_ID,
            document_id=uuid.UUID(
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            ),
            document_hash="ab" * 32,
            decision="APPROVE",
        )
        payload = model.model_dump(mode="json")

        self.assertEqual(
            set(payload),
            {
                "request_id",
                "document_id",
                "document_hash",
                "decision",
            },
        )
        self.assertEqual(len(payload), 4)

        with self.assertRaises(ValidationError):
            QUEUE_ROUTES.ClaimedSignatureRequestResponse(
                request_id=REQUEST_ID,
                document_id=uuid.uuid4(),
                document_hash="ab" * 32,
                decision="APPROVE",
                device_secret="must-never-be-returned",
            )

    def test_openapi_exposes_both_device_queue_endpoints(self) -> None:
        self.assertIn(NEXT_PATH, self.openapi["paths"])
        self.assertIn(
            (
                "/api/v1/device/signature-requests/"
                "{request_id}/status"
            ),
            self.openapi["paths"],
        )

    def test_openapi_requires_four_hmac_headers_without_admin_key(
        self,
    ) -> None:
        expected_headers = {
            "x-device-uid",
            "x-timestamp",
            "x-nonce",
            "x-signature",
        }
        paths = (
            NEXT_PATH,
            (
                "/api/v1/device/signature-requests/"
                "{request_id}/status"
            ),
        )

        for path in paths:
            with self.subTest(path=path):
                operation = self.openapi["paths"][path]["post"]
                headers = {
                    parameter["name"].lower()
                    for parameter in operation["parameters"]
                    if parameter["in"] == "header"
                    and parameter["required"] is True
                }

                self.assertEqual(headers, expected_headers)
                self.assertNotIn("AdminApiKey", json.dumps(operation))
                self.assertNotEqual(
                    operation.get("security"),
                    [{"AdminApiKey": []}],
                )

    def test_openapi_claim_schema_has_only_the_public_fields(
        self,
    ) -> None:
        schema = self.openapi["components"]["schemas"][
            "ClaimedSignatureRequestResponse"
        ]

        self.assertEqual(
            set(schema["properties"]),
            {
                "request_id",
                "document_id",
                "document_hash",
                "decision",
            },
        )
        self.assertEqual(
            set(schema["required"]),
            set(schema["properties"]),
        )
        self.assertFalse(
            schema.get("additionalProperties", True)
        )


class _DeviceEndpointDatabase:
    def __init__(self, device=None) -> None:
        self.device = device
        self.scalar_statements = []
        self.commit_count = 0
        self.refresh_count = 0

    def scalar(self, statement):
        self.scalar_statements.append(statement)
        return self.device

    def commit(self) -> None:
        self.commit_count += 1

    def refresh(self, _record) -> None:
        self.refresh_count += 1


def _device_request(path: str = NEXT_PATH):
    return SimpleNamespace(
        client=None,
        method="POST",
        url=SimpleNamespace(path=path),
    )


def _active_test_device():
    return SimpleNamespace(
        id=uuid.UUID(
            "dddddddd-1111-4222-8333-444444444444"
        ),
        device_uid=DEVICE_UID,
        device_secret=TEST_ONLY_DEVICE_SECRET_HEX,
        status=QUEUE_MODELS.DeviceStatus.ACTIVE,
        last_seen=None,
    )


class DeviceQueueAuthenticationOrderTests(unittest.TestCase):
    def test_hmac_is_verified_before_nonce_is_consumed(self) -> None:
        calls = []
        device = _active_test_device()
        database = _DeviceEndpointDatabase(device)

        def verify(**_kwargs):
            calls.append("hmac")
            return True

        def consume(**_kwargs):
            calls.append("nonce")
            return True

        with (
            patch.object(
                QUEUE_ROUTES,
                "verify_device_hmac",
                side_effect=verify,
            ),
            patch.object(
                QUEUE_ROUTES,
                "consume_nonce",
                side_effect=consume,
            ),
        ):
            authenticated = QUEUE_ROUTES._authenticate_device(
                database,
                request=_device_request(),
                x_device_uid=DEVICE_UID.lower(),
                x_timestamp=TEST_TIMESTAMP,
                x_nonce=TEST_NONCE,
                x_signature="00" * 32,
                extra_data=DEVICE_UID,
            )

        self.assertIs(authenticated, device)
        self.assertEqual(calls, ["hmac", "nonce"])
        lookup_parameters = (
            database.scalar_statements[0]
            .compile(dialect=postgresql.dialect())
            .params
        )
        self.assertIn(DEVICE_UID, lookup_parameters.values())

    def test_invalid_hmac_never_consumes_the_nonce(self) -> None:
        device = _active_test_device()
        database = _DeviceEndpointDatabase(device)
        consume = Mock(return_value=True)

        with (
            patch.object(
                QUEUE_ROUTES,
                "verify_device_hmac",
                return_value=False,
            ),
            patch.object(
                QUEUE_ROUTES,
                "consume_nonce",
                consume,
            ),
        ):
            with self.assertRaises(HTTPException) as rejected:
                QUEUE_ROUTES._authenticate_device(
                    database,
                    request=_device_request(),
                    x_device_uid=DEVICE_UID,
                    x_timestamp=TEST_TIMESTAMP,
                    x_nonce=TEST_NONCE,
                    x_signature="00" * 32,
                    extra_data=DEVICE_UID,
                )

        self.assertEqual(rejected.exception.status_code, 401)
        consume.assert_not_called()


class DeviceQueueEndpointResponseTests(unittest.TestCase):
    def test_empty_queue_commits_nonce_and_returns_empty_204(self) -> None:
        device = _active_test_device()
        database = _DeviceEndpointDatabase()

        with (
            patch.object(
                QUEUE_ROUTES,
                "_authenticate_device",
                return_value=device,
            ),
            patch.object(
                QUEUE_ROUTES,
                "claim_next_signature_request",
                return_value=None,
            ),
        ):
            response = QUEUE_ROUTES.claim_next_request(
                _device_request(),
                DEVICE_UID,
                TEST_TIMESTAMP,
                TEST_NONCE,
                "00" * 32,
                database,
            )

        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.body, b"")
        self.assertEqual(database.commit_count, 1)

    def test_claimed_queue_response_has_only_four_fields(self) -> None:
        device = _active_test_device()
        database = _DeviceEndpointDatabase()
        signature_request = SimpleNamespace(
            id=REQUEST_ID,
            document_id=uuid.UUID(
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            ),
            document_hash="ab" * 32,
            decision="APPROVE",
        )

        with (
            patch.object(
                QUEUE_ROUTES,
                "_authenticate_device",
                return_value=device,
            ),
            patch.object(
                QUEUE_ROUTES,
                "claim_next_signature_request",
                return_value=signature_request,
            ),
        ):
            response = QUEUE_ROUTES.claim_next_request(
                _device_request(),
                DEVICE_UID,
                TEST_TIMESTAMP,
                TEST_NONCE,
                "00" * 32,
                database,
            )

        payload = response.model_dump(mode="json")
        self.assertEqual(
            set(payload),
            {
                "request_id",
                "document_id",
                "document_hash",
                "decision",
            },
        )
        self.assertEqual(database.commit_count, 1)
        self.assertEqual(database.refresh_count, 1)


class _RecordingDatabase:
    def __init__(self, scalar_results: list) -> None:
        self.scalar_results = list(scalar_results)
        self.scalar_statements = []
        self.execute_statements = []

    def scalar(self, statement):
        self.scalar_statements.append(statement)

        if not self.scalar_results:
            raise AssertionError("Unexpected scalar statement")

        return self.scalar_results.pop(0)

    def execute(self, statement):
        self.execute_statements.append(statement)

        return SimpleNamespace(rowcount=0)


class DeviceQueueTransitionTests(unittest.TestCase):
    def test_request_links_session_then_signature_without_regression(
        self,
    ) -> None:
        initial_time = datetime(
            2026,
            9,
            1,
            12,
            0,
            tzinfo=timezone.utc,
        )
        device_id = uuid.uuid4()
        document_id = uuid.uuid4()
        authentication_session_id = uuid.uuid4()
        signature_id = uuid.uuid4()
        request_record = SimpleNamespace(
            id=REQUEST_ID,
            device_id=device_id,
            document_id=document_id,
            document_hash="ab" * 32,
            decision="APPROVE",
            status=QUEUE_MODELS.SignatureRequestStatus.CLAIMED,
            expires_at=initial_time + timedelta(minutes=10),
            authentication_session_id=None,
            authentication_started_at=None,
            authenticated_at=None,
            signature_id=None,
            failure_detail=None,
            completed_at=None,
            updated_at=initial_time - timedelta(seconds=1),
        )
        authentication_session = SimpleNamespace(
            id=authentication_session_id,
            device_id=device_id,
            document_id=document_id,
            document_hash=request_record.document_hash,
            decision="APPROVE",
        )
        attach_database = _RecordingDatabase([request_record])

        with patch.object(
            QUEUE_SERVICE,
            "utc_now",
            return_value=initial_time,
        ):
            QUEUE_SERVICE.attach_authentication_session(
                attach_database,
                device_id=device_id,
                document_id=document_id,
                document_hash=request_record.document_hash,
                decision="APPROVE",
                authentication_session=authentication_session,
            )

        self.assertEqual(
            request_record.status,
            QUEUE_MODELS.SignatureRequestStatus.AUTHENTICATING,
        )
        self.assertEqual(
            request_record.authentication_session_id,
            authentication_session_id,
        )
        self.assertEqual(request_record.updated_at, initial_time)
        attach_sql = str(
            attach_database.scalar_statements[0].compile(
                dialect=postgresql.dialect()
            )
        ).upper()
        self.assertIn("FOR UPDATE", attach_sql)
        self.assertNotIn("SKIP LOCKED", attach_sql)

        authenticated_time = initial_time + timedelta(seconds=1)

        with patch.object(
            QUEUE_SERVICE,
            "utc_now",
            return_value=authenticated_time,
        ):
            QUEUE_SERVICE.mark_signature_request_authenticated(
                _RecordingDatabase([request_record]),
                authentication_session_id=(
                    authentication_session_id
                ),
            )

        self.assertEqual(
            request_record.status,
            QUEUE_MODELS.SignatureRequestStatus.AUTHENTICATED,
        )
        self.assertEqual(
            request_record.authenticated_at,
            authenticated_time,
        )
        self.assertEqual(
            request_record.updated_at,
            authenticated_time,
        )

        signed_time = initial_time + timedelta(seconds=2)
        signature = SimpleNamespace(
            id=signature_id,
            session_id=authentication_session_id,
            device_id=device_id,
            document_id=document_id,
            document_hash=request_record.document_hash,
        )

        with patch.object(
            QUEUE_SERVICE,
            "utc_now",
            return_value=signed_time,
        ):
            QUEUE_SERVICE.mark_signature_request_signed(
                _RecordingDatabase([request_record]),
                authentication_session_id=(
                    authentication_session_id
                ),
                signature=signature,
            )

        self.assertEqual(
            request_record.status,
            QUEUE_MODELS.SignatureRequestStatus.SIGNED,
        )
        self.assertEqual(request_record.signature_id, signature_id)
        self.assertEqual(request_record.completed_at, signed_time)
        self.assertEqual(request_record.updated_at, signed_time)

        # A terminal SIGNED row cannot be failed or moved backwards.
        with patch.object(
            QUEUE_SERVICE,
            "utc_now",
            return_value=initial_time + timedelta(seconds=3),
        ):
            QUEUE_SERVICE.mark_signature_request_failed(
                _RecordingDatabase([request_record]),
                request_id=REQUEST_ID,
                device_id=device_id,
                failure_detail="late failure",
            )
            QUEUE_SERVICE.mark_signature_request_authenticated(
                _RecordingDatabase([request_record]),
                authentication_session_id=(
                    authentication_session_id
                ),
            )

        self.assertEqual(
            request_record.status,
            QUEUE_MODELS.SignatureRequestStatus.SIGNED,
        )
        self.assertEqual(request_record.updated_at, signed_time)

    def test_only_pending_and_claimed_requests_expire(self) -> None:
        now = datetime(
            2026,
            9,
            1,
            12,
            0,
            tzinfo=timezone.utc,
        )

        for queue_status in (
            QUEUE_MODELS.SignatureRequestStatus.PENDING,
            QUEUE_MODELS.SignatureRequestStatus.CLAIMED,
        ):
            with self.subTest(queue_status=queue_status.value):
                request_record = SimpleNamespace(
                    status=queue_status,
                    expires_at=now - timedelta(seconds=1),
                    failure_detail=None,
                    completed_at=None,
                    updated_at=now - timedelta(minutes=1),
                )

                expired = QUEUE_SERVICE._expire_if_needed(
                    request_record,
                    now=now,
                )

                self.assertTrue(expired)
                self.assertEqual(
                    request_record.status,
                    QUEUE_MODELS.SignatureRequestStatus.EXPIRED,
                )
                self.assertEqual(request_record.updated_at, now)

        authenticating = SimpleNamespace(
            status=(
                QUEUE_MODELS.SignatureRequestStatus.AUTHENTICATING
            ),
            expires_at=now - timedelta(seconds=1),
            updated_at=now - timedelta(minutes=1),
        )
        original_updated_at = authenticating.updated_at

        self.assertFalse(
            QUEUE_SERVICE._expire_if_needed(
                authenticating,
                now=now,
            )
        )
        self.assertEqual(
            authenticating.status,
            QUEUE_MODELS.SignatureRequestStatus.AUTHENTICATING,
        )
        self.assertEqual(
            authenticating.updated_at,
            original_updated_at,
        )


class DeviceQueuePostgreSQLLockingTests(unittest.TestCase):
    def test_claim_uses_advisory_lock_and_skip_locked_queue_select(
        self,
    ) -> None:
        device_id = uuid.UUID(
            "dddddddd-1111-4222-8333-444444444444"
        )
        device = SimpleNamespace(id=device_id)
        pending_request = SimpleNamespace(
            status=QUEUE_MODELS.SignatureRequestStatus.PENDING,
            authentication_session_id=None,
            claimed_at=None,
            updated_at=None,
        )
        database = _RecordingDatabase(
            [
                None,
                pending_request,
            ]
        )

        result = QUEUE_SERVICE.claim_next_signature_request(
            database,
            device=device,
        )

        self.assertIs(result, pending_request)
        self.assertEqual(len(database.scalar_statements), 2)

        compiled = [
            str(
                statement.compile(
                    dialect=postgresql.dialect()
                )
            ).upper()
            for statement in database.scalar_statements
        ]
        pending_claim_sql = compiled[-1]
        advisory_lock_sql = str(
            database.execute_statements[0].compile(
                dialect=postgresql.dialect()
            )
        ).upper()

        self.assertIn(
            "PG_ADVISORY_XACT_LOCK",
            advisory_lock_sql,
        )
        self.assertIn("FOR UPDATE SKIP LOCKED", pending_claim_sql)
        self.assertIn("SIGNATURE_REQUESTS", pending_claim_sql)
        self.assertIn("DEVICE_ID", pending_claim_sql)
        pending_parameters = (
            database.scalar_statements[-1]
            .compile(dialect=postgresql.dialect())
            .params
        )
        self.assertIn(device_id, pending_parameters.values())

    def test_an_in_flight_request_is_never_delivered_again(
        self,
    ) -> None:
        device = SimpleNamespace(
            id=uuid.UUID(
                "dddddddd-1111-4222-8333-444444444444"
            )
        )
        claimed_request = SimpleNamespace(
            status=QUEUE_MODELS.SignatureRequestStatus.CLAIMED,
            authentication_session_id=None,
        )
        database = _RecordingDatabase([claimed_request])

        result = QUEUE_SERVICE.claim_next_signature_request(
            database,
            device=device,
        )

        self.assertIsNone(result)
        self.assertEqual(len(database.scalar_statements), 1)


if __name__ == "__main__":
    unittest.main()
