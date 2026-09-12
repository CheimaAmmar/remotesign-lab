import hashlib
import inspect
import json
import unittest
import uuid

from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException, status
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql
from starlette.requests import Request

from app.api.auth import complete_authentication
from app.api.signing import sign_document
from app.main import app
from app.models import (
    DeviceStatus,
    Document,
    DocumentSignature,
    SecurityAuditEvent,
    SignatureRequest,
    SignatureRequestStatus,
    User,
    UserStatus,
)
from app.security.passwords import hash_password, verify_password
from app.security import user_session as user_session_store
from app.security.user_session import (
    USER_SESSION_COOKIE_NAME,
    USER_SESSION_TTL_SECONDS,
    UserSession,
    create_user_session,
    get_user_session,
    has_viewed_document,
    mark_document_viewed,
    require_user_csrf,
    require_user_session,
)
from app.services.signature_request_service import (
    mark_signature_request_failed_by_session,
    signature_request_is_authorized_for_session,
)
from app.user_web.routes import (
    CONSENT_VERSION,
    USER_SIGNATURE_REQUEST_MESSAGES,
    UserSignatureRequestCreate,
    _request_response,
    create_user_signature_request,
    create_user_web_session,
    list_user_documents,
    router as user_web_router,
    user_interface,
    user_logout,
    view_user_document,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
USER_ASSETS = (
    PROJECT_ROOT / "app/user_web/templates/login.html",
    PROJECT_ROOT / "app/user_web/templates/index.html",
    PROJECT_ROOT / "app/user_web/static/login.js",
    PROJECT_ROOT / "app/user_web/static/app.js",
    PROJECT_ROOT / "app/user_web/static/user.css",
)


def build_request(
    *,
    path: str = "/user",
    method: str = "GET",
    scheme: str = "https",
    host: str | None = None,
    session_token: str | None = None,
    csrf_token: str | None = None,
    origin: str | None = None,
    fetch_site: str | None = None,
) -> Request:
    headers: list[tuple[bytes, bytes]] = []

    if host is not None:
        headers.append((b"host", host.encode("ascii")))

    if session_token is not None:
        headers.append(
            (
                b"cookie",
                (
                    f"{USER_SESSION_COOKIE_NAME}={session_token}"
                ).encode("ascii"),
            )
        )

    if csrf_token is not None:
        headers.append(
            (b"x-csrf-token", csrf_token.encode("ascii"))
        )

    if origin is not None:
        headers.append((b"origin", origin.encode("ascii")))

    if fetch_site is not None:
        headers.append(
            (b"sec-fetch-site", fetch_site.encode("ascii"))
        )

    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": scheme,
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 12345),
            "server": ("hsm-server.local", 443),
        }
    )


def response_json(response) -> dict:
    return json.loads(response.body.decode("utf-8"))


def make_test_user(
    *,
    password: str = "correct-test-password",
) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        username="lina",
        full_name="Lina Test",
        email="lina@example.test",
        password_hash=hash_password(password),
        status=UserStatus.ACTIVE,
    )


class LoginDatabase:
    def __init__(self, user) -> None:
        self.user = user
        self.added = []
        self.commit_count = 0

    def scalar(self, _statement):
        return self.user

    def add(self, record) -> None:
        self.added.append(record)

    def commit(self) -> None:
        self.commit_count += 1


class ScalarRows:
    def __init__(self, rows) -> None:
        self.rows = rows

    def all(self):
        return list(self.rows)


class OwnedDocumentsDatabase:
    def __init__(
        self,
        documents,
        requests=(),
        signatures=(),
        user=None,
    ) -> None:
        self.documents = documents
        self.requests = requests
        self.signatures = signatures
        self.user = user
        self.statements = []

    def get(self, model, record_id):
        if (
            model is User
            and self.user is not None
            and record_id == self.user.id
        ):
            return self.user

        return None

    def scalars(self, statement):
        self.statements.append(statement)
        entity = statement.column_descriptions[0].get("entity")
        parameters = statement.compile(
            dialect=postgresql.dialect()
        ).params
        user_ids = {
            value
            for value in parameters.values()
            if isinstance(value, uuid.UUID)
        }

        if entity is Document:
            rows = [
                document
                for document in self.documents
                if document.user_id in user_ids
            ]
        elif entity is SignatureRequest:
            rows = [
                request
                for request in self.requests
                if request.user_id in user_ids
            ]
        elif entity is DocumentSignature:
            rows = list(self.signatures)
        else:
            rows = []

        return ScalarRows(rows)


class QueueCreationDatabase:
    def __init__(self, scalar_results) -> None:
        self.scalar_results = iter(scalar_results)
        self.scalar_statements = []
        self.added = []
        self.commit_count = 0

    def scalar(self, statement):
        self.scalar_statements.append(statement)
        return next(self.scalar_results)

    def add(self, record) -> None:
        self.added.append(record)

    def flush(self) -> None:
        for record in self.added:
            if isinstance(record, SignatureRequest) and record.id is None:
                record.id = uuid.uuid4()

    def commit(self) -> None:
        self.commit_count += 1


class AuthorizationDatabase:
    def __init__(self, signature_request) -> None:
        self.signature_request = signature_request

    def scalar(self, _statement):
        return self.signature_request

    def begin_nested(self):
        return nullcontext()


class PasswordAndLoginTests(unittest.TestCase):
    def tearDown(self) -> None:
        user_session_store._sessions.clear()

    def test_password_is_scrypt_hashed_and_verified(self) -> None:
        password = "correct-test-password"
        encoded = hash_password(password)

        self.assertTrue(encoded.startswith("scrypt$"))
        self.assertNotIn(password, encoded)
        self.assertTrue(verify_password(password, encoded))
        self.assertFalse(verify_password("wrong-test-password", encoded))

    def test_correct_login_issues_separate_secure_cookie(self) -> None:
        password = "correct-test-password"
        user = make_test_user(password=password)
        database = LoginDatabase(user)
        response = create_user_web_session(
            build_request(
                path="/user/login",
                method="POST",
                fetch_site="same-origin",
            ),
            user.email.upper(),
            password,
            database,
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/user")
        cookie = SimpleCookie()
        cookie.load(response.headers["set-cookie"])
        morsel = cookie[USER_SESSION_COOKIE_NAME]

        self.assertEqual(morsel["path"], "/user")
        self.assertEqual(morsel["samesite"], "strict")
        self.assertTrue(morsel["secure"])
        self.assertTrue(morsel["httponly"])
        self.assertEqual(int(morsel["max-age"]), USER_SESSION_TTL_SECONDS)
        self.assertEqual(get_user_session(morsel.value).user_id, user.id)
        self.assertNotEqual(
            USER_SESSION_COOKIE_NAME,
            "stage_hsm_ui_session",
        )

        material = response.headers["set-cookie"] + response.body.decode()
        self.assertNotIn(password, material)
        self.assertNotIn(user.password_hash, material)

    def test_login_rotates_an_existing_user_session(self) -> None:
        password = "correct-test-password"
        user = make_test_user(password=password)
        old_token, _old_session = create_user_session(user.id)
        response = create_user_web_session(
            build_request(
                path="/user/login",
                method="POST",
                session_token=old_token,
                fetch_site="same-origin",
            ),
            user.email,
            password,
            LoginDatabase(user),
        )
        cookie = SimpleCookie()
        cookie.load(response.headers["set-cookie"])
        new_token = cookie[USER_SESSION_COOKIE_NAME].value

        self.assertNotEqual(new_token, old_token)
        self.assertIsNone(get_user_session(old_token))
        self.assertIsNotNone(get_user_session(new_token))

    def test_wrong_password_is_rejected(self) -> None:
        user = make_test_user()
        response = create_user_web_session(
            build_request(
                path="/user/login",
                method="POST",
                fetch_site="same-origin",
            ),
            user.email,
            "wrong-test-password",
            LoginDatabase(user),
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.headers["location"],
            "/user/login?error=invalid",
        )
        self.assertNotIn("set-cookie", response.headers)

    def test_cross_site_login_is_rejected(self) -> None:
        user = make_test_user()

        with self.assertRaises(HTTPException) as rejected:
            create_user_web_session(
                build_request(
                    path="/user/login",
                    method="POST",
                    origin="https://attacker.example",
                    fetch_site="cross-site",
                ),
                user.email,
                "correct-test-password",
                LoginDatabase(user),
            )

        self.assertEqual(rejected.exception.status_code, 403)

    def test_same_origin_https_with_port_is_accepted(self) -> None:
        password = "correct-test-password"
        user = make_test_user(password=password)
        response = create_user_web_session(
            build_request(
                path="/user/login",
                method="POST",
                scheme="https",
                host="172.20.10.4:8443",
                origin="https://172.20.10.4:8443",
                fetch_site="same-origin",
            ),
            user.email,
            password,
            LoginDatabase(user),
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/user")

    def test_null_origin_same_origin_fetch_site_is_accepted(self) -> None:
        password = "correct-test-password"
        user = make_test_user(password=password)
        response = create_user_web_session(
            build_request(
                path="/user/login",
                method="POST",
                scheme="https",
                host="172.20.10.4:8443",
                origin="null",
                fetch_site="same-origin",
            ),
            user.email,
            password,
            LoginDatabase(user),
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/user")

    def test_null_origin_cross_site_fetch_site_is_rejected(self) -> None:
        self._assert_login_origin_rejected(
            origin="null",
            fetch_site="cross-site",
        )

    def test_missing_origin_same_origin_fetch_site_is_accepted(self) -> None:
        password = "correct-test-password"
        user = make_test_user(password=password)
        response = create_user_web_session(
            build_request(
                path="/user/login",
                method="POST",
                scheme="https",
                host="172.20.10.4:8443",
                fetch_site="same-origin",
            ),
            user.email,
            password,
            LoginDatabase(user),
        )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/user")

    def test_different_ip_is_rejected(self) -> None:
        self._assert_login_origin_rejected(
            origin="https://192.0.2.10:8443",
        )

    def test_different_port_is_rejected(self) -> None:
        self._assert_login_origin_rejected(
            origin="https://172.20.10.4:9443",
        )

    def test_different_scheme_is_rejected(self) -> None:
        self._assert_login_origin_rejected(
            origin="http://172.20.10.4:8443",
        )

    def test_external_origin_is_rejected(self) -> None:
        self._assert_login_origin_rejected(
            origin="https://attacker.example",
        )

    def test_malformed_non_null_origin_is_rejected(self) -> None:
        self._assert_login_origin_rejected(
            origin="not-an-http-origin",
        )

    def _assert_login_origin_rejected(
        self,
        *,
        origin: str,
        fetch_site: str = "same-origin",
    ) -> None:
        user = make_test_user()

        with self.assertRaises(HTTPException) as rejected:
            create_user_web_session(
                build_request(
                    path="/user/login",
                    method="POST",
                    scheme="https",
                    host="172.20.10.4:8443",
                    origin=origin,
                    fetch_site=fetch_site,
                ),
                user.email,
                "correct-test-password",
                LoginDatabase(user),
            )

        self.assertEqual(rejected.exception.status_code, 403)

    def test_access_without_session_and_logout(self) -> None:
        redirect = user_interface(build_request())
        self.assertEqual(redirect.status_code, 303)
        self.assertEqual(redirect.headers["location"], "/user/login")

        with self.assertRaises(HTTPException) as missing:
            require_user_session(build_request())
        self.assertEqual(missing.exception.status_code, 401)

        user_id = uuid.uuid4()
        token, session = create_user_session(user_id)
        response = user_logout(
            build_request(
                method="POST",
                session_token=token,
                csrf_token=session.csrf_token,
            ),
            session,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(get_user_session(token))

    def test_expired_session_and_invalid_csrf_are_rejected(self) -> None:
        user_id = uuid.uuid4()

        with patch(
            "app.security.user_session.time.monotonic",
            return_value=100.0,
        ):
            token, session = create_user_session(user_id)

        with patch(
            "app.security.user_session.time.monotonic",
            return_value=101.0,
        ):
            self.assertNotIn(token, user_session_store._sessions)

            with self.assertRaises(HTTPException) as csrf_rejected:
                require_user_csrf(
                    build_request(
                        method="POST",
                        session_token=token,
                        csrf_token="wrong-csrf-token",
                    )
                )
        self.assertEqual(csrf_rejected.exception.status_code, 403)

        with patch(
            "app.security.user_session.time.monotonic",
            return_value=100.0 + USER_SESSION_TTL_SECONDS + 1,
        ):
            self.assertIsNone(get_user_session(token))

        self.assertNotEqual(session.csrf_token, token)


class UserDocumentIsolationTests(unittest.TestCase):
    def tearDown(self) -> None:
        user_session_store._sessions.clear()

    def test_user_a_list_does_not_return_user_b_document(self) -> None:
        user_a = uuid.uuid4()
        user_b = uuid.uuid4()
        document_a = SimpleNamespace(
            id=uuid.uuid4(),
            user_id=user_a,
            original_filename="a.pdf",
            size_bytes=10,
            document_hash="a" * 64,
            created_at=SimpleNamespace(
                isoformat=lambda: "2026-09-03T00:00:00+00:00"
            ),
        )
        document_b = SimpleNamespace(
            id=uuid.uuid4(),
            user_id=user_b,
            original_filename="b.pdf",
            size_bytes=20,
            document_hash="b" * 64,
            created_at=document_a.created_at,
        )
        database = OwnedDocumentsDatabase(
            [document_a, document_b]
        )
        session = UserSession(
            id="session-a",
            user_id=user_a,
            csrf_token="csrf-a",
            expires_at=999999999.0,
        )

        payload = response_json(
            list_user_documents(session, database)
        )

        self.assertEqual(len(payload["documents"]), 1)
        self.assertEqual(
            payload["documents"][0]["document_id"],
            str(document_a.id),
        )
        self.assertNotIn("b.pdf", json.dumps(payload))

    def test_signed_document_list_exposes_signature_metadata(self) -> None:
        user_id = uuid.uuid4()
        document_id = uuid.uuid4()
        signature_id = uuid.uuid4()
        signed_at = datetime.now(timezone.utc)
        document = SimpleNamespace(
            id=document_id,
            user_id=user_id,
            original_filename="contrat.pdf",
            size_bytes=100,
            document_hash="a" * 64,
            created_at=signed_at,
        )
        signature_request = SimpleNamespace(
            id=uuid.uuid4(),
            user_id=user_id,
            document_id=document_id,
            status=SignatureRequestStatus.SIGNED,
            signature_id=signature_id,
            completed_at=signed_at,
        )
        signature = SimpleNamespace(
            id=signature_id,
            algorithm="RSA-PKCS1-SHA256",
            signed_document_path="signed.pdf",
            signing_time=signed_at,
            pades_profile="PAdES-B-T",
            certificate_subject="CN=Stage-HSM Development Signer",
            timestamp_time=signed_at,
            tsa_certificate_subject=(
                "CN=Stage-HSM Development TSA"
            ),
        )
        database = OwnedDocumentsDatabase(
            [document],
            [signature_request],
            [signature],
            user=SimpleNamespace(
                id=user_id,
                full_name="Alice Martin",
            ),
        )
        session = UserSession(
            id="session-a",
            user_id=user_id,
            csrf_token="csrf-a",
            expires_at=999999999.0,
        )

        payload = response_json(
            list_user_documents(session, database)
        )["documents"][0]["request"]

        self.assertEqual(payload["state"], "SIGNED")
        self.assertEqual(payload["filename"], "contrat.pdf")
        self.assertEqual(payload["signed_at"], signed_at.isoformat())
        self.assertEqual(payload["signature_id"], str(signature_id))
        self.assertEqual(payload["algorithm"], "RSA-PKCS1-SHA256")
        self.assertEqual(payload["signer_name"], "Alice Martin")
        self.assertEqual(payload["pades_profile"], "PAdES-B-T")
        self.assertEqual(payload["timestamp_time"], signed_at.isoformat())
        self.assertEqual(
            payload["tsa_certificate_subject"],
            "CN=Stage-HSM Development TSA",
        )

    def test_document_view_is_scoped_and_recorded_server_side(self) -> None:
        user_a = uuid.uuid4()
        user_b = uuid.uuid4()
        session = UserSession(
            id="session-a",
            user_id=user_a,
            csrf_token="csrf-a",
            expires_at=999999999.0,
        )
        document = SimpleNamespace(
            id=uuid.uuid4(),
            user_id=user_a,
            stored_filename="owned.pdf",
            original_filename="owned.pdf",
        )

        class ViewDatabase:
            def __init__(self, visible) -> None:
                self.visible = visible

            def scalar(self, statement):
                values = statement.compile(
                    dialect=postgresql.dialect()
                ).params.values()
                return document if self.visible and user_a in values else None

        with self.assertRaises(HTTPException) as hidden:
            view_user_document(
                document.id,
                build_request(
                    path=f"/user/documents/{document.id}/view"
                ),
                UserSession(
                    id="session-b",
                    user_id=user_b,
                    csrf_token="csrf-b",
                    expires_at=999999999.0,
                ),
                ViewDatabase(False),
            )
        self.assertEqual(hidden.exception.status_code, 404)

        with TemporaryDirectory() as directory:
            path = Path(directory) / document.stored_filename
            path.write_bytes(b"%PDF-1.4\n%%EOF\n")

            with (
                patch(
                    "app.user_web.routes.DOCUMENT_STORAGE",
                    Path(directory),
                ),
                patch(
                    "app.user_web.routes.record_audit_event",
                    return_value=True,
                ) as audit,
            ):
                response = view_user_document(
                    document.id,
                    build_request(
                        path=f"/user/documents/{document.id}/view"
                    ),
                    session,
                    ViewDatabase(True),
                )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(has_viewed_document(session, document.id))
        self.assertEqual(
            audit.call_args.kwargs["event_type"],
            "DOCUMENT_VIEWED",
        )


class UserSignatureRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.user_a = uuid.uuid4()
        self.user_b = uuid.uuid4()
        self.session = UserSession(
            id="user-session-a",
            user_id=self.user_a,
            csrf_token="csrf-a",
            expires_at=999999999.0,
        )
        self.document = SimpleNamespace(
            id=uuid.uuid4(),
            user_id=self.user_a,
            document_hash="a" * 64,
        )
        self.device = SimpleNamespace(
            id=uuid.uuid4(),
            status=DeviceStatus.ACTIVE,
            device_secret="configured",
        )
        self.payload = UserSignatureRequestCreate(
            document_id=self.document.id,
            document_viewed=True,
            signature_confirmed=True,
        )

    def test_browser_cannot_choose_user_id(self) -> None:
        with self.assertRaises(ValidationError):
            UserSignatureRequestCreate(
                document_id=self.document.id,
                document_viewed=True,
                signature_confirmed=True,
                user_id=self.user_b,
            )

    def test_request_requires_server_side_document_view(self) -> None:
        database = QueueCreationDatabase([self.document])

        with self.assertRaises(HTTPException) as rejected:
            create_user_signature_request(
                self.payload,
                build_request(method="POST"),
                self.session,
                database,
            )

        self.assertEqual(rejected.exception.status_code, 409)
        self.assertEqual(database.added, [])

    def test_user_a_cannot_create_request_for_user_b_document(self) -> None:
        database = QueueCreationDatabase([None])

        with self.assertRaises(HTTPException) as rejected:
            create_user_signature_request(
                self.payload,
                build_request(method="POST"),
                self.session,
                database,
            )

        self.assertEqual(rejected.exception.status_code, 404)
        self.assertEqual(database.added, [])

    def test_request_uses_session_user_and_records_consent(self) -> None:
        mark_document_viewed(self.session, self.document.id)
        database = QueueCreationDatabase(
            [self.document, None, self.device]
        )
        response = create_user_signature_request(
            self.payload,
            build_request(method="POST"),
            self.session,
            database,
        )
        signature_request = next(
            record
            for record in database.added
            if isinstance(record, SignatureRequest)
        )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response_json(response)["state"], "PENDING")
        self.assertEqual(
            signature_request.status,
            SignatureRequestStatus.PENDING,
        )
        self.assertIsNone(
            signature_request.authentication_session_id
        )
        self.assertEqual(signature_request.user_id, self.user_a)
        self.assertEqual(signature_request.document_id, self.document.id)
        self.assertEqual(
            signature_request.document_hash,
            self.document.document_hash,
        )
        self.assertIsNotNone(signature_request.consented_at)
        self.assertEqual(
            signature_request.consent_version,
            CONSENT_VERSION,
        )
        audit_event_types = {
            record.event_type
            for record in database.added
            if isinstance(record, SecurityAuditEvent)
        }
        self.assertEqual(
            audit_event_types,
            {
                "CONSENT_RECORDED",
                "SIGNATURE_REQUEST_CREATED",
            },
        )
        self.assertEqual(database.commit_count, 1)
        document_lookup = str(
            database.scalar_statements[0].compile(
                dialect=postgresql.dialect()
            )
        ).upper()
        self.assertIn("FOR UPDATE", document_lookup)

    def test_active_request_cannot_be_duplicated(self) -> None:
        mark_document_viewed(self.session, self.document.id)

        for active_status in (
            SignatureRequestStatus.PENDING,
            SignatureRequestStatus.CLAIMED,
            SignatureRequestStatus.AUTHENTICATING,
            SignatureRequestStatus.AUTHENTICATED,
        ):
            with self.subTest(active_status=active_status.value):
                existing_request = SimpleNamespace(
                    id=uuid.uuid4(),
                    status=active_status,
                )
                database = QueueCreationDatabase(
                    [self.document, existing_request]
                )

                with self.assertRaises(HTTPException) as rejected:
                    create_user_signature_request(
                        self.payload,
                        build_request(method="POST"),
                        self.session,
                        database,
                    )

                self.assertEqual(rejected.exception.status_code, 409)
                self.assertEqual(database.added, [])


class StrongAuthenticationOwnershipTests(unittest.TestCase):
    def _authorization_records(self):
        now = datetime.now(timezone.utc)
        request_user = uuid.uuid4()
        authentication_session = SimpleNamespace(
            id=uuid.uuid4(),
            user_id=request_user,
            device_id=uuid.uuid4(),
            document_id=uuid.uuid4(),
            document_hash="a" * 64,
            decision="APPROVE",
        )
        signature_request = SimpleNamespace(
            authentication_session_id=authentication_session.id,
            user_id=request_user,
            device_id=authentication_session.device_id,
            document_id=authentication_session.document_id,
            document_hash=authentication_session.document_hash,
            decision=authentication_session.decision,
            status=SignatureRequestStatus.AUTHENTICATING,
            consented_at=now,
            consent_version=CONSENT_VERSION,
            expires_at=now + timedelta(minutes=5),
            failure_detail=None,
            completed_at=None,
            updated_at=now,
        )
        return authentication_session, signature_request

    def test_wrong_rfid_fingerprint_user_is_failed(self) -> None:
        authentication_session, signature_request = (
            self._authorization_records()
        )
        authentication_session.user_id = uuid.uuid4()
        database = AuthorizationDatabase(signature_request)

        self.assertFalse(
            signature_request_is_authorized_for_session(
                database,
                authentication_session=authentication_session,
                expected_status=SignatureRequestStatus.AUTHENTICATING,
            )
        )
        mark_signature_request_failed_by_session(
            database,
            authentication_session_id=authentication_session.id,
            failure_detail="Authenticated user mismatch",
        )
        self.assertEqual(
            signature_request.status,
            SignatureRequestStatus.FAILED,
        )

    def test_matching_rfid_fingerprint_user_is_allowed_by_policy(self) -> None:
        authentication_session, signature_request = (
            self._authorization_records()
        )

        self.assertTrue(
            signature_request_is_authorized_for_session(
                AuthorizationDatabase(signature_request),
                authentication_session=authentication_session,
                expected_status=SignatureRequestStatus.AUTHENTICATING,
            )
        )

    def test_missing_web_consent_is_rejected(self) -> None:
        authentication_session, signature_request = (
            self._authorization_records()
        )

        for missing_field in ("consented_at", "consent_version"):
            with self.subTest(missing_field=missing_field):
                original = getattr(signature_request, missing_field)
                setattr(signature_request, missing_field, None)
                self.assertFalse(
                    signature_request_is_authorized_for_session(
                        AuthorizationDatabase(signature_request),
                        authentication_session=authentication_session,
                        expected_status=(
                            SignatureRequestStatus.AUTHENTICATING
                        ),
                    )
                )
                setattr(signature_request, missing_field, original)

    def test_missing_request_user_is_rejected(self) -> None:
        authentication_session, signature_request = (
            self._authorization_records()
        )
        signature_request.user_id = None

        self.assertFalse(
            signature_request_is_authorized_for_session(
                AuthorizationDatabase(signature_request),
                authentication_session=authentication_session,
                expected_status=SignatureRequestStatus.AUTHENTICATING,
            )
        )

    def test_expired_request_is_rejected(self) -> None:
        authentication_session, signature_request = (
            self._authorization_records()
        )
        signature_request.expires_at = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        )

        self.assertFalse(
            signature_request_is_authorized_for_session(
                AuthorizationDatabase(signature_request),
                authentication_session=authentication_session,
                expected_status=SignatureRequestStatus.AUTHENTICATING,
            )
        )

    def test_document_and_hash_mismatch_are_rejected(self) -> None:
        authentication_session, signature_request = (
            self._authorization_records()
        )

        for field, invalid_value in (
            ("document_id", uuid.uuid4()),
            ("document_hash", "b" * 64),
        ):
            with self.subTest(field=field):
                original = getattr(authentication_session, field)
                setattr(authentication_session, field, invalid_value)
                self.assertFalse(
                    signature_request_is_authorized_for_session(
                        AuthorizationDatabase(signature_request),
                        authentication_session=authentication_session,
                        expected_status=(
                            SignatureRequestStatus.AUTHENTICATING
                        ),
                    )
                )
                setattr(authentication_session, field, original)

    def test_complete_and_sign_apply_the_ownership_policy(self) -> None:
        self.assertIn(
            "signature_request_is_authorized_for_session",
            inspect.getsource(complete_authentication),
        )
        self.assertIn(
            "signature_request_is_authorized_for_session",
            inspect.getsource(sign_document),
        )


class UserSignatureStatePresentationTests(unittest.TestCase):
    def test_user_interface_preserves_consent_then_device_order(
        self,
    ) -> None:
        source = (
            PROJECT_ROOT / "app/user_web/static/app.js"
        ).read_text(encoding="utf-8")
        open_consent = source.split(
            "function openConsent(documentData)",
            maxsplit=1,
        )[1].split("function closeConsent", maxsplit=1)[0]

        self.assertNotIn("apiFetch", open_consent)
        self.assertNotIn("/api/v1/auth", open_consent)
        request_signature = source.split(
            "async function requestSignature(event)",
            maxsplit=1,
        )[1].split("async function logout", maxsplit=1)[0]
        self.assertIn(
            'apiFetch("/user/api/signature-requests"',
            request_signature,
        )
        self.assertNotIn("/api/v1/auth", request_signature)
        self.assertNotIn("/api/v1/sign", request_signature)
        self.assertIn('sign.textContent = "Signer ce document"', source)
        self.assertIn(
            'elements.requestState.textContent = "Authentification forte requise"',
            source,
        )
        self.assertIn(
            "Votre demande de signature a été enregistrée.",
            source,
        )
        self.assertIn(
            "Authentifiez-vous maintenant sur votre terminal ESP32.",
            source,
        )

    def test_active_states_do_not_require_a_second_click(self) -> None:
        source = (
            PROJECT_ROOT / "app/user_web/static/app.js"
        ).read_text(encoding="utf-8")

        for active_state in (
            "PENDING",
            "CLAIMED",
            "AUTHENTICATING",
            "AUTHENTICATED",
        ):
            self.assertIn(f'"{active_state}"', source)

        self.assertIn(
            "else if (!(item.request && ACTIVE_STATES.has(item.request.state)))",
            source,
        )
        self.assertIn("elements.consentForm.hidden = true", source)
        self.assertIn("elements.consentForm.reset()", source)
        self.assertIn("elements.documentViewed.checked = false", source)
        self.assertIn("schedulePoll(requestId)", source)
        self.assertEqual(
            source.count('title: "Document signé avec succès"'),
            1,
        )

    def test_pending_prompts_for_terminal_authentication(self) -> None:
        source = (
            PROJECT_ROOT / "app/user_web/static/app.js"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'title: "En attente de votre authentification forte"',
            source,
        )
        self.assertIn(
            'message: "Authentifiez-vous sur le terminal ESP32."',
            source,
        )

    def test_only_signed_uses_the_success_message(self) -> None:
        success_message = "Document signé avec succès."

        for request_status, message in (
            USER_SIGNATURE_REQUEST_MESSAGES.items()
        ):
            with self.subTest(request_status=request_status.value):
                if request_status == SignatureRequestStatus.SIGNED:
                    self.assertEqual(message, success_message)
                else:
                    self.assertNotEqual(message, success_message)

        self.assertEqual(
            USER_SIGNATURE_REQUEST_MESSAGES[
                SignatureRequestStatus.PENDING
            ],
            "Authentifiez-vous sur le terminal ESP32.",
        )
        self.assertEqual(
            USER_SIGNATURE_REQUEST_MESSAGES[
                SignatureRequestStatus.AUTHENTICATED
            ],
            "Signature cryptographique en cours.",
        )

    def test_signed_response_contains_available_signature_metadata(
        self,
    ) -> None:
        signed_at = datetime.now(timezone.utc)
        signature_id = uuid.uuid4()
        response = _request_response(
            SimpleNamespace(
                id=uuid.uuid4(),
                document_id=uuid.uuid4(),
                status=SignatureRequestStatus.SIGNED,
                signature_id=signature_id,
                completed_at=signed_at,
            ),
            document=SimpleNamespace(original_filename="contrat.pdf"),
            signature=SimpleNamespace(algorithm="RSA-PKCS1-SHA256"),
        )

        self.assertEqual(response["state"], "SIGNED")
        self.assertEqual(
            response["message"],
            "Document signé avec succès.",
        )
        self.assertEqual(response["filename"], "contrat.pdf")
        self.assertEqual(response["signed_at"], signed_at.isoformat())
        self.assertEqual(response["signature_id"], str(signature_id))
        self.assertEqual(response["algorithm"], "RSA-PKCS1-SHA256")


class UserWebSecurityContractTests(unittest.TestCase):
    def test_user_mutations_require_user_csrf(self) -> None:
        protected_routes = {
            ("/user/logout", "POST"),
            ("/user/api/signature-requests", "POST"),
        }

        for path, method in protected_routes:
            route = next(
                candidate
                for candidate in user_web_router.routes
                if candidate.path == path and method in candidate.methods
            )
            dependencies = {
                dependency.call.__name__
                for dependency in route.dependant.dependencies
            }
            self.assertIn("require_user_csrf", dependencies)

    def test_user_pages_are_not_admin_or_device_openapi_routes(self) -> None:
        schema = app.openapi()
        self.assertNotIn("/user", schema["paths"])

        user_read_fields = schema["components"]["schemas"][
            "UserRead"
        ]["properties"]
        self.assertNotIn("password", user_read_fields)
        self.assertNotIn("password_hash", user_read_fields)

        admin_security = schema["paths"][
            "/api/v1/documents/upload"
        ]["post"].get("security")
        self.assertIn({"AdminApiKey": []}, admin_security)

        for path in (
            "/api/v1/auth/challenge",
            "/api/v1/auth/complete",
            "/api/v1/sign",
        ):
            self.assertIsNone(schema["paths"][path]["post"].get("security"))

    def test_browser_assets_contain_no_server_secret_names(self) -> None:
        forbidden = (
            "ADMIN_API_KEY",
            "DEVICE_SECRET",
            "SOFTHSM_USER_PIN",
            "X-Admin-Key",
        )

        for asset in USER_ASSETS:
            content = asset.read_text(encoding="utf-8")
            for marker in forbidden:
                with self.subTest(asset=asset.name, marker=marker):
                    self.assertNotIn(marker, content)


if __name__ == "__main__":
    unittest.main()
