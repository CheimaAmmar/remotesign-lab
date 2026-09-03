import hashlib
import hmac
import json
import unittest
import uuid

from http.cookies import SimpleCookie
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from dotenv import dotenv_values
from fastapi import HTTPException, UploadFile, status
from starlette.datastructures import Headers
from starlette.requests import Request

from app.config import get_settings
from app.main import app
from app.models import DeviceStatus, SignatureRequestStatus
from app.security import ui_session as ui_session_store
from app.security.ui_session import (
    UI_SESSION_COOKIE_NAME,
    UI_SESSION_TTL_SECONDS,
    create_ui_session,
    delete_ui_session,
    get_ui_session,
    require_ui_csrf,
)
from app.services.document_service import store_document
from app.web.routes import (
    SignatureRequestCreate,
    create_web_session,
    login_page,
    request_signature_from_web,
    router as web_router,
    signature_request_status,
    web_interface,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_ASSETS = (
    PROJECT_ROOT / "app/web/templates/login.html",
    PROJECT_ROOT / "app/web/templates/index.html",
    PROJECT_ROOT / "app/web/static/styles.css",
    PROJECT_ROOT / "app/web/static/login.js",
    PROJECT_ROOT / "app/web/static/app.js",
)


def build_request(
    *,
    path: str = "/ui",
    session_token: str | None = None,
    csrf_token: str | None = None,
) -> Request:
    headers: list[tuple[bytes, bytes]] = []

    if session_token is not None:
        cookie = (
            f"{UI_SESSION_COOKIE_NAME}={session_token}"
        )
        headers.append(
            (b"cookie", cookie.encode("ascii"))
        )

    if csrf_token is not None:
        headers.append(
            (
                b"x-csrf-token",
                csrf_token.encode("latin-1"),
            )
        )

    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
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


class FakeDocumentDatabase:
    def __init__(self) -> None:
        self.added = None
        self.commit_count = 0
        self.refresh_count = 0

    def add(self, record) -> None:
        self.added = record

    def commit(self) -> None:
        self.commit_count += 1

    def refresh(self, _record) -> None:
        self.refresh_count += 1


class FakeStatusDatabase:
    def __init__(self) -> None:
        self.commit_count = 0

    def commit(self) -> None:
        self.commit_count += 1


class FakeQueueCreationDatabase:
    def __init__(self, document, device) -> None:
        self.document = document
        self.device = device
        self.added = []
        self.flush_count = 0
        self.commit_count = 0

    def get(self, _model, record_id):
        if record_id == self.document.id:
            return self.document

        return None

    def scalar(self, _statement):
        return self.device

    def add(self, record) -> None:
        self.added.append(record)

    def flush(self) -> None:
        self.flush_count += 1

    def commit(self) -> None:
        self.commit_count += 1


class WebSessionSecurityTests(unittest.TestCase):
    def tearDown(self) -> None:
        ui_session_store._sessions.clear()

    def test_only_the_session_token_hash_is_stored(self) -> None:
        token, session = create_ui_session()
        digest = hashlib.sha256(
            token.encode("utf-8")
        ).hexdigest()

        if token in ui_session_store._sessions:
            self.fail("Raw Web session token was stored")

        self.assertIn(
            digest,
            ui_session_store._sessions,
        )
        self.assertEqual(
            get_ui_session(token),
            session,
        )
        self.assertIsNone(
            get_ui_session(token + "invalid")
        )

        delete_ui_session(token)
        self.assertIsNone(get_ui_session(token))

    def test_expired_session_is_rejected(self) -> None:
        with patch(
            "app.security.ui_session.time.monotonic",
            return_value=100.0,
        ):
            token, _session = create_ui_session()

        with patch(
            "app.security.ui_session.time.monotonic",
            return_value=(
                100.0
                + UI_SESSION_TTL_SECONDS
                + 1
            ),
        ):
            self.assertIsNone(get_ui_session(token))

    def test_csrf_is_required_and_compared_exactly(self) -> None:
        token, session = create_ui_session()

        with self.assertRaises(HTTPException) as missing:
            require_ui_csrf(
                build_request(session_token=token)
            )

        self.assertEqual(
            missing.exception.status_code,
            status.HTTP_403_FORBIDDEN,
        )

        with self.assertRaises(HTTPException) as wrong:
            require_ui_csrf(
                build_request(
                    session_token=token,
                    csrf_token="wrong-token",
                )
            )

        self.assertEqual(
            wrong.exception.status_code,
            status.HTTP_403_FORBIDDEN,
        )

        with self.assertRaises(HTTPException) as unicode_value:
            require_ui_csrf(
                build_request(
                    session_token=token,
                    csrf_token="é",
                )
            )

        self.assertEqual(
            unicode_value.exception.status_code,
            status.HTTP_403_FORBIDDEN,
        )
        self.assertEqual(
            require_ui_csrf(
                build_request(
                    session_token=token,
                    csrf_token=session.csrf_token,
                )
            ),
            session,
        )

    def test_login_issues_an_opaque_secure_cookie(self) -> None:
        expected_key = (
            get_settings()
            .admin_api_key
            .get_secret_value()
        )
        response = create_web_session(
            build_request(path="/ui/login"),
            expected_key,
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_303_SEE_OTHER,
        )
        self.assertEqual(
            response.headers["location"],
            "/ui",
        )

        set_cookie = response.headers["set-cookie"]
        cookie = SimpleCookie()
        cookie.load(set_cookie)
        morsel = cookie[UI_SESSION_COOKIE_NAME]

        self.assertEqual(morsel["path"], "/ui")
        self.assertEqual(morsel["samesite"], "strict")
        self.assertTrue(morsel["secure"])
        self.assertTrue(morsel["httponly"])
        self.assertEqual(
            int(morsel["max-age"]),
            UI_SESSION_TTL_SECONDS,
        )
        self.assertIsNotNone(
            get_ui_session(morsel.value)
        )

        response_material = (
            set_cookie
            + response.headers["location"]
            + response.body.decode("utf-8")
        )

        if (
            expected_key
            and expected_key in response_material
        ):
            self.fail(
                "Administrator key was returned to the browser"
            )

    def test_bad_or_unicode_login_is_rejected_without_500(self) -> None:
        expected_key = (
            get_settings()
            .admin_api_key
            .get_secret_value()
        )
        wrong_key = "invalid-web-admin-key"

        if hmac.compare_digest(
            wrong_key.encode("utf-8"),
            expected_key.encode("utf-8"),
        ):
            wrong_key += "-different"

        for supplied_key in (wrong_key, "é"):
            response = create_web_session(
                build_request(path="/ui/login"),
                supplied_key,
            )

            self.assertEqual(
                response.status_code,
                status.HTTP_303_SEE_OTHER,
            )
            self.assertEqual(
                response.headers["location"],
                "/ui/login?error=1",
            )
            self.assertNotIn(
                "set-cookie",
                response.headers,
            )

    def test_pages_require_a_valid_web_session(self) -> None:
        login_response = login_page(
            build_request(path="/ui/login")
        )
        self.assertEqual(
            login_response.status_code,
            status.HTTP_200_OK,
        )

        redirect = web_interface(
            build_request(path="/ui")
        )
        self.assertEqual(
            redirect.status_code,
            status.HTTP_303_SEE_OTHER,
        )
        self.assertEqual(
            redirect.headers["location"],
            "/ui/login",
        )

        token, _session = create_ui_session()
        page = web_interface(
            build_request(
                path="/ui",
                session_token=token,
            )
        )
        self.assertEqual(
            page.status_code,
            status.HTTP_200_OK,
        )


class WebAssetTests(unittest.TestCase):
    def test_assets_contain_the_requested_workflow(self) -> None:
        index = WEB_ASSETS[1].read_text(
            encoding="utf-8"
        )
        javascript = WEB_ASSETS[4].read_text(
            encoding="utf-8"
        )

        for label in (
            "Document sélectionné",
            "Upload en cours",
            "Document prêt",
            "Attente d’authentification",
            "Authentification réussie",
            "Signature réussie",
            "Signature refusée",
            "Demander la signature",
        ):
            self.assertIn(label, index + javascript)

        for field in (
            "document-filename",
            "document-size",
            "document-id",
            "document-hash",
            "queue-state",
        ):
            self.assertIn(field, index)

        for queue_state in SignatureRequestStatus:
            self.assertIn(queue_state.value, javascript)

    def test_no_configured_secret_is_in_browser_assets(self) -> None:
        browser_content = "\n".join(
            path.read_text(encoding="utf-8")
            for path in WEB_ASSETS
        )
        settings = get_settings()
        configured_values = [
            settings.admin_api_key.get_secret_value(),
            settings.softhsm_user_pin.get_secret_value(),
            settings.database_url,
        ]
        dotenv = dotenv_values(PROJECT_ROOT / ".env")

        for name, value in dotenv.items():
            normalized_name = name.upper()

            if (
                isinstance(value, str)
                and value
                and any(
                    marker in normalized_name
                    for marker in (
                        "SECRET",
                        "PASSWORD",
                        "PRIVATE_KEY",
                    )
                )
            ):
                configured_values.append(value)

        for configured_value in configured_values:
            if (
                configured_value
                and configured_value
                in browser_content
            ):
                self.fail(
                    "A configured secret is present in a browser asset"
                )

    def test_javascript_never_uses_server_credentials(self) -> None:
        javascript = "\n".join(
            path.read_text(encoding="utf-8")
            for path in WEB_ASSETS
            if path.suffix == ".js"
        )

        for forbidden in (
            "X-Admin-Key",
            "ADMIN_API_KEY",
            "DEVICE_SECRET",
            "SOFTHSM_USER_PIN",
            "document.cookie",
            "localStorage",
            "sessionStorage",
            "/api/v1/auth/",
            "/api/v1/sign",
        ):
            self.assertNotIn(forbidden, javascript)

        self.assertIn(
            "/ui/api/documents/upload",
            javascript,
        )


class DocumentServiceTests(unittest.TestCase):
    def test_pdf_is_stored_and_hashed_without_a_real_database(self) -> None:
        pdf = b"%PDF-1.7\nprototype Stage-HSM\n%%EOF\n"
        database = FakeDocumentDatabase()
        upload = UploadFile(
            file=BytesIO(pdf),
            filename="prototype.pdf",
            headers=Headers(
                {"content-type": "application/pdf"}
            ),
        )

        with TemporaryDirectory() as directory:
            storage = Path(directory)

            with patch(
                "app.services.document_service.DOCUMENT_STORAGE",
                storage,
            ):
                result = store_document(
                    file=upload,
                    database=database,
                )

            stored_files = list(storage.glob("*.pdf"))
            self.assertEqual(len(stored_files), 1)
            self.assertEqual(
                stored_files[0].read_bytes(),
                pdf,
            )

        self.assertEqual(
            result["filename"],
            "prototype.pdf",
        )
        self.assertEqual(result["size_bytes"], len(pdf))
        self.assertEqual(
            result["document_hash"],
            hashlib.sha256(pdf).hexdigest(),
        )
        self.assertEqual(database.commit_count, 1)
        self.assertEqual(database.refresh_count, 1)
        self.assertIsNotNone(database.added)


class SignatureRequestTests(unittest.TestCase):
    def test_status_returns_each_persistent_queue_state(self) -> None:
        ui_token, ui_session = create_ui_session()
        self.addCleanup(delete_ui_session, ui_token)
        request_id = uuid.uuid4()
        document_id = uuid.uuid4()
        signature_id = uuid.uuid4()

        for queue_state in SignatureRequestStatus:
            database = FakeStatusDatabase()
            request_record = SimpleNamespace(
                id=request_id,
                document_id=document_id,
                status=queue_state,
                signature_id=(
                    signature_id
                    if queue_state
                    == SignatureRequestStatus.SIGNED
                    else None
                ),
            )

            with patch(
                "app.web.routes.get_owned_signature_request",
                return_value=request_record,
            ):
                response = signature_request_status(
                    request_id,
                    ui_session,
                    database,
                )

            payload = response_json(response)
            self.assertEqual(payload["state"], queue_state.value)
            self.assertEqual(database.commit_count, 1)

            if queue_state == SignatureRequestStatus.SIGNED:
                self.assertEqual(
                    payload["signature_id"],
                    str(signature_id),
                )
            else:
                self.assertNotIn("signature_id", payload)

    def test_status_is_scoped_to_the_web_session(self) -> None:
        request_id = uuid.uuid4()
        database = FakeStatusDatabase()
        ui_session = SimpleNamespace(id="another-session")

        with patch(
            "app.web.routes.get_owned_signature_request",
            return_value=None,
        ) as lookup:
            with self.assertRaises(HTTPException) as rejected:
                signature_request_status(
                    request_id,
                    ui_session,
                    database,
                )

        self.assertEqual(
            rejected.exception.status_code,
            status.HTTP_404_NOT_FOUND,
        )
        lookup.assert_called_once_with(
            database,
            request_id=request_id,
            owner_session_id=ui_session.id,
        )

    def test_web_creation_targets_the_configured_device(self) -> None:
        document = SimpleNamespace(
            id=uuid.uuid4(),
            document_hash="a" * 64,
        )
        device = SimpleNamespace(
            id=uuid.uuid4(),
            status=DeviceStatus.ACTIVE,
            device_secret="present",
        )
        database = FakeQueueCreationDatabase(
            document,
            device,
        )
        request_record = SimpleNamespace(
            id=uuid.uuid4(),
            status=SignatureRequestStatus.PENDING,
        )
        ui_session = SimpleNamespace(id="web-session-owner")

        with patch(
            "app.web.routes.create_signature_request",
            return_value=request_record,
        ) as create_request:
            response = request_signature_from_web(
                SignatureRequestCreate(
                    document_id=document.id,
                    document_hash=document.document_hash,
                ),
                ui_session,
                database,
            )

        payload = response_json(response)
        self.assertEqual(payload["state"], "PENDING")
        self.assertEqual(database.flush_count, 1)
        self.assertEqual(database.commit_count, 1)
        create_request.assert_called_once_with(
            database,
            owner_session_id=ui_session.id,
            device=device,
            document=document,
        )


class OpenApiIsolationTests(unittest.TestCase):
    def test_web_mutations_require_session_csrf(self) -> None:
        protected_routes = {
            ("/ui/logout", "POST"),
            ("/ui/api/documents/upload", "POST"),
            ("/ui/api/signature-requests", "POST"),
        }

        for path, method in protected_routes:
            route = next(
                candidate
                for candidate in web_router.routes
                if candidate.path == path
                and method in candidate.methods
            )
            dependency_names = {
                dependency.call.__name__
                for dependency
                in route.dependant.dependencies
            }
            self.assertIn(
                "require_ui_csrf",
                dependency_names,
            )

    def test_admin_and_esp32_security_are_separate(self) -> None:
        schema = app.openapi()
        admin_security = schema["paths"][
            "/api/v1/documents/upload"
        ]["post"].get("security")

        self.assertIn(
            {"AdminApiKey": []},
            admin_security,
        )

        for path in (
            "/api/v1/auth/challenge",
            "/api/v1/auth/complete",
            "/api/v1/sign",
        ):
            self.assertIsNone(
                schema["paths"][path]["post"].get(
                    "security"
                )
            )

        self.assertIn(
            "AdminApiKey",
            schema["components"][
                "securitySchemes"
            ],
        )

    def test_web_routes_are_hidden_and_docs_stay_enabled(self) -> None:
        schema = app.openapi()
        self.assertFalse(
            any(
                path.startswith("/ui")
                for path in schema["paths"]
            )
        )
        self.assertTrue(
            any(
                getattr(route, "path", None)
                == "/docs"
                for route in app.routes
            )
        )


if __name__ == "__main__":
    unittest.main()
