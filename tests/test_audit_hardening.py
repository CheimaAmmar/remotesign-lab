import csv
import importlib.util
import inspect
import json
import threading
import unittest
import uuid

from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import HTTPException
from sqlalchemy import create_engine, event as sqlalchemy_event, select
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.api.signing import reject_sign, sign_document
from app.config import get_settings
from app.main import app
from app.models import (
    SecurityAuditEvent,
    SignatureRequestStatus,
    UserStatus,
)
from app.security.passwords import hash_password
from app.security.ui_session import require_ui_session
from app.services.audit_service import (
    AUDIT_CHAIN_GENESIS_HASH,
    AUDIT_CHAIN_LOCK_KEY,
    add_audit_event,
    calculate_audit_event_hash,
    canonical_audit_event,
    record_audit_event,
    sanitize_audit_details,
    serialize_audit_event,
    verify_audit_chain,
    write_audit_event,
)
from app.services.signature_request_service import _expire_if_needed
from app.user_web.routes import create_user_web_session
from app.web.audit_routes import (
    _csv_safe,
    audit_event_details,
    audit_integrity,
    export_audit_csv,
    list_audit_events,
    router as audit_web_router,
)
from app.web.routes import create_web_session


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = (
    PROJECT_ROOT
    / "alembic/versions/a84f2c1d9e70_harden_security_audit_events.py"
)


def build_request(
    path: str,
    *,
    method: str = "GET",
    user_agent: str = "Stage-HSM audit test",
) -> Request:
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "https",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": [
                (b"host", b"stage-hsm.test"),
                (b"user-agent", user_agent.encode("ascii")),
                (b"sec-fetch-site", b"same-origin"),
            ],
            "client": ("127.0.0.1", 42000),
            "server": ("stage-hsm.test", 443),
        }
    )


def audit_engine(path: Path):
    engine = create_engine(
        f"sqlite+pysqlite:///{path}",
        connect_args={"check_same_thread": False},
    )

    @sqlalchemy_event.listens_for(engine, "connect")
    def add_character_length(connection, _record):
        connection.create_function(
            "char_length",
            1,
            lambda value: len(value) if value is not None else None,
        )

    with engine.begin() as connection:
        for table in (
            "users",
            "devices",
            "authentication_sessions",
            "documents",
            "signature_requests",
            "document_signatures",
        ):
            connection.exec_driver_sql(
                f"CREATE TABLE {table} (id UUID PRIMARY KEY)"
            )

        SecurityAuditEvent.__table__.create(connection)

    return engine


def audit_list_response(database: Session, **overrides):
    arguments = {
        "from_time": None,
        "to_time": None,
        "category": None,
        "event_type": None,
        "actor_type": None,
        "user_id": None,
        "device_id": None,
        "document_id": None,
        "signature_request_id": None,
        "signature_id": None,
        "outcome": None,
        "failure_code": None,
        "correlation_id": None,
        "limit": 50,
        "offset": 0,
        "database": database,
    }
    arguments.update(overrides)
    return list_audit_events(**arguments)


class FakeAuditDatabase:
    def __init__(self, scalar_value=None) -> None:
        self.scalar_value = scalar_value
        self.added = []
        self.commits = 0

    def scalar(self, _statement):
        return self.scalar_value

    def add(self, value) -> None:
        self.added.append(value)

    def commit(self) -> None:
        self.commits += 1


class AuditSanitizationTests(unittest.TestCase):
    def test_nested_sensitive_keys_are_removed(self) -> None:
        sanitized = sanitize_audit_details(
            {
                "operation": "sign",
                "password": "must-not-survive",
                "password_hash": "must-not-survive",
                "HMAC": "must-not-survive",
                "hmac_secret": "must-not-survive",
                "hmac_signature": "must-not-survive",
                "ADMIN_API_KEY": "must-not-survive",
                "SoftHSM PIN": "must-not-survive",
                "cookie": "must-not-survive",
                "session_token": "must-not-survive",
                "CSRF": "must-not-survive",
                "private_key": "must-not-survive",
                "TSA_PRIVATE_KEY": "must-not-survive",
                "CA_PRIVATE_KEY": "must-not-survive",
                "nested": {
                    "DEVICE_SECRET": "must-not-survive",
                    "Authorization": "must-not-survive",
                    "safe": "retained",
                },
                "items": [
                    {"csrf_token": "must-not-survive", "id": 7},
                    {
                        "message": (
                            "password=must-not-survive "
                            "HMAC=must-not-survive"
                        )
                    },
                ],
            }
        )

        material = json.dumps(sanitized)
        self.assertNotIn("must-not-survive", material)
        self.assertEqual(sanitized["operation"], "sign")
        self.assertEqual(sanitized["nested"]["safe"], "retained")
        self.assertEqual(sanitized["items"][0], {"id": 7})
        self.assertIn("[REDACTED]", sanitized["items"][1]["message"])

    def test_legacy_detail_masks_assignments_and_bearer_tokens(self) -> None:
        event = SecurityAuditEvent(
            id=uuid.uuid4(),
            event_type="TEST",
            outcome="SUCCESS",
            detail="password=hidden Authorization: Bearer hidden-token",
            created_at=datetime.now(timezone.utc),
        )

        serialized = serialize_audit_event(event)

        self.assertNotIn("hidden-token", serialized["detail"])
        self.assertNotIn("password=hidden", serialized["detail"])

    def test_free_text_context_is_sanitized_on_write_and_read(self) -> None:
        event = add_audit_event(
            FakeAuditDatabase(),
            event_type="TEST",
            outcome="SUCCESS",
            actor_id="HMAC=must-not-survive",
            user_agent="Authorization: Bearer must-not-survive",
            details={"message": "session=must-not-survive"},
        )

        serialized = serialize_audit_event(event)
        material = json.dumps(serialized)

        self.assertNotIn("must-not-survive", material)
        self.assertIn("[REDACTED]", material)

    def test_csv_formula_prefixes_are_neutralized(self) -> None:
        for value in (
            "=SUM(1,1)",
            "+cmd",
            "-CMD",
            "*formula",
            "@name",
        ):
            self.assertTrue(_csv_safe(value).startswith("'"))

        self.assertEqual(_csv_safe("normal"), "normal")

    def test_http_context_uses_socket_ip_not_forwarded_header(self) -> None:
        request = build_request("/user/login", method="POST")
        request.scope["headers"].append(
            (b"x-forwarded-for", b"203.0.113.99")
        )
        event = add_audit_event(
            FakeAuditDatabase(),
            event_type="USER_LOGIN_SUCCESS",
            outcome="SUCCESS",
            actor_type="USER",
            request=request,
            http_status=303,
        )

        self.assertEqual(event.source_ip, "127.0.0.1")
        self.assertEqual(event.user_agent, "Stage-HSM audit test")
        self.assertEqual(event.http_method, "POST")
        self.assertEqual(event.http_path, "/user/login")


class AuditHashChainTests(unittest.TestCase):
    def test_canonical_json_is_stable_and_hash_covers_fields(self) -> None:
        event = SecurityAuditEvent(
            id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            category="AUTH",
            event_type="USER_LOGIN_SUCCESS",
            actor_type="USER",
            actor_id="00000000-0000-0000-0000-000000000002",
            outcome="SUCCESS",
            details={"z": 2, "a": 1},
            created_at=datetime(
                2026,
                9,
                11,
                10,
                30,
                tzinfo=timezone.utc,
            ),
            previous_hash=AUDIT_CHAIN_GENESIS_HASH,
        )
        canonical = canonical_audit_event(event).decode("utf-8")

        self.assertFalse(canonical.endswith("\n"))
        self.assertNotIn(": ", canonical)
        self.assertIn('"details":{"a":1,"z":2}', canonical)
        first_hash = calculate_audit_event_hash(event)
        event.outcome = "FAILURE"
        self.assertNotEqual(
            first_hash,
            calculate_audit_event_hash(event),
        )

    def test_valid_chain_and_direct_tampering_detection(self) -> None:
        with TemporaryDirectory() as directory:
            engine = audit_engine(Path(directory) / "audit.db")

            with Session(engine) as database:
                events = [
                    add_audit_event(
                        database,
                        event_type=f"TEST_EVENT_{index}",
                        outcome="SUCCESS",
                    )
                    for index in range(3)
                ]
                database.commit()
                valid = verify_audit_chain(database)
                self.assertTrue(valid["valid"])
                self.assertEqual(valid["chained_events"], 3)

                events[1].event_type = "TAMPERED"
                database.commit()
                invalid = verify_audit_chain(database)

                self.assertFalse(invalid["valid"])
                self.assertEqual(
                    invalid["first_invalid_event_id"],
                    str(events[1].id),
                )

    def test_historical_null_hash_rows_are_counted_not_backfilled(self) -> None:
        with TemporaryDirectory() as directory:
            engine = audit_engine(Path(directory) / "audit.db")

            with Session(engine) as database:
                historical = SecurityAuditEvent(
                    event_type="LEGACY_EVENT",
                    outcome="FAILED",
                    created_at=(
                        datetime.now(timezone.utc)
                        - timedelta(days=1)
                    ),
                )
                database.add(historical)
                database.commit()
                add_audit_event(
                    database,
                    event_type="NEW_EVENT",
                    outcome="SUCCESS",
                )
                database.commit()
                result = verify_audit_chain(database)

                self.assertTrue(result["valid"])
                self.assertEqual(
                    result["historical_unsealed_events"],
                    1,
                )
                self.assertEqual(result["chained_events"], 1)
                self.assertIsNone(historical.previous_hash)
                self.assertIsNone(historical.event_hash)
                chained = database.scalar(
                    select(SecurityAuditEvent).where(
                        SecurityAuditEvent.event_hash.is_not(None)
                    )
                )
                self.assertEqual(
                    chained.previous_hash,
                    AUDIT_CHAIN_GENESIS_HASH,
                )

    def test_unsealed_row_after_chain_start_is_invalid(self) -> None:
        with TemporaryDirectory() as directory:
            engine = audit_engine(Path(directory) / "audit.db")

            with Session(engine) as database:
                sealed = add_audit_event(
                    database,
                    event_type="SEALED_EVENT",
                    outcome="SUCCESS",
                )
                database.commit()
                unsealed = SecurityAuditEvent(
                    event_type="UNSEALED_AFTER_CHAIN",
                    outcome="FAILED",
                    created_at=sealed.created_at + timedelta(seconds=1),
                )
                database.add(unsealed)
                database.commit()

                result = verify_audit_chain(database)

                self.assertFalse(result["valid"])
                self.assertEqual(
                    result["first_invalid_event_id"],
                    str(unsealed.id),
                )

    def test_success_rolls_back_and_denial_survives_independently(self) -> None:
        with TemporaryDirectory() as directory:
            engine = audit_engine(Path(directory) / "audit.db")

            with Session(engine) as database:
                add_audit_event(
                    database,
                    event_type="BUSINESS_SUCCESS",
                    outcome="SUCCESS",
                )
                database.rollback()
                persisted = record_audit_event(
                    database,
                    event_type="BUSINESS_DENIED",
                    outcome="DENIED",
                )

            with Session(engine) as database:
                events = list(
                    database.scalars(select(SecurityAuditEvent)).all()
                )

            self.assertTrue(persisted)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].event_type, "BUSINESS_DENIED")

    def test_audit_cleanup_errors_do_not_escape(self) -> None:
        class BrokenAuditDatabase:
            def rollback(self) -> None:
                raise RuntimeError("audit rollback failed")

            def close(self) -> None:
                raise RuntimeError("audit close failed")

        engine = SimpleNamespace(
            dialect=SimpleNamespace(name="postgresql")
        )
        source_database = SimpleNamespace(get_bind=lambda: engine)

        with (
            patch(
                "app.services.audit_service.sessionmaker",
                return_value=lambda: BrokenAuditDatabase(),
            ),
            patch(
                "app.services.audit_service.write_audit_event",
                side_effect=RuntimeError("audit write failed"),
            ),
        ):
            persisted = record_audit_event(
                source_database,
                event_type="BUSINESS_DENIED",
                outcome="DENIED",
            )

        self.assertFalse(persisted)

    def test_independent_concurrent_writers_form_one_chain(self) -> None:
        with TemporaryDirectory() as directory:
            engine = audit_engine(Path(directory) / "audit.db")
            outcomes = []
            outcomes_lock = threading.Lock()

            def write(index: int) -> None:
                with Session(engine) as source_database:
                    result = record_audit_event(
                        source_database,
                        event_type=f"CONCURRENT_{index}",
                        outcome="SUCCESS",
                    )
                with outcomes_lock:
                    outcomes.append(result)

            threads = [
                threading.Thread(target=write, args=(index,))
                for index in range(8)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual(outcomes, [True] * 8)

            with Session(engine) as database:
                result = verify_audit_chain(database)

            self.assertTrue(result["valid"])
            self.assertEqual(result["chained_events"], 8)

    def test_multiple_events_chain_with_application_autoflush_disabled(self) -> None:
        with TemporaryDirectory() as directory:
            engine = audit_engine(Path(directory) / "audit.db")

            with Session(engine, autoflush=False) as database:
                first = add_audit_event(
                    database,
                    event_type="FIRST_IN_TRANSACTION",
                    outcome="SUCCESS",
                )
                second = add_audit_event(
                    database,
                    event_type="SECOND_IN_TRANSACTION",
                    outcome="SUCCESS",
                )
                database.commit()
                result = verify_audit_chain(database)

            self.assertEqual(first.previous_hash, AUDIT_CHAIN_GENESIS_HASH)
            self.assertEqual(second.previous_hash, first.event_hash)
            self.assertTrue(result["valid"])
            self.assertEqual(result["chained_events"], 2)

    def test_postgresql_advisory_lock_constant_is_documented(self) -> None:
        self.assertEqual(AUDIT_CHAIN_LOCK_KEY, 0x535447484D415544)

    def test_postgresql_writer_acquires_transaction_lock(self) -> None:
        with Session() as database:
            with (
                patch(
                    "app.services.audit_service._database_dialect",
                    return_value="postgresql",
                ),
                patch(
                    "app.services.audit_service._latest_chained_event",
                    return_value=None,
                ),
                patch.object(database, "execute") as execute,
                patch.object(database, "add") as add,
                patch.object(database, "flush") as flush,
            ):
                write_audit_event(
                    database,
                    event_type="LOCK_TEST",
                    outcome="SUCCESS",
                )

        statement, parameters = execute.call_args.args
        self.assertIn("pg_advisory_xact_lock", str(statement))
        self.assertEqual(
            parameters,
            {"lock_key": AUDIT_CHAIN_LOCK_KEY},
        )
        add.assert_called_once()
        flush.assert_called_once_with()

    def test_expiration_transition_is_audited_atomically(self) -> None:
        now = datetime.now(timezone.utc)
        request_record = SimpleNamespace(
            id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            device_id=uuid.uuid4(),
            document_id=uuid.uuid4(),
            status=SignatureRequestStatus.PENDING,
            expires_at=now - timedelta(seconds=1),
            failure_detail=None,
            completed_at=None,
            updated_at=now - timedelta(minutes=1),
        )
        database = FakeAuditDatabase()

        expired = _expire_if_needed(
            request_record,
            now=now,
            database=database,
        )

        self.assertTrue(expired)
        self.assertEqual(
            request_record.status,
            SignatureRequestStatus.EXPIRED,
        )
        audit_event = database.added[-1]
        self.assertEqual(
            audit_event.event_type,
            "SIGNATURE_REQUEST_EXPIRED",
        )
        self.assertEqual(audit_event.actor_type, "SYSTEM")
        self.assertEqual(audit_event.failure_code, "REQUEST_EXPIRED")


class AuditTaxonomyTests(unittest.TestCase):
    def test_hmac_nonce_and_device_failures_are_normalized(self) -> None:
        database = FakeAuditDatabase()

        hmac_event = add_audit_event(
            database,
            event_type="AUTH_CHALLENGE_REJECTED",
            outcome="FAILED",
            detail="Invalid device HMAC",
        )
        nonce_event = add_audit_event(
            database,
            event_type="SIGNATURE_QUEUE_AUTH_REJECTED",
            outcome="FAILED",
            detail="Device queue nonce replay detected",
        )
        auth_event = add_audit_event(
            database,
            event_type="STRONG_AUTH_REJECTED",
            outcome="FAILED",
            detail="RFID does not match authentication session",
        )

        self.assertEqual(
            (hmac_event.event_type, hmac_event.failure_code),
            ("HMAC_REJECTED", "INVALID_HMAC"),
        )
        self.assertEqual(hmac_event.outcome, "DENIED")
        self.assertEqual(
            (nonce_event.event_type, nonce_event.failure_code),
            ("NONCE_REPLAY_REJECTED", "NONCE_REPLAY"),
        )
        self.assertEqual(
            (auth_event.event_type, auth_event.failure_code),
            ("DEVICE_AUTH_FAILED", "RFID_MISMATCH"),
        )

    def test_device_actor_wins_over_related_user_context(self) -> None:
        event = add_audit_event(
            FakeAuditDatabase(),
            event_type="STRONG_AUTH_REJECTED",
            outcome="FAILED",
            user_id=uuid.uuid4(),
            device_id=uuid.uuid4(),
            detail="Fingerprint mismatch",
        )

        self.assertEqual(event.actor_type, "DEVICE")
        self.assertIsNotNone(event.user_id)

    def test_signing_denials_and_service_failures_are_distinct(self) -> None:
        database = Mock()

        with patch(
            "app.api.signing.record_audit_event",
            return_value=True,
        ) as recorder:
            with self.assertRaises(HTTPException):
                reject_sign(
                    database,
                    status_code=403,
                    response_detail="Denied",
                    audit_detail="Consent mismatch",
                    source_ip="127.0.0.1",
                )

            self.assertEqual(
                recorder.call_args.kwargs["outcome"],
                "DENIED",
            )

            with self.assertRaises(HTTPException):
                reject_sign(
                    database,
                    status_code=503,
                    response_detail="Unavailable",
                    audit_detail="TSA unavailable",
                    source_ip="127.0.0.1",
                    audit_event_type="TSA_TIMESTAMP_FAILED",
                    failure_code="TSA_UNAVAILABLE",
                )

            self.assertEqual(
                recorder.call_args.kwargs["outcome"],
                "FAILURE",
            )
            self.assertEqual(
                recorder.call_args.kwargs["event_type"],
                "TSA_TIMESTAMP_FAILED",
            )
            self.assertEqual(
                recorder.call_args.kwargs["failure_code"],
                "TSA_UNAVAILABLE",
            )

    def test_signing_route_contains_success_and_failure_audit_hooks(self) -> None:
        source = inspect.getsource(sign_document)

        for event_type in (
            "SIGNATURE_STARTED",
            "TSA_TIMESTAMP_FAILED",
            "TSA_TIMESTAMP_SUCCESS",
            "PADES_CREATED",
            "PADES_VALIDATION_FAILED",
            "PADES_VALIDATION_SUCCESS",
            "SIGNATURE_SUCCESS",
        ):
            self.assertIn(f'"{event_type}"', source)


class AuditAdminApiTests(unittest.TestCase):
    def test_integrity_endpoint_executes_select_only(self) -> None:
        with TemporaryDirectory() as directory:
            engine = audit_engine(Path(directory) / "audit.db")

            with Session(engine) as database:
                add_audit_event(
                    database,
                    event_type="READ_ONLY_CHECK",
                    outcome="SUCCESS",
                )
                database.commit()
                statements = []

                def capture_statement(
                    _connection,
                    _cursor,
                    statement,
                    _parameters,
                    _context,
                    _executemany,
                ) -> None:
                    statements.append(statement.strip().upper())

                sqlalchemy_event.listen(
                    engine,
                    "before_cursor_execute",
                    capture_statement,
                )
                try:
                    response = audit_integrity(database)
                finally:
                    sqlalchemy_event.remove(
                        engine,
                        "before_cursor_execute",
                        capture_statement,
                    )

            self.assertTrue(json.loads(response.body)["valid"])
            self.assertTrue(statements)
            self.assertTrue(
                all(statement.startswith("SELECT") for statement in statements)
            )

    def test_list_filters_and_deterministic_pagination(self) -> None:
        with TemporaryDirectory() as directory:
            engine = audit_engine(Path(directory) / "audit.db")

            with Session(engine) as database:
                add_audit_event(
                    database,
                    event_type="DOCUMENT_VIEWED",
                    outcome="SUCCESS",
                )
                add_audit_event(
                    database,
                    event_type="HMAC_REJECTED",
                    outcome="DENIED",
                    failure_code="INVALID_HMAC",
                )
                database.commit()

                response = audit_list_response(
                    database,
                    category="SECURITY",
                    limit=1,
                )
                payload = json.loads(response.body)

                self.assertEqual(payload["total"], 1)
                self.assertEqual(len(payload["items"]), 1)
                self.assertEqual(
                    payload["items"][0]["event_type"],
                    "HMAC_REJECTED",
                )
                self.assertEqual(payload["limit"], 1)
                self.assertEqual(payload["offset"], 0)

    def test_csv_export_uses_filtered_sanitized_values(self) -> None:
        with TemporaryDirectory() as directory:
            engine = audit_engine(Path(directory) / "audit.db")

            with Session(engine) as database:
                add_audit_event(
                    database,
                    event_type="TEST_EXPORT",
                    outcome="SUCCESS",
                    actor_type="ADMIN",
                    actor_id="=FORMULA()",
                    details={
                        "safe": "visible",
                        "password": "must-not-survive",
                    },
                )
                database.commit()
                response = export_audit_csv(
                    from_time=None,
                    to_time=None,
                    category=None,
                    event_type=None,
                    actor_type=None,
                    user_id=None,
                    device_id=None,
                    document_id=None,
                    signature_request_id=None,
                    signature_id=None,
                    outcome=None,
                    failure_code=None,
                    correlation_id=None,
                    limit=100,
                    offset=0,
                    database=database,
                )

                rows = list(csv.DictReader(StringIO(response.body.decode())))
                self.assertEqual(len(rows), 1)
                self.assertTrue(rows[0]["actor_id"].startswith("'="))
                self.assertIn("visible", rows[0]["details"])
                self.assertNotIn("must-not-survive", rows[0]["details"])

    def test_user_without_admin_ui_session_is_denied(self) -> None:
        with self.assertRaises(HTTPException) as rejected:
            require_ui_session(build_request("/ui/api/audit"))

        self.assertEqual(rejected.exception.status_code, 401)
        audit_paths = {
            route.path
            for route in audit_web_router.routes
        }
        self.assertIn("/ui/api/audit", audit_paths)
        self.assertIn("/ui/api/audit/integrity", audit_paths)

    def test_detail_endpoint_resanitizes_historical_values(self) -> None:
        event_id = uuid.uuid4()
        event = SecurityAuditEvent(
            id=event_id,
            event_type="LEGACY_EVENT",
            outcome="FAILED",
            detail="password=must-not-survive",
            details={
                "safe": "visible",
                "session_token": "must-not-survive",
            },
            created_at=datetime.now(timezone.utc),
        )
        database = SimpleNamespace(
            get=lambda model, record_id: (
                event
                if model is SecurityAuditEvent
                and record_id == event_id
                else None
            )
        )

        response = audit_event_details(event_id, database)
        payload = json.loads(response.body)
        material = json.dumps(payload)

        self.assertIn("visible", material)
        self.assertNotIn("must-not-survive", material)

    def test_admin_ui_renders_audit_values_as_text(self) -> None:
        template = (
            PROJECT_ROOT / "app/web/templates/index.html"
        ).read_text(encoding="utf-8")
        script = (
            PROJECT_ROOT / "app/web/static/app.js"
        ).read_text(encoding="utf-8")

        self.assertIn("Journal d’audit", template)
        self.assertIn("/ui/api/audit/export.csv", template)
        self.assertIn("cell.textContent", script)
        self.assertNotIn("innerHTML", script)


class AuditLoginIntegrationTests(unittest.TestCase):
    def test_user_login_success_and_failure_events(self) -> None:
        user = SimpleNamespace(
            id=uuid.uuid4(),
            email="audit-user@example.test",
            password_hash=hash_password("correct-test-password"),
            status=UserStatus.ACTIVE,
        )
        success_database = FakeAuditDatabase(user)
        response = create_user_web_session(
            build_request("/user/login", method="POST"),
            user.email,
            "correct-test-password",
            success_database,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            success_database.added[-1].event_type,
            "USER_LOGIN_SUCCESS",
        )

        with patch(
            "app.user_web.routes.record_audit_event",
            return_value=True,
        ) as recorder:
            response = create_user_web_session(
                build_request("/user/login", method="POST"),
                user.email,
                "wrong-test-password",
                FakeAuditDatabase(user),
            )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            recorder.call_args.kwargs["event_type"],
            "USER_LOGIN_FAILED",
        )

    def test_admin_login_success_and_failure_events(self) -> None:
        expected_key = (
            get_settings().admin_api_key.get_secret_value()
        )
        success_database = FakeAuditDatabase()
        response = create_web_session(
            build_request("/ui/login", method="POST"),
            expected_key,
            success_database,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            success_database.added[-1].event_type,
            "ADMIN_LOGIN_SUCCESS",
        )

        failure_database = SimpleNamespace(get_bind=lambda: None)
        with patch(
            "app.web.routes.record_audit_event",
            return_value=True,
        ) as recorder:
            response = create_web_session(
                build_request("/ui/login", method="POST"),
                "wrong-admin-key-for-audit-test",
                failure_database,
            )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            recorder.call_args.kwargs["event_type"],
            "ADMIN_LOGIN_FAILED",
        )


class AuditMigrationTests(unittest.TestCase):
    def test_migration_preserves_historical_rows_and_indexes_queries(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "audit_hardening_migration",
            MIGRATION_PATH,
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        calls = []

        class Recorder:
            def __getattr__(self, name):
                def record(*args, **kwargs):
                    calls.append((name, args, kwargs))

                return record

        migration.op = Recorder()
        migration.upgrade()

        self.assertEqual(migration.down_revision, "e74a1c6d902f")
        added_columns = {
            args[1].name: args[1]
            for name, args, _kwargs in calls
            if name == "add_column"
        }
        self.assertTrue(added_columns["previous_hash"].nullable)
        self.assertTrue(added_columns["event_hash"].nullable)
        indexed = {
            args[0]
            for name, args, _kwargs in calls
            if name == "create_index"
        }
        self.assertEqual(
            indexed,
            {
                "ix_security_audit_events_category",
                "ix_security_audit_events_actor_type",
                "ix_security_audit_events_signature_request_id",
                "ix_security_audit_events_correlation_id",
            },
        )
        self.assertFalse(
            any(name == "execute" for name, _args, _kwargs in calls)
        )


if __name__ == "__main__":
    unittest.main()
