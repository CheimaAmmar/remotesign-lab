import importlib.util
import inspect
import unittest

from pathlib import Path

from sqlalchemy import create_engine

from app.services.signature_request_service import (
    create_signature_request,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = (
    PROJECT_ROOT
    / "alembic/versions/b8127e4c9a30_add_user_web_auth_and_consent.py"
)


def load_migration():
    spec = importlib.util.spec_from_file_location(
        "user_web_auth_migration",
        MIGRATION_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load migration")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OperationRecorder:
    def __init__(self) -> None:
        self.calls = []
        self.sql = []

    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            if name == "execute":
                self.sql.append(str(args[0]))

        return record


def normalized(sql: str) -> str:
    return " ".join(sql.split())


class UserWebMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.migration = load_migration()
        self.operations = OperationRecorder()
        self.migration.op = self.operations
        self.migration.upgrade()

    def test_signature_request_user_id_remains_nullable(self) -> None:
        columns = [
            args[1]
            for name, args, _kwargs in self.operations.calls
            if name == "add_column"
            and args[0] == "signature_requests"
            and args[1].name == "user_id"
        ]

        self.assertEqual(len(columns), 1)
        self.assertTrue(columns[0].nullable)
        self.assertFalse(
            any(
                name == "alter_column"
                and args[0] == "signature_requests"
                and args[1] == "user_id"
                for name, args, _kwargs in self.operations.calls
            )
        )

    def test_request_backfill_uses_authentication_session_only(self) -> None:
        request_backfill = normalized(self.operations.sql[0])

        self.assertIn(
            "SET user_id = authentication_session.user_id",
            request_backfill,
        )
        self.assertIn(
            "FROM authentication_sessions AS authentication_session",
            request_backfill,
        )
        self.assertIn(
            "signature_request.authentication_session_id = "
            "authentication_session.id",
            request_backfill,
        )
        self.assertNotIn("devices", request_backfill.lower())
        self.assertNotIn("device.user_id", request_backfill.lower())

    def test_request_without_authentication_session_remains_unowned(self) -> None:
        request_backfill = normalized(self.operations.sql[0])

        self.assertNotIn("LEFT JOIN", request_backfill.upper())
        self.assertIn(
            "signature_request.authentication_session_id = "
            "authentication_session.id",
            request_backfill,
        )

    def test_historical_backfill_uses_authenticated_user(self) -> None:
        engine = create_engine("sqlite+pysqlite:///:memory:")

        with engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE authentication_sessions ("
                "id TEXT PRIMARY KEY, user_id TEXT NOT NULL)"
            )
            connection.exec_driver_sql(
                "CREATE TABLE devices ("
                "id TEXT PRIMARY KEY, user_id TEXT NOT NULL)"
            )
            connection.exec_driver_sql(
                "CREATE TABLE signature_requests ("
                "id TEXT PRIMARY KEY, status TEXT NOT NULL, "
                "device_id TEXT NOT NULL, "
                "authentication_session_id TEXT, user_id TEXT)"
            )
            connection.exec_driver_sql(
                "INSERT INTO authentication_sessions "
                "VALUES ('session-1', 'authenticated-user')"
            )
            connection.exec_driver_sql(
                "INSERT INTO devices "
                "VALUES ('device-1', 'different-device-user')"
            )
            connection.exec_driver_sql(
                "INSERT INTO signature_requests VALUES "
                "('signed-1', 'SIGNED', 'device-1', 'session-1', NULL), "
                "('expired-1', 'EXPIRED', 'device-1', NULL, NULL)"
            )
            connection.exec_driver_sql(self.operations.sql[0])

            rows = dict(
                connection.exec_driver_sql(
                    "SELECT id, user_id FROM signature_requests"
                ).fetchall()
            )

        self.assertEqual(rows["signed-1"], "authenticated-user")
        self.assertIsNone(rows["expired-1"])
        self.assertNotEqual(
            rows["signed-1"],
            "different-device-user",
        )

    def test_document_backfill_uses_only_identified_requests(self) -> None:
        document_backfill = normalized(self.operations.sql[1])

        self.assertIn("WHERE user_id IS NOT NULL", document_backfill)
        self.assertNotIn("devices", document_backfill.lower())

    def test_new_requests_still_require_user_id(self) -> None:
        parameter = inspect.signature(
            create_signature_request
        ).parameters["user_id"]

        self.assertIs(parameter.default, inspect.Parameter.empty)
        with self.assertRaises(TypeError):
            create_signature_request(
                None,
                owner_session_id="session",
                device=None,
                document=None,
            )


if __name__ == "__main__":
    unittest.main()
