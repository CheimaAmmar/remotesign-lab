import hmac
import os
import unittest

from pathlib import Path

from dotenv import dotenv_values
from fastapi import HTTPException, status
from pydantic import SecretStr
from starlette.requests import Request

from app.config import get_settings
from app.security.admin_auth import (
    admin_api_key_header,
    require_admin,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def has_process_admin_key_override() -> bool:
    return any(
        name.casefold() == "admin_api_key"
        for name in os.environ
    )


def build_request(
    *,
    admin_key: str | None = None,
    authorization: str | None = None,
) -> Request:
    headers: list[tuple[bytes, bytes]] = []

    if admin_key is not None:
        headers.append(
            (
                b"x-admin-key",
                admin_key.encode("latin-1"),
            )
        )

    if authorization is not None:
        headers.append(
            (
                b"authorization",
                authorization.encode("latin-1"),
            )
        )

    return Request(
        {
            "type": "http",
            "headers": headers,
        }
    )


async def authorization_status(
    *,
    admin_key: str | None = None,
    authorization: str | None = None,
) -> int:
    request = build_request(
        admin_key=admin_key,
        authorization=authorization,
    )
    supplied_key = await admin_api_key_header(request)

    try:
        require_admin(supplied_key)
    except HTTPException as error:
        return error.status_code

    return status.HTTP_200_OK


class AdminAuthenticationTests(
    unittest.IsolatedAsyncioTestCase,
):
    def setUp(self) -> None:
        settings = get_settings()

        self.assertIsInstance(
            settings.admin_api_key,
            SecretStr,
        )

        self.expected_key = (
            settings
            .admin_api_key
            .get_secret_value()
        )

        if not self.expected_key:
            self.fail(
                "ADMIN_API_KEY must not be empty"
            )

    def test_pydantic_loads_key_from_dotenv(self) -> None:
        if has_process_admin_key_override():
            self.skipTest(
                "A process environment override takes precedence"
            )

        dotenv_key = dotenv_values(
            PROJECT_ROOT / ".env"
        ).get("ADMIN_API_KEY")

        if not isinstance(dotenv_key, str) or not dotenv_key:
            self.fail(
                "ADMIN_API_KEY is missing from .env"
            )

        if not hmac.compare_digest(
            self.expected_key,
            dotenv_key,
        ):
            self.fail(
                "Pydantic did not load ADMIN_API_KEY from .env"
            )

    async def test_missing_header_is_rejected(self) -> None:
        self.assertEqual(
            await authorization_status(),
            status.HTTP_401_UNAUTHORIZED,
        )

    async def test_wrong_key_is_rejected(self) -> None:
        wrong_key = "invalid-admin-key-for-test"

        if hmac.compare_digest(
            wrong_key,
            self.expected_key,
        ):
            wrong_key += "-different"

        self.assertEqual(
            await authorization_status(
                admin_key=wrong_key,
            ),
            status.HTTP_401_UNAUTHORIZED,
        )

    async def test_loaded_key_is_authorized(self) -> None:
        self.assertEqual(
            await authorization_status(
                admin_key=self.expected_key,
            ),
            status.HTTP_200_OK,
        )

    async def test_bearer_value_is_not_accepted(self) -> None:
        self.assertEqual(
            await authorization_status(
                authorization=(
                    "Bearer "
                    + self.expected_key
                ),
            ),
            status.HTTP_401_UNAUTHORIZED,
        )

    async def test_key_comparison_is_exact(self) -> None:
        self.assertEqual(
            await authorization_status(
                admin_key=self.expected_key + " ",
            ),
            status.HTTP_401_UNAUTHORIZED,
        )


if __name__ == "__main__":
    unittest.main()
