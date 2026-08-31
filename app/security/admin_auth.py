import hmac

from typing import Annotated

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.config import get_settings


admin_api_key_header = APIKeyHeader(
    name="X-Admin-Key",
    scheme_name="AdminApiKey",
    description="Administrator API key",
    auto_error=False,
)


def require_admin(
    x_admin_key: Annotated[
        str | None,
        Security(admin_api_key_header),
    ],
) -> None:
    expected_key = (
        get_settings()
        .admin_api_key
        .get_secret_value()
    )

    if (
        x_admin_key is None
        or not hmac.compare_digest(
            x_admin_key,
            expected_key,
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid administrator credentials",
        )
