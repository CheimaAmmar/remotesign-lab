from datetime import (
    datetime,
    timedelta,
    timezone,
)

from sqlalchemy import (
    func,
    select,
)

from sqlalchemy.orm import Session

from app.models import (
    SecurityAuditEvent,
)


RATE_LIMIT_WINDOW_SECONDS = 300
RATE_LIMIT_MAX_FAILURES = 10


def is_rate_limited(
    database: Session,
    *,
    source_ip: str | None,
    device_id=None,
) -> bool:

    if source_ip is None:
        return False

    since = (
        datetime.now(timezone.utc)
        - timedelta(
            seconds=RATE_LIMIT_WINDOW_SECONDS
        )
    )

    conditions = [
        SecurityAuditEvent.outcome.in_(
            ("FAILED", "FAILURE", "DENIED")
        ),

        SecurityAuditEvent.source_ip
        == source_ip,

        SecurityAuditEvent.created_at
        >= since,
    ]

    if device_id is not None:
        conditions.append(
            SecurityAuditEvent.device_id
            == device_id
        )

    count = database.scalar(
        select(
            func.count(
                SecurityAuditEvent.id
            )
        )
        .where(
            *conditions
        )
    )

    return (
        count is not None
        and count >= RATE_LIMIT_MAX_FAILURES
    )
