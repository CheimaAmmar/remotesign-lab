import csv
import io
import json
import uuid

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import SecurityAuditEvent
from app.security.ui_session import require_ui_session
from app.services.audit_service import (
    sanitize_audit_details,
    serialize_audit_event,
    verify_audit_chain,
)


NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}
AUDIT_LIST_MAX_LIMIT = 200
AUDIT_EXPORT_MAX_ROWS = 5000

router = APIRouter(
    prefix="/ui/api/audit",
    tags=["Web UI Audit"],
    include_in_schema=False,
    dependencies=[Depends(require_ui_session)],
)


def _audit_conditions(
    *,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    category: str | None = None,
    event_type: str | None = None,
    actor_type: str | None = None,
    user_id: uuid.UUID | None = None,
    device_id: uuid.UUID | None = None,
    document_id: uuid.UUID | None = None,
    signature_request_id: uuid.UUID | None = None,
    signature_id: uuid.UUID | None = None,
    outcome: str | None = None,
    failure_code: str | None = None,
    correlation_id: uuid.UUID | None = None,
) -> list:
    conditions = []

    if from_time is not None:
        conditions.append(
            SecurityAuditEvent.created_at >= from_time
        )
    if to_time is not None:
        conditions.append(
            SecurityAuditEvent.created_at <= to_time
        )
    if category:
        conditions.append(
            SecurityAuditEvent.category == category.strip().upper()
        )
    if event_type:
        conditions.append(
            SecurityAuditEvent.event_type
            == event_type.strip().upper()
        )
    if actor_type:
        conditions.append(
            SecurityAuditEvent.actor_type
            == actor_type.strip().upper()
        )
    if user_id is not None:
        conditions.append(SecurityAuditEvent.user_id == user_id)
    if device_id is not None:
        conditions.append(
            SecurityAuditEvent.device_id == device_id
        )
    if document_id is not None:
        conditions.append(
            SecurityAuditEvent.document_id == document_id
        )
    if signature_request_id is not None:
        conditions.append(
            SecurityAuditEvent.signature_request_id
            == signature_request_id
        )
    if signature_id is not None:
        conditions.append(
            SecurityAuditEvent.signature_id == signature_id
        )
    if outcome:
        conditions.append(
            SecurityAuditEvent.outcome == outcome.strip().upper()
        )
    if failure_code:
        conditions.append(
            SecurityAuditEvent.failure_code
            == failure_code.strip().upper()
        )
    if correlation_id is not None:
        conditions.append(
            SecurityAuditEvent.correlation_id == correlation_id
        )

    return conditions


def _query_events(
    database: Session,
    *,
    conditions: list,
    limit: int,
    offset: int,
) -> tuple[list[SecurityAuditEvent], int]:
    total = database.scalar(
        select(func.count(SecurityAuditEvent.id)).where(
            *conditions
        )
    )
    events = list(
        database.scalars(
            select(SecurityAuditEvent)
            .where(*conditions)
            .order_by(
                SecurityAuditEvent.created_at.desc(),
                SecurityAuditEvent.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        ).all()
    )

    return events, int(total or 0)


def _csv_safe(value: object) -> str:
    if value is None:
        return ""

    text_value = str(value)

    if text_value.startswith(("=", "+", "-", "*", "@")):
        return "'" + text_value

    return text_value


@router.get("/integrity")
def audit_integrity(
    database: Session = Depends(get_db),
) -> JSONResponse:
    return JSONResponse(
        verify_audit_chain(database),
        headers=NO_STORE_HEADERS,
    )


@router.get("/export.csv")
def export_audit_csv(
    from_time: Annotated[
        datetime | None,
        Query(alias="from"),
    ] = None,
    to_time: Annotated[
        datetime | None,
        Query(alias="to"),
    ] = None,
    category: str | None = None,
    event_type: str | None = None,
    actor_type: str | None = None,
    user_id: uuid.UUID | None = None,
    device_id: uuid.UUID | None = None,
    document_id: uuid.UUID | None = None,
    signature_request_id: uuid.UUID | None = None,
    signature_id: uuid.UUID | None = None,
    outcome: str | None = None,
    failure_code: str | None = None,
    correlation_id: uuid.UUID | None = None,
    limit: int = Query(
        default=AUDIT_EXPORT_MAX_ROWS,
        ge=1,
        le=AUDIT_EXPORT_MAX_ROWS,
    ),
    offset: int = Query(default=0, ge=0),
    database: Session = Depends(get_db),
) -> Response:
    conditions = _audit_conditions(
        from_time=from_time,
        to_time=to_time,
        category=category,
        event_type=event_type,
        actor_type=actor_type,
        user_id=user_id,
        device_id=device_id,
        document_id=document_id,
        signature_request_id=signature_request_id,
        signature_id=signature_id,
        outcome=outcome,
        failure_code=failure_code,
        correlation_id=correlation_id,
    )
    events, _total = _query_events(
        database,
        conditions=conditions,
        limit=limit,
        offset=offset,
    )
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    columns = (
        "id",
        "created_at",
        "category",
        "event_type",
        "actor_type",
        "actor_id",
        "user_id",
        "device_id",
        "document_id",
        "signature_request_id",
        "signature_id",
        "outcome",
        "failure_code",
        "correlation_id",
        "http_method",
        "http_path",
        "http_status",
        "source_ip",
        "user_agent",
        "detail",
        "details",
        "previous_hash",
        "event_hash",
    )
    writer.writerow(columns)

    for event in events:
        item = serialize_audit_event(event)
        item["details"] = json.dumps(
            sanitize_audit_details(item["details"]),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        writer.writerow(
            [_csv_safe(item.get(column)) for column in columns]
        )

    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            **NO_STORE_HEADERS,
            "Content-Disposition": (
                'attachment; filename="remotesign-lab-audit.csv"'
            ),
        },
    )


@router.get("")
def list_audit_events(
    from_time: Annotated[
        datetime | None,
        Query(alias="from"),
    ] = None,
    to_time: Annotated[
        datetime | None,
        Query(alias="to"),
    ] = None,
    category: str | None = None,
    event_type: str | None = None,
    actor_type: str | None = None,
    user_id: uuid.UUID | None = None,
    device_id: uuid.UUID | None = None,
    document_id: uuid.UUID | None = None,
    signature_request_id: uuid.UUID | None = None,
    signature_id: uuid.UUID | None = None,
    outcome: str | None = None,
    failure_code: str | None = None,
    correlation_id: uuid.UUID | None = None,
    limit: int = Query(
        default=50,
        ge=1,
        le=AUDIT_LIST_MAX_LIMIT,
    ),
    offset: int = Query(default=0, ge=0),
    database: Session = Depends(get_db),
) -> JSONResponse:
    conditions = _audit_conditions(
        from_time=from_time,
        to_time=to_time,
        category=category,
        event_type=event_type,
        actor_type=actor_type,
        user_id=user_id,
        device_id=device_id,
        document_id=document_id,
        signature_request_id=signature_request_id,
        signature_id=signature_id,
        outcome=outcome,
        failure_code=failure_code,
        correlation_id=correlation_id,
    )
    events, total = _query_events(
        database,
        conditions=conditions,
        limit=limit,
        offset=offset,
    )

    return JSONResponse(
        {
            "items": [
                serialize_audit_event(event)
                for event in events
            ],
            "total": total,
            "limit": limit,
            "offset": offset,
        },
        headers=NO_STORE_HEADERS,
    )


@router.get("/{event_id}")
def audit_event_details(
    event_id: uuid.UUID,
    database: Session = Depends(get_db),
) -> JSONResponse:
    event = database.get(SecurityAuditEvent, event_id)

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit event not found",
        )

    return JSONResponse(
        serialize_audit_event(event),
        headers=NO_STORE_HEADERS,
    )
