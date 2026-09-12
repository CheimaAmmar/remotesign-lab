import hashlib
import hmac
import json
import logging
import math
import re
import threading
import uuid

from collections.abc import Mapping, Sequence
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from app.models import SecurityAuditEvent


logger = logging.getLogger(__name__)

# Signed BIGINT mnemonic for "STGHMAUD". This lock namespace is reserved
# exclusively for appending to the audit hash chain.
AUDIT_CHAIN_LOCK_KEY = 0x535447484D415544
AUDIT_CHAIN_GENESIS_HASH = "0" * 64
AUDIT_DETAILS_MAX_DEPTH = 5
AUDIT_DETAILS_MAX_ITEMS = 50
AUDIT_DETAILS_MAX_STRING = 512

AUDIT_CATEGORIES = frozenset(
    {
        "AUTH",
        "DOCUMENT",
        "CONSENT",
        "SIGNATURE_REQUEST",
        "DEVICE_AUTH",
        "SIGNATURE",
        "PADES",
        "TSA",
        "ADMIN",
        "SECURITY",
    }
)
AUDIT_ACTOR_TYPES = frozenset(
    {"USER", "ADMIN", "DEVICE", "SYSTEM"}
)
AUDIT_OUTCOMES = frozenset(
    {"SUCCESS", "FAILURE", "DENIED"}
)

_DEVICE_ACTOR_EVENTS = frozenset(
    {
        "HMAC_REJECTED",
        "NONCE_REPLAY_REJECTED",
        "RATE_LIMIT_BLOCKED",
        "SIGNATURE_REQUEST_CLAIMED",
        "SIGNATURE_REQUEST_FAILED",
        "SIGNATURE_STARTED",
        "SIGNATURE_SUCCESS",
        "SIGNATURE_FAILED",
    }
)

_PROCESS_CHAIN_LOCK = threading.RLock()
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "password_hash",
        "device_secret",
        "hmac_secret",
        "hmac_key",
        "hmac_signature",
        "x_signature",
        "admin_api_key",
        "softhsm_pin",
        "softhsm_user_pin",
        "private_key",
        "session_token",
        "cookie",
        "authorization",
        "csrf",
        "csrf_token",
        "tsa_key",
        "tsa_private_key",
        "ca_private_key",
    }
)
_SENSITIVE_KEY_PARTS = (
    "password",
    "private_key",
    "device_secret",
    "hmac",
    "admin_api_key",
    "session_token",
    "session_cookie",
    "session_secret",
    "authorization",
    "cookie",
    "csrf",
    "softhsm_pin",
    "softhsm_user_pin",
    "tsa_key",
    "ca_private_key",
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password(?:_hash)?|device_secret|"
    r"hmac(?:_secret|_key|_signature)?|admin_api_key|"
    r"softhsm_(?:user_)?pin|authorization|cookie|csrf(?:_token)?|"
    r"session(?:_token|_cookie|_secret)?|private_key|tsa_key|"
    r"tsa_private_key|ca_private_key|x-signature)"
    r"\s*[:=]\s*(?:Bearer\s+)?[^\s,;]+"
)
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[^\s,;]+")

_EVENT_ALIASES = {
    "USER_WEB_LOGIN": "USER_LOGIN_SUCCESS",
    "USER_SIGNATURE_REQUEST_CREATED": "SIGNATURE_REQUEST_CREATED",
    "AUTH_CHALLENGE_CREATED": "DEVICE_CHALLENGE_CREATED",
    "STRONG_AUTH_COMPLETED": "DEVICE_AUTH_SUCCESS",
    "DOCUMENT_SIGNED": "SIGNATURE_SUCCESS",
    "SIGNATURE_REQUEST_FAILURE_REPORTED": (
        "SIGNATURE_REQUEST_FAILED"
    ),
}


def _normalized_key(value: object) -> str:
    return re.sub(
        r"[^a-z0-9]+",
        "_",
        str(value).strip().lower(),
    ).strip("_")


def _is_sensitive_key(value: object) -> bool:
    key = _normalized_key(value)
    return key in _SENSITIVE_KEYS or any(
        part in key for part in _SENSITIVE_KEY_PARTS
    )


def _stable_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sanitize_text(value: object, *, max_length: int) -> str:
    sanitized = _SENSITIVE_ASSIGNMENT.sub(
        r"\1=[REDACTED]",
        str(value),
    )
    sanitized = _BEARER_TOKEN.sub(
        "Bearer [REDACTED]",
        sanitized,
    )
    return sanitized[:max_length]


def _sanitize_value(value: Any, *, depth: int) -> Any:
    if depth > AUDIT_DETAILS_MAX_DEPTH:
        return "[TRUNCATED]"

    if value is None or isinstance(value, (bool, int)):
        return value

    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)

    if isinstance(value, uuid.UUID):
        return str(value)

    if isinstance(value, datetime):
        return _stable_datetime(value)

    if isinstance(value, Enum):
        return _sanitize_value(value.value, depth=depth)

    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}

        for index, (raw_key, raw_value) in enumerate(
            value.items()
        ):
            if index >= AUDIT_DETAILS_MAX_ITEMS:
                sanitized["_truncated"] = True
                break

            key = str(raw_key)[:128]

            if _is_sensitive_key(key):
                continue

            sanitized[key] = _sanitize_value(
                raw_value,
                depth=depth + 1,
            )

        return sanitized

    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        values = list(value)
        sanitized_items = [
            _sanitize_value(item, depth=depth + 1)
            for item in values[:AUDIT_DETAILS_MAX_ITEMS]
        ]

        if len(values) > AUDIT_DETAILS_MAX_ITEMS:
            sanitized_items.append("[TRUNCATED]")

        return sanitized_items

    return _sanitize_text(
        value,
        max_length=AUDIT_DETAILS_MAX_STRING,
    )


def sanitize_audit_details(
    value: Any,
) -> dict | list | None:
    if value is None:
        return None

    sanitized = _sanitize_value(value, depth=0)

    if isinstance(sanitized, (dict, list)):
        return sanitized

    return {"value": sanitized}


def sanitize_legacy_detail(
    value: str | None,
) -> str | None:
    if value is None:
        return None

    return _sanitize_text(
        value,
        max_length=255,
    )


def _taxonomy(
    event_type: str,
    detail: str | None,
) -> tuple[str, str | None]:
    normalized = str(event_type).strip().upper()
    message = (detail or "").lower()

    if "hmac" in message and (
        "invalid" in message or "rejected" in message
    ):
        return "HMAC_REJECTED", "INVALID_HMAC"

    if "nonce" in message and (
        "replay" in message or "already used" in message
    ):
        return "NONCE_REPLAY_REJECTED", "NONCE_REPLAY"

    normalized = _EVENT_ALIASES.get(normalized, normalized)
    failure_code = None

    if normalized in {
        "AUTH_CHALLENGE_REJECTED",
        "SIGNATURE_QUEUE_AUTH_REJECTED",
    }:
        normalized = "DEVICE_CHALLENGE_REJECTED"
    elif normalized == "STRONG_AUTH_REJECTED":
        normalized = "DEVICE_AUTH_FAILED"
    elif normalized == "DOCUMENT_SIGN_REJECTED":
        normalized = "SIGNATURE_FAILED"

    reason_codes = (
        ("rfid does not match", "RFID_MISMATCH"),
        ("fingerprint", "FINGERPRINT_MISMATCH"),
        ("missing consent", "CONSENT_MISSING"),
        ("consent", "CONSENT_MISMATCH"),
        ("document hash", "DOCUMENT_HASH_MISMATCH"),
        ("current state", "REQUEST_STATE_INVALID"),
        ("session/device mismatch", "DEVICE_MISMATCH"),
        ("device mismatch", "DEVICE_MISMATCH"),
        (
            "signed pades document was not published",
            "SIGNED_DOCUMENT_MISSING",
        ),
        ("tsa", "TSA_UNAVAILABLE"),
        ("timestamp", "TSA_VALIDATION_FAILED"),
        ("pades", "PADES_CREATION_FAILED"),
    )

    for marker, code in reason_codes:
        if marker in message:
            failure_code = code
            break

    return normalized[:64], failure_code


def _category_for(event_type: str) -> str:
    if event_type.startswith("USER_LOGIN") or event_type in {
        "USER_LOGOUT",
        "ADMIN_LOGIN_SUCCESS",
        "ADMIN_LOGIN_FAILED",
        "ADMIN_LOGOUT",
    }:
        return "AUTH"

    if event_type.startswith("DOCUMENT_") or event_type == (
        "SIGNED_DOCUMENT_DOWNLOADED"
    ):
        return "DOCUMENT"

    if event_type.startswith("CONSENT_"):
        return "CONSENT"

    if event_type.startswith("SIGNATURE_REQUEST_") or (
        event_type.startswith("DEVICE_REQUEST_")
    ):
        return "SIGNATURE_REQUEST"

    if event_type.startswith("DEVICE_"):
        return "DEVICE_AUTH"

    if event_type.startswith("PADES_"):
        return "PADES"

    if event_type.startswith("TSA_"):
        return "TSA"

    if event_type.startswith("SIGNATURE_"):
        return "SIGNATURE"

    if event_type.startswith("ADMIN_"):
        return "ADMIN"

    return "SECURITY"


def _normalized_outcome(
    outcome: str,
    event_type: str,
) -> str:
    normalized = str(outcome).strip().upper()

    if normalized == "FAILED":
        normalized = "FAILURE"

    if event_type in {
        "HMAC_REJECTED",
        "NONCE_REPLAY_REJECTED",
        "DEVICE_CHALLENGE_REJECTED",
        "DEVICE_AUTH_FAILED",
        "USER_LOGIN_FAILED",
        "ADMIN_LOGIN_FAILED",
        "RATE_LIMIT_BLOCKED",
    }:
        normalized = "DENIED"

    if normalized not in AUDIT_OUTCOMES:
        raise ValueError("Unsupported audit outcome")

    return normalized


def _normalized_failure_code(
    value: str | None,
) -> str | None:
    if value is None:
        return None

    normalized = value.strip().upper()

    if not re.fullmatch(r"[A-Z0-9_]{3,64}", normalized):
        return "INVALID_FAILURE_CODE"

    return normalized


def _canonical_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value

    if isinstance(value, uuid.UUID):
        return str(value)

    if isinstance(value, datetime):
        return _stable_datetime(value)

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, Mapping):
        return {
            str(key): _canonical_value(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [_canonical_value(item) for item in value]

    return str(value)


AUDIT_HASH_FIELDS = (
    "id",
    "category",
    "event_type",
    "actor_type",
    "actor_id",
    "user_id",
    "device_id",
    "session_id",
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
    "created_at",
    "previous_hash",
)


def canonical_audit_event(
    event: SecurityAuditEvent,
) -> bytes:
    payload = {
        field: _canonical_value(getattr(event, field, None))
        for field in AUDIT_HASH_FIELDS
    }

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def calculate_audit_event_hash(
    event: SecurityAuditEvent,
) -> str:
    return hashlib.sha256(
        canonical_audit_event(event)
    ).hexdigest()


def _database_dialect(
    database: Session,
) -> str | None:
    try:
        return database.get_bind().dialect.name
    except (AttributeError, TypeError):
        return None


def _latest_chained_event(
    database: Session,
) -> SecurityAuditEvent | None:
    return database.scalar(
        select(SecurityAuditEvent)
        .where(SecurityAuditEvent.event_hash.is_not(None))
        .order_by(
            SecurityAuditEvent.created_at.desc(),
            SecurityAuditEvent.id.desc(),
        )
        .limit(1)
    )


def _now_after(
    previous: SecurityAuditEvent | None,
) -> datetime:
    now = datetime.now(timezone.utc)

    if previous is None or previous.created_at is None:
        return now

    previous_time = previous.created_at

    if previous_time.tzinfo is None:
        previous_time = previous_time.replace(
            tzinfo=timezone.utc
        )

    if now <= previous_time:
        return previous_time + timedelta(microseconds=1)

    return now


def write_audit_event(
    database: Session,
    *,
    event_type: str,
    outcome: str,
    category: str | None = None,
    actor_type: str | None = None,
    actor_id: str | None = None,
    user_id=None,
    device_id=None,
    session_id=None,
    document_id=None,
    signature_request_id=None,
    signature_id=None,
    failure_code: str | None = None,
    correlation_id=None,
    request=None,
    http_status: int | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    detail: str | None = None,
    details: Any = None,
) -> SecurityAuditEvent:
    safe_detail = sanitize_legacy_detail(detail)
    normalized_event, inferred_failure = _taxonomy(
        event_type,
        safe_detail,
    )
    normalized_category = (
        category or _category_for(normalized_event)
    ).strip().upper()

    if normalized_category not in AUDIT_CATEGORIES:
        raise ValueError("Unsupported audit category")

    if actor_type is None:
        if (
            normalized_event.startswith("DEVICE_")
            or normalized_event in _DEVICE_ACTOR_EVENTS
        ):
            actor_type = "DEVICE"
        elif user_id is not None:
            actor_type = "USER"
        elif device_id is not None:
            actor_type = "DEVICE"
        else:
            actor_type = "SYSTEM"

    actor_type = actor_type.strip().upper()

    if actor_type not in AUDIT_ACTOR_TYPES:
        raise ValueError("Unsupported audit actor type")

    if actor_id is None:
        if actor_type == "USER" and user_id is not None:
            actor_id = str(user_id)
        elif actor_type == "DEVICE" and device_id is not None:
            actor_id = str(device_id)

    if request is not None:
        http_method = str(
            getattr(request, "method", "")
        ).upper()[:10] or None
        request_url = getattr(request, "url", None)
        http_path = str(
            getattr(request_url, "path", "")
        )[:255] or None

        request_client = getattr(request, "client", None)

        if request_client is not None:
            source_ip = request_client.host

        request_headers = getattr(request, "headers", None)

        if request_headers is not None:
            user_agent = request_headers.get("user-agent")
    else:
        http_method = None
        http_path = None

    if correlation_id is None and document_id is not None:
        correlation_id = document_id

    safe_details = sanitize_audit_details(
        details
        if details is not None
        else ({"message": safe_detail} if safe_detail else None)
    )
    normalized_outcome = _normalized_outcome(
        outcome,
        normalized_event,
    )
    normalized_failure = _normalized_failure_code(
        failure_code or inferred_failure
    )

    is_real_session = isinstance(database, Session)
    dialect = (
        _database_dialect(database)
        if is_real_session
        else None
    )
    lock_context = (
        _PROCESS_CHAIN_LOCK
        if is_real_session and dialect != "postgresql"
        else nullcontext()
    )

    with lock_context:
        if dialect == "postgresql":
            database.execute(
                text(
                    "SELECT pg_advisory_xact_lock(:lock_key)"
                ),
                {"lock_key": AUDIT_CHAIN_LOCK_KEY},
            )

        previous = (
            _latest_chained_event(database)
            if is_real_session
            else None
        )
        event = SecurityAuditEvent(
            id=uuid.uuid4(),
            category=normalized_category,
            event_type=normalized_event,
            actor_type=actor_type,
            actor_id=(
                _sanitize_text(actor_id, max_length=128)
                if actor_id is not None
                else None
            ),
            outcome=normalized_outcome,
            user_id=user_id,
            device_id=device_id,
            session_id=session_id,
            document_id=document_id,
            signature_request_id=signature_request_id,
            signature_id=signature_id,
            failure_code=normalized_failure,
            correlation_id=correlation_id,
            http_method=http_method,
            http_path=http_path,
            http_status=http_status,
            source_ip=(source_ip[:64] if source_ip else None),
            user_agent=(
                _sanitize_text(user_agent, max_length=512)
                if user_agent
                else None
            ),
            detail=safe_detail,
            details=safe_details,
            created_at=_now_after(previous),
            previous_hash=(
                previous.event_hash
                if previous is not None
                else AUDIT_CHAIN_GENESIS_HASH
            ),
        )
        event.event_hash = calculate_audit_event_hash(event)
        database.add(event)

        if is_real_session:
            database.flush()

        return event


def add_audit_event(
    database: Session,
    **kwargs,
) -> SecurityAuditEvent:
    """Add a chained event to the current business transaction."""
    return write_audit_event(database, **kwargs)


def record_audit_event(
    database: Session,
    **kwargs,
) -> bool:
    """Persist a denial independently after business rollback."""
    event_type = str(kwargs.get("event_type", "UNKNOWN"))

    try:
        bind = database.get_bind()
        engine = getattr(bind, "engine", bind)
        dialect = getattr(
            getattr(engine, "dialect", None),
            "name",
            None,
        )
        audit_session_factory = sessionmaker(
            bind=engine,
            autoflush=False,
            expire_on_commit=False,
        )
        audit_database = audit_session_factory()
    except Exception:
        logger.exception(
            "Unable to open audit transaction for: %s",
            event_type,
        )
        return False

    try:
        commit_context = (
            _PROCESS_CHAIN_LOCK
            if dialect != "postgresql"
            else nullcontext()
        )

        with commit_context:
            write_audit_event(audit_database, **kwargs)
            audit_database.commit()
        return True
    except Exception:
        try:
            audit_database.rollback()
        except Exception:
            logger.exception(
                "Unable to roll back failed audit event: %s",
                event_type,
            )
        logger.exception(
            "Unable to persist security audit event: %s",
            event_type,
        )
        return False
    finally:
        try:
            audit_database.close()
        except Exception:
            logger.exception(
                "Unable to close audit transaction for: %s",
                event_type,
            )


def serialize_audit_event(
    event: SecurityAuditEvent,
) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "category": event.category,
        "event_type": event.event_type,
        "actor_type": event.actor_type,
        "actor_id": (
            _sanitize_text(event.actor_id, max_length=128)
            if event.actor_id is not None
            else None
        ),
        "user_id": (
            str(event.user_id)
            if event.user_id is not None
            else None
        ),
        "device_id": (
            str(event.device_id)
            if event.device_id is not None
            else None
        ),
        "session_id": (
            str(event.session_id)
            if event.session_id is not None
            else None
        ),
        "document_id": (
            str(event.document_id)
            if event.document_id is not None
            else None
        ),
        "signature_request_id": (
            str(event.signature_request_id)
            if event.signature_request_id is not None
            else None
        ),
        "signature_id": (
            str(event.signature_id)
            if event.signature_id is not None
            else None
        ),
        "outcome": event.outcome,
        "failure_code": event.failure_code,
        "correlation_id": (
            str(event.correlation_id)
            if event.correlation_id is not None
            else None
        ),
        "http_method": event.http_method,
        "http_path": (
            _sanitize_text(event.http_path, max_length=255)
            if event.http_path is not None
            else None
        ),
        "http_status": event.http_status,
        "source_ip": event.source_ip,
        "user_agent": (
            _sanitize_text(event.user_agent, max_length=512)
            if event.user_agent is not None
            else None
        ),
        "detail": sanitize_legacy_detail(event.detail),
        "details": sanitize_audit_details(event.details),
        "created_at": (
            event.created_at.isoformat()
            if event.created_at
            else None
        ),
        "previous_hash": event.previous_hash,
        "event_hash": event.event_hash,
    }


def verify_audit_chain(
    database: Session,
) -> dict[str, Any]:
    events = list(
        database.scalars(
            select(SecurityAuditEvent).order_by(
                SecurityAuditEvent.created_at.asc(),
                SecurityAuditEvent.id.asc(),
            )
        ).all()
    )
    historical = 0
    chained = 0
    checked = 0
    first_invalid = None
    expected_previous = AUDIT_CHAIN_GENESIS_HASH
    chain_started = False

    for event in events:
        has_previous = event.previous_hash is not None
        has_hash = event.event_hash is not None

        if not has_previous and not has_hash and not chain_started:
            historical += 1
            continue

        if not has_previous or not has_hash:
            first_invalid = event.id
            checked += 1
            break

        chain_started = True
        chained += 1
        checked += 1
        calculated = calculate_audit_event_hash(event)

        if (
            event.previous_hash != expected_previous
            or not hmac.compare_digest(
                event.event_hash,
                calculated,
            )
        ):
            first_invalid = event.id
            break

        expected_previous = event.event_hash

    return {
        "valid": first_invalid is None,
        "historical_unsealed_events": historical,
        "chained_events": chained,
        "events_checked": checked,
        "first_invalid_event_id": (
            str(first_invalid)
            if first_invalid is not None
            else None
        ),
    }
