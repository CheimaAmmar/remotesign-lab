import hashlib
import hmac
import secrets
import threading
import time
import uuid

from dataclasses import dataclass, field

from fastapi import HTTPException, Request, status


USER_SESSION_COOKIE_NAME = "stage_hsm_user_session"
USER_SESSION_TTL_SECONDS = 30 * 60


@dataclass(slots=True)
class UserSession:
    id: str
    user_id: uuid.UUID
    csrf_token: str
    expires_at: float
    viewed_document_ids: set[uuid.UUID] = field(
        default_factory=set,
    )


_sessions: dict[str, UserSession] = {}
_sessions_lock = threading.Lock()


def _session_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _cleanup_expired_sessions(now: float) -> None:
    expired = [
        digest
        for digest, session in _sessions.items()
        if session.expires_at <= now
    ]

    for digest in expired:
        _sessions.pop(digest, None)


def create_user_session(
    user_id: uuid.UUID,
) -> tuple[str, UserSession]:
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    session = UserSession(
        id=secrets.token_urlsafe(18),
        user_id=user_id,
        csrf_token=secrets.token_urlsafe(32),
        expires_at=now + USER_SESSION_TTL_SECONDS,
    )

    with _sessions_lock:
        _cleanup_expired_sessions(now)
        _sessions[_session_digest(token)] = session

    return token, session


def get_user_session(token: str | None) -> UserSession | None:
    if not token:
        return None

    now = time.monotonic()

    with _sessions_lock:
        _cleanup_expired_sessions(now)
        return _sessions.get(_session_digest(token))


def delete_user_session(token: str | None) -> None:
    if not token:
        return

    with _sessions_lock:
        _sessions.pop(_session_digest(token), None)


def delete_user_sessions_for_user(user_id: uuid.UUID) -> None:
    with _sessions_lock:
        session_digests = [
            digest
            for digest, session in _sessions.items()
            if session.user_id == user_id
        ]

        for digest in session_digests:
            _sessions.pop(digest, None)


def get_request_user_session(
    request: Request,
) -> UserSession | None:
    return get_user_session(
        request.cookies.get(USER_SESSION_COOKIE_NAME)
    )


def require_user_session(request: Request) -> UserSession:
    session = get_request_user_session(request)

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User session required",
        )

    return session


def require_user_csrf(request: Request) -> UserSession:
    session = require_user_session(request)
    supplied_token = request.headers.get("X-CSRF-Token")

    if (
        supplied_token is None
        or not hmac.compare_digest(
            supplied_token.encode("utf-8"),
            session.csrf_token.encode("utf-8"),
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token",
        )

    return session


def mark_document_viewed(
    session: UserSession,
    document_id: uuid.UUID,
) -> None:
    with _sessions_lock:
        session.viewed_document_ids.add(document_id)


def has_viewed_document(
    session: UserSession,
    document_id: uuid.UUID,
) -> bool:
    with _sessions_lock:
        return document_id in session.viewed_document_ids


def remaining_user_session_seconds(
    session: UserSession,
) -> int:
    return max(0, int(session.expires_at - time.monotonic()))
