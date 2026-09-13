import hashlib
import hmac
import secrets
import threading
import time

from dataclasses import dataclass

from fastapi import HTTPException, Request, status


UI_SESSION_COOKIE_NAME = "remotesign_lab_ui_session"
UI_SESSION_TTL_SECONDS = 30 * 60

# Prototype-local storage: use one application worker.
# A restart intentionally invalidates every Web session.

@dataclass(frozen=True, slots=True)
class UiSession:
    id: str
    csrf_token: str
    expires_at: float


_sessions: dict[str, UiSession] = {}
_sessions_lock = threading.Lock()


def _session_digest(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def _cleanup_expired_sessions(now: float) -> None:
    expired = [
        digest
        for digest, session in _sessions.items()
        if session.expires_at <= now
    ]

    for digest in expired:
        _sessions.pop(digest, None)


def create_ui_session() -> tuple[str, UiSession]:
    token = secrets.token_urlsafe(32)
    now = time.monotonic()

    session = UiSession(
        id=secrets.token_urlsafe(18),
        csrf_token=secrets.token_urlsafe(32),
        expires_at=now + UI_SESSION_TTL_SECONDS,
    )

    with _sessions_lock:
        _cleanup_expired_sessions(now)
        _sessions[_session_digest(token)] = session

    return token, session


def get_ui_session(
    token: str | None,
) -> UiSession | None:
    if not token:
        return None

    now = time.monotonic()
    digest = _session_digest(token)

    with _sessions_lock:
        _cleanup_expired_sessions(now)
        return _sessions.get(digest)


def delete_ui_session(token: str | None) -> None:
    if not token:
        return

    with _sessions_lock:
        _sessions.pop(
            _session_digest(token),
            None,
        )


def get_request_ui_session(
    request: Request,
) -> UiSession | None:
    return get_ui_session(
        request.cookies.get(
            UI_SESSION_COOKIE_NAME
        )
    )


def require_ui_session(
    request: Request,
) -> UiSession:
    session = get_request_ui_session(request)

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Web session required",
        )

    return session


def require_ui_csrf(
    request: Request,
) -> UiSession:
    session = require_ui_session(request)
    supplied_token = request.headers.get(
        "X-CSRF-Token"
    )

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


def remaining_session_seconds(
    session: UiSession,
) -> int:
    return max(
        0,
        int(session.expires_at - time.monotonic()),
    )
