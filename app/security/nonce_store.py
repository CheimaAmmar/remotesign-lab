import time


NONCE_TTL_SECONDS = 120

_used_nonces: dict[str, float] = {}


def cleanup_expired_nonces() -> None:
    now = time.time()

    expired_keys = [
        key
        for key, expiration in _used_nonces.items()
        if expiration <= now
    ]

    for key in expired_keys:
        _used_nonces.pop(key, None)


def is_nonce_used(
    device_uid: str,
    nonce: str,
) -> bool:
    cleanup_expired_nonces()

    key = f"{device_uid}:{nonce}"

    return key in _used_nonces


def store_nonce(
    device_uid: str,
    nonce: str,
) -> None:
    cleanup_expired_nonces()

    key = f"{device_uid}:{nonce}"

    _used_nonces[key] = (
        time.time() + NONCE_TTL_SECONDS
    )