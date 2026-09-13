import hashlib
import hmac
import time


MAX_CLOCK_SKEW_SECONDS = 120


def build_canonical_message(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    extra_data: str = "",
) -> bytes:

    parts = [
        method.upper(),
        path,
        timestamp,
        nonce,
    ]

    # Append extra_data only when present to preserve the canonical
    # format of requests that do not provide it.
    if extra_data:
        parts.append(extra_data)

    message = "\n".join(parts)

    return message.encode("utf-8")


def verify_device_hmac(
    device_secret: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    received_signature: str,
    extra_data: str = "",
) -> bool:

    # ==================================================
    # TIMESTAMP VERIFICATION
    # ==================================================

    try:
        timestamp_int = int(timestamp)

    except (ValueError, TypeError):
        return False

    current_time = int(time.time())

    if (
        abs(current_time - timestamp_int)
        > MAX_CLOCK_SKEW_SECONDS
    ):
        return False

    # ==================================================
    # HEX SECRET -> BYTES
    # ==================================================

    try:
        secret_bytes = bytes.fromhex(
            device_secret
        )

    except ValueError:
        return False

    # ==================================================
    # CANONICAL MESSAGE
    # ==================================================

    canonical_message = (
        build_canonical_message(
            method=method,
            path=path,
            timestamp=timestamp,
            nonce=nonce,
            extra_data=extra_data,
        )
    )

    # ==================================================
    # HMAC SHA256
    # ==================================================

    expected_signature = hmac.new(
        secret_bytes,
        canonical_message,
        hashlib.sha256,
    ).hexdigest()

    # ==================================================
    # SECURE COMPARISON
    # ==================================================

    try:
        received_signature_bytes = (
            received_signature
            .lower()
            .encode("ascii")
        )

    except UnicodeEncodeError:
        return False

    return hmac.compare_digest(
        expected_signature.encode("ascii"),
        received_signature_bytes,
    )
