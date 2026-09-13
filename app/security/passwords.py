import hashlib
import hmac
import re
import secrets


PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(value: str) -> str:
    normalized = value.strip().casefold()

    if (
        not normalized
        or len(normalized) > 320
        or EMAIL_PATTERN.fullmatch(normalized) is None
    ):
        raise ValueError("Invalid email address")

    return normalized


def _derive_password(
    password: str,
    *,
    salt: bytes,
    n: int,
    r: int,
    p: int,
) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=SCRYPT_DKLEN,
    )


def hash_password(password: str) -> str:
    if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
        raise ValueError("Invalid password length")

    salt = secrets.token_bytes(16)
    digest = _derive_password(
        password,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )

    return "$".join(
        (
            "scrypt",
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            salt.hex(),
            digest.hex(),
        )
    )


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        scheme, n_value, r_value, p_value, salt_hex, digest_hex = (
            encoded_hash.split("$")
        )
        n = int(n_value)
        r = int(r_value)
        p = int(p_value)
        salt = bytes.fromhex(salt_hex)
        expected_digest = bytes.fromhex(digest_hex)

        if (
            scheme != "scrypt"
            or n != SCRYPT_N
            or r != SCRYPT_R
            or p != SCRYPT_P
            or len(salt) != 16
            or len(expected_digest) != SCRYPT_DKLEN
        ):
            return False

        actual_digest = _derive_password(
            password,
            salt=salt,
            n=n,
            r=r,
            p=p,
        )

    except (UnicodeError, ValueError):
        return False

    return hmac.compare_digest(
        actual_digest,
        expected_digest,
    )


_DUMMY_PASSWORD_HASH = "$".join(
    (
        "scrypt",
        str(SCRYPT_N),
        str(SCRYPT_R),
        str(SCRYPT_P),
        (b"RemoteSignLabDummyPwd").hex(),
        _derive_password(
            "not-the-user-password",
            salt=b"RemoteSignLabDummyPwd",
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
        ).hex(),
    )
)


def verify_dummy_password(password: str) -> None:
    verify_password(password, _DUMMY_PASSWORD_HASH)
