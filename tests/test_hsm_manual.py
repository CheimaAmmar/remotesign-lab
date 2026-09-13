import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from app.services.hsm_service import HSMService


def main() -> None:
    data = b"Test document signed from Python"

    hsm = HSMService()

    result = hsm.sign_sha256_rsa_pkcs1(data)

    print("Algorithm:", result.algorithm)
    print("Key label:", result.key_label)
    print("Size:", len(result.signature), "bytes")
    print(
        "Signature:",
        result.signature_base64[:80] + "...",
    )

    public_key_der = hsm.get_public_key_der()

    public_key = serialization.load_der_public_key(
        public_key_der
    )

    try:
        public_key.verify(
            result.signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        print("Verification: OK")

    except InvalidSignature:
        print("Verification: FAILED")
        raise SystemExit(1)

    try:
        public_key.verify(
            result.signature,
            b"Modified document",
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    except InvalidSignature:
        print(
            "Modification test: signature correctly rejected"
        )


if __name__ == "__main__":
    main()
