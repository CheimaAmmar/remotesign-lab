import argparse

from pathlib import Path

from asn1crypto import csr, keys, pem, x509

from app.services.hsm_service import HSMService


def build_csr(common_name: str) -> bytes:
    hsm = HSMService()
    public_key = keys.PublicKeyInfo.load(
        hsm.get_public_key_der()
    )
    request_info = csr.CertificationRequestInfo(
        {
            "version": "v1",
            "subject": x509.Name.build(
                {"common_name": common_name}
            ),
            "subject_pk_info": public_key,
            "attributes": [],
        }
    )
    signature = hsm.sign_sha256_rsa_pkcs1(
        request_info.dump()
    ).signature
    request = csr.CertificationRequest(
        {
            "certification_request_info": request_info,
            "signature_algorithm": {
                "algorithm": "sha256_rsa"
            },
            "signature": signature,
        }
    )
    return pem.armor(
        "CERTIFICATE REQUEST",
        request.dump(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Create a CSR whose private-key operation stays in SoftHSM"
        )
    )
    parser.add_argument(
        "--common-name",
        default="RemoteSignLab Development Signer",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("certs/remotesign-lab-signing.csr"),
    )
    arguments = parser.parse_args()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_bytes(
        build_csr(arguments.common_name)
    )
    print(f"CSR written to {arguments.output}")


if __name__ == "__main__":
    main()
