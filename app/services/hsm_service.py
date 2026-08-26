import base64
from dataclasses import dataclass

import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import PKCS11Error

from app.config import get_settings


class HSMServiceError(RuntimeError):
    """Erreur contrôlée lors d'une opération avec le HSM."""


@dataclass(frozen=True)
class SignatureResult:
    signature: bytes
    signature_base64: str
    algorithm: str
    key_label: str


class HSMService:
    def __init__(self) -> None:
        self.settings = get_settings()

        try:
            self.library = pkcs11.lib(
                self.settings.softhsm_module
            )

            self.token = self.library.get_token(
                token_label=self.settings.softhsm_token_label
            )

        except PKCS11Error as error:
            raise HSMServiceError(
                "Impossible de charger le module ou le token PKCS#11"
            ) from error

    def sign_sha256_rsa_pkcs1(
        self,
        data: bytes,
    ) -> SignatureResult:
        try:
            with self.token.open(
                user_pin=self.settings.softhsm_user_pin.get_secret_value()
            ) as session:
                private_key = session.get_key(
                    object_class=ObjectClass.PRIVATE_KEY,
                    key_type=KeyType.RSA,
                    label=self.settings.softhsm_key_label,
                )

                signature = bytes(
                    private_key.sign(
                        data,
                        mechanism=Mechanism.SHA256_RSA_PKCS,
                    )
                )

        except PKCS11Error as error:
            raise HSMServiceError(
                "La signature PKCS#11 a échoué"
            ) from error

        return SignatureResult(
            signature=signature,
            signature_base64=base64.b64encode(
                signature
            ).decode("ascii"),
            algorithm="SHA256-RSA-PKCS1-v1_5",
            key_label=self.settings.softhsm_key_label,
        )

    def get_public_key_der(self) -> bytes:
        try:
            with self.token.open() as session:
                public_key = session.get_key(
                    object_class=ObjectClass.PUBLIC_KEY,
                    key_type=KeyType.RSA,
                    label=self.settings.softhsm_key_label,
                )

                modulus = public_key[Attribute.MODULUS]
                public_exponent = public_key[
                    Attribute.PUBLIC_EXPONENT
                ]

        except PKCS11Error as error:
            raise HSMServiceError(
                "Impossible de lire la clé publique PKCS#11"
            ) from error

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        public_numbers = rsa.RSAPublicNumbers(
            e=int.from_bytes(public_exponent, "big"),
            n=int.from_bytes(modulus, "big"),
        )

        public_key_object = public_numbers.public_key()

        return public_key_object.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
