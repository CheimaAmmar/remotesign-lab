from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Stage HSM Server"
    app_version: str = "0.1.0"
    signature_device_uid: str = "ESP32-001"

    database_url: str

    admin_api_key: SecretStr

    softhsm_module: str
    softhsm_token_label: str = "STAGE-HSM"
    softhsm_key_label: str = "REMOTE-SIGNING-KEY"
    softhsm_key_id: str = "01"
    softhsm_user_pin: SecretStr

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
