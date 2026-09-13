import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.models import DeviceStatus, UserStatus


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        min_length=3,
        max_length=100,
        pattern=r"^[a-zA-Z0-9_.-]+$",
        examples=["lina"],
    )

    full_name: str = Field(
        min_length=2,
        max_length=150,
        examples=["Lina Mouna"],
    )

    email: str | None = Field(
        default=None,
        min_length=3,
        max_length=320,
        examples=["lina@example.test"],
    )

    password: SecretStr | None = Field(
        default=None,
        min_length=12,
        max_length=128,
    )


class UserCredentialsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(
        min_length=3,
        max_length=320,
        examples=["lina@example.test"],
    )

    password: SecretStr = Field(
        min_length=12,
        max_length=128,
    )


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    full_name: str
    email: str | None
    status: UserStatus
    created_at: datetime


class DeviceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_uid: str = Field(
        min_length=3,
        max_length=100,
        pattern=r"^[A-Za-z0-9_.:-]+$",
        examples=["ESP32-001"],
    )

    display_name: str = Field(
        min_length=2,
        max_length=150,
        examples=["Primary signing device"],
    )

    user_id: uuid.UUID

    rfid_enabled: bool = True
    fingerprint_enabled: bool = True


class DeviceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_uid: str
    display_name: str
    user_id: uuid.UUID
    status: DeviceStatus
    rfid_enabled: bool
    fingerprint_enabled: bool
    last_seen: datetime | None
    created_at: datetime
