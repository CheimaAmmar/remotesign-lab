import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import (
    UserCreate,
    UserCredentialsUpdate,
    UserRead,
)
from app.security.admin_auth import require_admin
from app.security.passwords import (
    hash_password,
    normalize_email,
)
from app.security.user_session import (
    delete_user_sessions_for_user,
)


router = APIRouter(
    prefix="/api/v1/users",
    tags=["Users"],
    dependencies=[Depends(require_admin)],
)


@router.post(
    "",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    payload: UserCreate,
    database: Session = Depends(get_db),
) -> User:
    normalized_username = payload.username.strip().lower()
    normalized_full_name = payload.full_name.strip()
    supplied_email = payload.email
    supplied_password = payload.password

    if (supplied_email is None) != (supplied_password is None):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Email and password must be configured together",
        )

    normalized_email = None
    password_hash = None

    if supplied_email is not None and supplied_password is not None:
        try:
            normalized_email = normalize_email(supplied_email)
            password_hash = hash_password(
                supplied_password.get_secret_value()
            )
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(error),
            ) from error

    existing_user = database.scalar(
        select(User).where(User.username == normalized_username)
    )

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    if normalized_email is not None:
        existing_email = database.scalar(
            select(User).where(User.email == normalized_email)
        )

        if existing_email is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already exists",
            )

    user = User(
        username=normalized_username,
        full_name=normalized_full_name,
        email=normalized_email,
        password_hash=password_hash,
    )

    database.add(user)

    try:
        database.commit()
        database.refresh(user)

    except IntegrityError as error:
        database.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to create user",
        ) from error

    return user


@router.put(
    "/{user_id}/credentials",
    response_model=UserRead,
)
def update_user_credentials(
    user_id: uuid.UUID,
    payload: UserCredentialsUpdate,
    database: Session = Depends(get_db),
) -> User:
    user = database.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    try:
        normalized_email = normalize_email(payload.email)
        password_hash = hash_password(
            payload.password.get_secret_value()
        )
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        ) from error

    existing_user = database.scalar(
        select(User).where(
            User.email == normalized_email,
            User.id != user.id,
        )
    )

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already exists",
        )

    user.email = normalized_email
    user.password_hash = password_hash

    try:
        database.commit()
        database.refresh(user)
    except IntegrityError as error:
        database.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to update user credentials",
        ) from error

    delete_user_sessions_for_user(user.id)

    return user


@router.get(
    "",
    response_model=list[UserRead],
)
def list_users(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    database: Session = Depends(get_db),
) -> list[User]:
    query = (
        select(User)
        .order_by(User.created_at.desc())
        .offset(offset)
        .limit(limit)
    )

    return list(database.scalars(query).all())


@router.get(
    "/{user_id}",
    response_model=UserRead,
)
def get_user(
    user_id: uuid.UUID,
    database: Session = Depends(get_db),
) -> User:
    user = database.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return user
