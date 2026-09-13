from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.staticfiles import StaticFiles

from app.api.auth import router as auth_router
from app.api.device_signature_requests import (
    router as device_signature_requests_router,
)
from app.api.devices import router as devices_router
from app.api.users import router as users_router
from app.api.signing import router as signing_router

from app.config import get_settings
from app.database import get_db
from app.web.routes import (
    WEB_STATIC,
    router as web_router,
)
from app.web.audit_routes import (
    router as web_audit_router,
)
from app.user_web.routes import (
    USER_WEB_STATIC,
    router as user_web_router,
)

from app.api.signatures import (
    router as signatures_router,
)

from app.api.documents import (
    router as documents_router,
)
from app.api.audit import (
    router as audit_router,
)

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description=(
        "Serveur d'authentification forte "
        "et de signature électronique distante"
    ),
    version=settings.app_version,
)


app.include_router(users_router)
app.include_router(devices_router)
app.include_router(auth_router)
app.include_router(device_signature_requests_router)
app.include_router(signing_router)
app.include_router(documents_router)
app.include_router(signatures_router)
app.include_router(audit_router)
app.mount(
    "/ui/static",
    StaticFiles(directory=WEB_STATIC),
    name="ui-static",
)
app.include_router(web_audit_router)
app.include_router(web_router)
app.mount(
    "/user/static",
    StaticFiles(directory=USER_WEB_STATIC),
    name="user-static",
)
app.include_router(user_web_router)


@app.get("/", tags=["General"])
def root() -> dict[str, str]:
    return {
        "message": settings.app_name,
        "status": "running",
    }


@app.get("/api/v1/health", tags=["Health"])
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "remotesign-lab-server",
        "version": settings.app_version,
    }


@app.get("/api/v1/health/database", tags=["Health"])
def database_health(
    database: Session = Depends(get_db),
) -> dict[str, str]:
    try:
        database.execute(text("SELECT 1"))

        return {
            "status": "ok",
            "database": "postgresql",
        }

    except SQLAlchemyError as error:
        raise HTTPException(
            status_code=503,
            detail="Database connection failed",
        ) from error
