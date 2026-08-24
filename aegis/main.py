"""FastAPI application entry point."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from aegis.api.routes.authentication import router as authentication_router
from aegis.api.routes.intelligence_records import (
    router as intelligence_records_router,
)
from aegis.api.routes.system import router as system_router
from aegis.api.routes.ui import router as ui_router
from aegis.core.config import get_settings


_PACKAGE_ROOT = Path(__file__).resolve().parent


def create_app() -> FastAPI:
    """Create and configure the AEGIS FastAPI application."""

    settings = get_settings()
    application = FastAPI(title=settings.app_name, debug=settings.debug)
    application.include_router(system_router)
    application.include_router(authentication_router)
    application.include_router(intelligence_records_router)
    application.include_router(ui_router)
    application.mount(
        "/static",
        StaticFiles(directory=_PACKAGE_ROOT / "static"),
        name="static",
    )

    @application.exception_handler(RequestValidationError)
    async def sanitized_login_validation_error(
        request: Request,
        exc: RequestValidationError,
    ):
        # FastAPI's normal validation detail can echo rejected input. Password
        # login instead preserves the same small public credential-failure shape.
        if request.url.path == "/auth/login":
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid username or password"},
            )
        if request.url.path == "/auth/mfa/totp/verify":
            return JSONResponse(
                status_code=401,
                content={"detail": "MFA verification failed"},
            )
        return await request_validation_exception_handler(request, exc)

    return application


app = create_app()
