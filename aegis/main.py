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
from aegis.security.authentication_abuse import AuthenticationAbuseControl
from aegis.security.abuse import AbuseDecisionStatus
from aegis.security.authentication_events import AuthenticationRequestContext
from aegis.security.availability_abuse import AvailabilityAbuseControl
import uuid


_PACKAGE_ROOT = Path(__file__).resolve().parent


def create_app() -> FastAPI:
    """Create and configure the AEGIS FastAPI application."""

    settings = get_settings()
    application = FastAPI(title=settings.app_name, debug=settings.debug)
    application.state.authentication_abuse_control = AuthenticationAbuseControl.create_local()
    application.state.availability_abuse_control = AvailabilityAbuseControl.create_local()

    @application.middleware("http")
    async def protect_public_availability(request: Request, call_next):
        public_path = (
            request.url.path
            in {
                "/",
                "/ui",
                "/ui/",
                "/docs",
                "/docs/",
                "/docs/oauth2-redirect",
                "/docs/oauth2-redirect/",
                "/redoc",
                "/redoc/",
                "/openapi.json",
            }
            or request.url.path.startswith("/static/")
        )
        if request.method in {"GET", "HEAD"} and public_path:
            context = AuthenticationRequestContext(
                request_id=uuid.uuid4(),
                source_ip=request.client.host if request.client is not None else None,
            )
            decision = application.state.availability_abuse_control.admit_public(
                context
            )
            if decision.status is AbuseDecisionStatus.LIMITED:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Request temporarily unavailable"},
                    headers={
                        "Cache-Control": "no-store",
                        "Retry-After": str(decision.retry_after_seconds),
                    },
                )
            # Cheap public routes fail open only for expected bounded-store
            # unavailability. Programming errors are intentionally not caught.
        return await call_next(request)
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
