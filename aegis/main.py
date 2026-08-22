"""FastAPI application entry point."""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import JSONResponse

from aegis.api.routes.authentication import router as authentication_router
from aegis.api.routes.system import router as system_router
from aegis.core.config import get_settings


def create_app() -> FastAPI:
    """Create and configure the AEGIS FastAPI application."""

    settings = get_settings()
    application = FastAPI(title=settings.app_name, debug=settings.debug)
    application.include_router(system_router)
    application.include_router(authentication_router)

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
        return await request_validation_exception_handler(request, exc)

    return application


app = create_app()
