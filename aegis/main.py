"""FastAPI application entry point."""

from fastapi import FastAPI

from aegis.api.routes.system import router as system_router
from aegis.core.config import get_settings


def create_app() -> FastAPI:
    """Create and configure the AEGIS FastAPI application."""

    settings = get_settings()
    application = FastAPI(title=settings.app_name, debug=settings.debug)
    application.include_router(system_router)
    return application


app = create_app()
