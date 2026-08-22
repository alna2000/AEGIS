"""Public system and health endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends

from aegis.core.config import Settings, get_settings

router = APIRouter(tags=["system"])


@router.get("/")
def read_system_status(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, str]:
    """Return the current application status."""

    return {
        "name": settings.app_name,
        "status": settings.environment.title(),
        "api": "Available",
    }


@router.get("/health")
def read_health() -> dict[str, str]:
    """Return a minimal process health response."""

    return {"status": "ok"}
