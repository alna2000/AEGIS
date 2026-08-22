"""Tests for the minimal AEGIS application."""

from fastapi.testclient import TestClient

from aegis.core.config import Settings, get_settings
from aegis.main import app


def get_test_settings() -> Settings:
    """Return defaults without reading a developer's local .env file."""

    return Settings(_env_file=None)


app.dependency_overrides[get_settings] = get_test_settings
client = TestClient(app)


def test_root_returns_application_status() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "name": "AEGIS",
        "status": "Development",
        "api": "Available",
    }


def test_health_reports_ok() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
