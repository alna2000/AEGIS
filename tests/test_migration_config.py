"""Migration credentials remain explicit and separate from runtime settings."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from pydantic import SecretStr, ValidationError
import pytest

from aegis.core.config import Settings
from aegis.core.migration_config import MigrationSettings


def test_migration_url_is_required_and_never_falls_back_to_runtime(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AEGIS_MIGRATION_DATABASE_URL", raising=False)
    monkeypatch.setenv(
        "AEGIS_DATABASE_URL", "postgresql+psycopg://runtime.invalid/runtime"
    )
    with pytest.raises(ValidationError):
        MigrationSettings()

    project_root = Path(__file__).resolve().parents[1]
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option("script_location", str(project_root / "migrations"))
    with pytest.raises(ValidationError):
        command.upgrade(config, "head", sql=True)


def test_runtime_settings_do_not_expose_migration_credentials(monkeypatch) -> None:
    monkeypatch.setenv(
        "AEGIS_MIGRATION_DATABASE_URL",
        "postgresql+psycopg://setup.invalid/setup",
    )
    runtime = Settings(_env_file=None)
    assert "migration_database_url" not in type(runtime).model_fields
    assert not hasattr(runtime, "migration_database_url")


def test_migration_url_is_secret_and_explicit_configuration_still_works(
    tmp_path: Path, monkeypatch
) -> None:
    migration_url = "postgresql+psycopg://setup.invalid/setup"
    monkeypatch.setenv("AEGIS_MIGRATION_DATABASE_URL", migration_url)
    configured = MigrationSettings(_env_file=None)
    assert isinstance(configured.migration_database_url, SecretStr)
    assert migration_url not in repr(configured)

    database_url = f"sqlite+pysqlite:///{(tmp_path / 'explicit.sqlite3').as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
