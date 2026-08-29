"""Safe local launcher for the synthetic AEGIS demonstration environment."""

from __future__ import annotations

from dataclasses import dataclass
import re
import sys
from typing import Callable

from pydantic import SecretStr, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import Engine, create_engine, text
import uvicorn

from aegis.core.config import Settings
from aegis.core.migration_config import MigrationSettings
from aegis.db.session import create_database_engine
from aegis.dev.bootstrap_demo import REQUIRED_REVISION, bootstrap_demo
from aegis.security.mfa_encryption import MfaKeyConfigurationError, MfaSecretCipher


HOST = "127.0.0.1"
PORT = 8000
_LOCAL_ENVIRONMENTS = {"development", "test"}
_TOTP_SECRET_PATTERN = re.compile(r"[A-Z2-7]{32}")


class DemoLauncherError(RuntimeError):
    """A concise launcher refusal that is safe to show to a local operator."""


class DemoLauncherSettings(BaseSettings):
    """Secrets used only by the explicit synthetic-data bootstrap."""

    demo_password: SecretStr = SecretStr("")
    demo_mfa_secret: SecretStr = SecretStr("")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="AEGIS_",
        extra="ignore",
    )


@dataclass(frozen=True, slots=True)
class DemoPreflightReport:
    environment: str
    revision: str


def create_migration_engine(settings: MigrationSettings) -> Engine:
    """Create the explicit setup engine without exposing its secret URL."""

    return create_engine(
        settings.migration_database_url.get_secret_value(),
        pool_pre_ping=True,
    )


def load_launcher_configuration(
) -> tuple[Settings, MigrationSettings, DemoLauncherSettings]:
    """Load all three deliberately separated local configuration domains."""

    try:
        runtime = Settings()
        migration = MigrationSettings()
        demo = DemoLauncherSettings()
    except ValidationError:
        raise DemoLauncherError(
            "required local database or demo configuration is missing or invalid"
        ) from None
    if not demo.demo_password.get_secret_value() or not demo.demo_mfa_secret.get_secret_value():
        raise DemoLauncherError(
            "AEGIS_DEMO_PASSWORD and AEGIS_DEMO_MFA_SECRET must be configured locally"
        )
    return runtime, migration, demo


def run_preflight(
    runtime: Settings,
    migration: MigrationSettings,
    demo: DemoLauncherSettings,
    *,
    runtime_engine_factory: Callable[[Settings], Engine] = create_database_engine,
    migration_engine_factory: Callable[[MigrationSettings], Engine] = (
        create_migration_engine
    ),
    bootstrap: Callable[..., object] = bootstrap_demo,
) -> DemoPreflightReport:
    """Validate local boundaries, reach runtime PostgreSQL, and reuse bootstrap."""

    environment = runtime.environment.strip().lower()
    if environment not in _LOCAL_ENVIRONMENTS:
        raise DemoLauncherError(
            "the local demo launcher is allowed only in development or test"
        )

    try:
        MfaSecretCipher(runtime.mfa_encryption_key, runtime.mfa_encryption_key_id)
    except MfaKeyConfigurationError:
        raise DemoLauncherError(
            "AEGIS_MFA_ENCRYPTION_KEY must be configured with a valid local Fernet key"
        ) from None

    password = demo.demo_password.get_secret_value()
    mfa_secret = demo.demo_mfa_secret.get_secret_value()
    if not _TOTP_SECRET_PATTERN.fullmatch(mfa_secret):
        raise DemoLauncherError(
            "AEGIS_DEMO_MFA_SECRET must be a 32-character unpadded Base32 secret"
        )

    runtime_engine: Engine | None = None
    try:
        runtime_engine = runtime_engine_factory(runtime)
        with runtime_engine.connect() as connection:
            connection.execute(text("SELECT 1")).scalar_one()
    except Exception:
        raise DemoLauncherError("the runtime database is not reachable") from None
    finally:
        if runtime_engine is not None:
            runtime_engine.dispose()

    setup_engine: Engine | None = None
    try:
        setup_engine = migration_engine_factory(migration)
        with setup_engine.connect() as connection:
            connection.execute(text("SELECT 1")).scalar_one()
        # bootstrap_demo verifies the exact revision and applies the existing
        # transactional, idempotent fixture through this setup-only engine.
        report = bootstrap(
            runtime,
            password,
            mfa_secret=mfa_secret,
            engine=setup_engine,
        )
    except Exception:
        raise DemoLauncherError(
            "migration/setup preflight or transactional demo bootstrap failed"
        ) from None
    finally:
        if setup_engine is not None:
            setup_engine.dispose()
    revision = getattr(report, "revision", None)
    if revision != REQUIRED_REVISION:
        raise DemoLauncherError("the database is not at the required migration revision")
    return DemoPreflightReport(environment=environment, revision=revision)


def launch_demo(
    *,
    serve: Callable[..., None] = uvicorn.run,
) -> None:
    """Run preflight, report only safe local facts, then serve on loopback."""

    runtime, migration, demo = load_launcher_configuration()
    report = run_preflight(runtime, migration, demo)
    print(f"Environment: {report.environment}")
    print("Database: reachable")
    print(f"Migration revision: {report.revision}")
    print(f"UI: http://{HOST}:{PORT}/ui")
    print(f"Health: http://{HOST}:{PORT}/health")
    serve("aegis.main:app", host=HOST, port=PORT, reload=False)


def main() -> int:
    try:
        launch_demo()
        return 0
    except DemoLauncherError as error:
        print(f"AEGIS local demo refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
