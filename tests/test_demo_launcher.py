"""Focused tests for the explicit loopback-only local demo launcher."""

from pathlib import Path
from types import SimpleNamespace

from cryptography.fernet import Fernet
from pydantic import SecretStr
import pyotp
import pytest
from sqlalchemy import create_engine

from aegis.core.config import Settings
from aegis.core.migration_config import MigrationSettings
from aegis.dev.bootstrap_demo import REQUIRED_REVISION
import aegis.dev.run_demo as launcher


@pytest.fixture(autouse=True)
def isolate_launcher_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "AEGIS_MFA_ENCRYPTION_KEY",
        "AEGIS_DEMO_PASSWORD",
        "AEGIS_DEMO_MFA_SECRET",
        "AEGIS_DATABASE_URL",
        "AEGIS_MIGRATION_DATABASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)


def runtime(*, environment: str = "development", key: str | None = None) -> Settings:
    return Settings(
        environment=environment,
        database_url="sqlite+pysqlite:///:memory:",
        session_cookie_secure=environment not in {"development", "test"},
        mfa_encryption_key=key or Fernet.generate_key().decode("ascii"),
        _env_file=None,
    )


def migration() -> MigrationSettings:
    return MigrationSettings(
        migration_database_url="sqlite+pysqlite:///:memory:",
        _env_file=None,
    )


def demo() -> launcher.DemoLauncherSettings:
    return launcher.DemoLauncherSettings(
        demo_password="Synthetic-Launcher-Password-91!",
        demo_mfa_secret=pyotp.random_base32(length=32),
        _env_file=None,
    )


def test_preflight_reaches_runtime_and_delegates_setup_to_existing_bootstrap() -> None:
    runtime_engine = create_engine("sqlite+pysqlite:///:memory:")
    setup_engine = create_engine("sqlite+pysqlite:///:memory:")
    calls = []

    def bootstrap(settings, password, *, mfa_secret, engine):
        calls.append((settings, password, mfa_secret, engine))
        return SimpleNamespace(revision=REQUIRED_REVISION)

    selected_runtime = runtime()
    selected_demo = demo()
    report = launcher.run_preflight(
        selected_runtime,
        migration(),
        selected_demo,
        runtime_engine_factory=lambda settings: runtime_engine,
        migration_engine_factory=lambda settings: setup_engine,
        bootstrap=bootstrap,
    )

    assert report == launcher.DemoPreflightReport("development", REQUIRED_REVISION)
    assert calls == [(
        selected_runtime,
        selected_demo.demo_password.get_secret_value(),
        selected_demo.demo_mfa_secret.get_secret_value(),
        setup_engine,
    )]


def test_preflight_refuses_non_local_environment_before_database_use() -> None:
    used = False

    def engine_factory(settings):
        nonlocal used
        used = True
        raise AssertionError("must not connect")

    with pytest.raises(launcher.DemoLauncherError, match="development or test"):
        launcher.run_preflight(
            runtime(environment="production"),
            migration(),
            demo(),
            runtime_engine_factory=engine_factory,
        )
    assert used is False


def test_preflight_errors_never_echo_database_or_demo_secrets() -> None:
    selected_demo = demo()
    marker = "sensitive-runtime-detail"

    def engine_factory(settings):
        raise RuntimeError(marker)

    with pytest.raises(launcher.DemoLauncherError) as exc_info:
        launcher.run_preflight(
            runtime(), migration(), selected_demo,
            runtime_engine_factory=engine_factory,
        )
    rendered = str(exc_info.value)
    assert marker not in rendered
    assert selected_demo.demo_password.get_secret_value() not in rendered
    assert selected_demo.demo_mfa_secret.get_secret_value() not in rendered


def test_missing_configuration_ignores_interactive_shell_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(launcher.DemoLauncherError, match="missing or invalid"):
        launcher.load_launcher_configuration()


def test_launch_reports_only_safe_facts_and_binds_loopback(monkeypatch, capsys) -> None:
    configured = (runtime(), migration(), demo())
    monkeypatch.setattr(launcher, "load_launcher_configuration", lambda: configured)
    monkeypatch.setattr(
        launcher,
        "run_preflight",
        lambda *args: launcher.DemoPreflightReport("development", REQUIRED_REVISION),
    )
    calls = []
    launcher.launch_demo(serve=lambda *args, **kwargs: calls.append((args, kwargs)))

    output = capsys.readouterr().out
    assert "Environment: development" in output
    assert "Database: reachable" in output
    assert f"Migration revision: {REQUIRED_REVISION}" in output
    assert "http://127.0.0.1:8000/ui" in output
    assert "http://127.0.0.1:8000/health" in output
    for value in (
        configured[2].demo_password.get_secret_value(),
        configured[2].demo_mfa_secret.get_secret_value(),
        configured[0].mfa_encryption_key.get_secret_value(),
        configured[0].database_url,
        configured[1].migration_database_url.get_secret_value(),
    ):
        assert value not in output
    assert calls == [(('aegis.main:app',), {
        "host": "127.0.0.1", "port": 8000, "reload": False
    })]
