"""Alembic migration smoke tests against an isolated disposable database."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_authentication_migration_upgrades_and_downgrades(tmp_path: Path) -> None:
    database_path = tmp_path / "migration-test.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_engine(database_url)
    inspector = inspect(engine)
    assert "users" in inspector.get_table_names()
    assert {column["name"] for column in inspector.get_columns("users")} == {
        "id",
        "username",
        "display_name",
        "email",
        "password_hash",
        "is_active",
        "created_at",
        "updated_at",
        "disabled_at",
    }
    unique_columns = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints("users")
    }
    assert ("username",) in unique_columns
    assert ("email",) in unique_columns
    check_names = {
        constraint["name"] for constraint in inspector.get_check_constraints("users")
    }
    assert {
        "ck_users_active_not_disabled",
        "ck_users_display_name_length",
        "ck_users_email_canonical",
        "ck_users_password_hash_not_empty",
        "ck_users_username_canonical",
        "ck_users_username_length",
    } <= check_names
    engine.dispose()

    command.downgrade(config, "base")

    engine = create_engine(database_url)
    assert "users" not in inspect(engine).get_table_names()
    engine.dispose()
