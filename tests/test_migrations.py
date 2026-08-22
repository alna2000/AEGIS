"""Alembic migration smoke tests against an isolated disposable database."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_authentication_migrations_upgrade_and_downgrade(tmp_path: Path) -> None:
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
    assert "sessions" in inspector.get_table_names()
    assert {column["name"] for column in inspector.get_columns("sessions")} == {
        "id",
        "user_id",
        "token_hash",
        "created_at",
        "expires_at",
        "last_seen_at",
        "revoked_at",
        "source_ip",
        "user_agent",
    }
    session_unique_columns = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints("sessions")
    }
    assert ("token_hash",) in session_unique_columns
    session_checks = {
        constraint["name"] for constraint in inspector.get_check_constraints("sessions")
    }
    assert {
        "ck_sessions_expiry_after_creation",
        "ck_sessions_last_seen_after_creation",
        "ck_sessions_revoked_after_creation",
        "ck_sessions_token_hash_format",
    } <= session_checks
    session_foreign_keys = inspector.get_foreign_keys("sessions")
    assert len(session_foreign_keys) == 1
    assert session_foreign_keys[0]["referred_table"] == "users"
    assert session_foreign_keys[0]["constrained_columns"] == ["user_id"]
    session_indexes = {
        index["name"]: tuple(index["column_names"])
        for index in inspector.get_indexes("sessions")
    }
    assert session_indexes["ix_sessions_expires_at"] == ("expires_at",)
    assert session_indexes["ix_sessions_user_lifecycle"] == (
        "user_id",
        "revoked_at",
        "expires_at",
    )
    assert "mfa_credentials" in inspector.get_table_names()
    assert {
        column["name"] for column in inspector.get_columns("mfa_credentials")
    } == {
        "id",
        "user_id",
        "method_type",
        "encrypted_secret",
        "encryption_key_id",
        "enabled",
        "created_at",
        "last_used_at",
        "disabled_at",
        "last_accepted_counter",
    }
    mfa_checks = {
        constraint["name"]
        for constraint in inspector.get_check_constraints("mfa_credentials")
    }
    assert {
        "ck_mfa_credentials_method_type",
        "ck_mfa_credentials_encrypted_secret_not_empty",
        "ck_mfa_credentials_key_id_length",
        "ck_mfa_credentials_enabled_not_disabled",
        "ck_mfa_credentials_last_used_after_creation",
        "ck_mfa_credentials_disabled_after_creation",
        "ck_mfa_credentials_counter_nonnegative",
        "ck_mfa_credentials_usage_state_complete",
    } <= mfa_checks
    mfa_foreign_keys = inspector.get_foreign_keys("mfa_credentials")
    assert len(mfa_foreign_keys) == 1
    assert mfa_foreign_keys[0]["referred_table"] == "users"
    assert mfa_foreign_keys[0]["constrained_columns"] == ["user_id"]
    mfa_indexes = {
        index["name"]: index for index in inspector.get_indexes("mfa_credentials")
    }
    assert mfa_indexes["uq_mfa_credentials_non_disabled_totp_user"]["unique"] == 1
    assert "mfa_challenges" in inspector.get_table_names()
    assert {
        column["name"] for column in inspector.get_columns("mfa_challenges")
    } == {
        "id",
        "user_id",
        "token_hash",
        "created_at",
        "expires_at",
        "consumed_at",
        "revoked_at",
        "source_ip",
        "user_agent",
    }
    challenge_unique_columns = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints("mfa_challenges")
    }
    assert ("token_hash",) in challenge_unique_columns
    challenge_checks = {
        constraint["name"]
        for constraint in inspector.get_check_constraints("mfa_challenges")
    }
    assert {
        "ck_mfa_challenges_token_hash_format",
        "ck_mfa_challenges_expiry_after_creation",
        "ck_mfa_challenges_consumed_after_creation",
        "ck_mfa_challenges_revoked_after_creation",
        "ck_mfa_challenges_single_terminal_state",
    } <= challenge_checks
    challenge_foreign_keys = inspector.get_foreign_keys("mfa_challenges")
    assert len(challenge_foreign_keys) == 1
    assert challenge_foreign_keys[0]["referred_table"] == "users"
    challenge_indexes = {
        index["name"]: tuple(index["column_names"])
        for index in inspector.get_indexes("mfa_challenges")
    }
    assert challenge_indexes["ix_mfa_challenges_expires_at"] == ("expires_at",)
    assert challenge_indexes["ix_mfa_challenges_user_lifecycle"] == (
        "user_id",
        "consumed_at",
        "revoked_at",
        "expires_at",
    )
    engine.dispose()

    command.downgrade(config, "base")

    engine = create_engine(database_url)
    assert "users" not in inspect(engine).get_table_names()
    engine.dispose()
