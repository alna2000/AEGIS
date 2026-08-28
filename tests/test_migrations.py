"""Alembic migration smoke tests against an isolated disposable database."""

from datetime import datetime, timezone
from pathlib import Path
import uuid

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import MetaData, Table, create_engine, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import make_url


def test_environment_database_url_supports_percent_without_credential_output(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    synthetic_password = "synthetic%credential"
    encoded_synthetic_password = "synthetic%25credential"
    database_url = (
        f"postgresql+psycopg://synthetic_user:{encoded_synthetic_password}"
        "@db.invalid/synthetic_db"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AEGIS_MIGRATION_DATABASE_URL", database_url)

    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option("script_location", str(project_root / "migrations"))
    command.upgrade(config, "head", sql=True)

    configured_url = config.get_main_option("sqlalchemy.url")
    captured = capsys.readouterr()
    assert "CREATE TABLE audit_events" in captured.out
    assert "MFA_CHALLENGE_ISSUED" in captured.out
    assert "LOGOUT_SUCCEEDED" in captured.out
    assert "RESOURCE_COLLECTION_READ" in captured.out
    assert configured_url == database_url
    assert make_url(configured_url).password == synthetic_password
    assert database_url not in captured.out
    assert database_url not in captured.err
    assert synthetic_password not in captured.out
    assert synthetic_password not in captured.err
    assert encoded_synthetic_password not in captured.out
    assert encoded_synthetic_password not in captured.err


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
        "department_id",
        "clearance_level_id",
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
        "failed_factor_attempts",
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
        "ck_mfa_challenges_failed_factor_attempts_bounded",
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
    assert {
        "roles",
        "departments",
        "clearance_levels",
        "compartments",
        "user_roles",
        "user_compartments",
        "intelligence_records",
        "record_departments",
        "record_compartments",
    } <= set(inspector.get_table_names())

    user_columns = {
        column["name"]: column for column in inspector.get_columns("users")
    }
    assert user_columns["department_id"]["nullable"] is True
    assert user_columns["clearance_level_id"]["nullable"] is True
    user_authorization_foreign_keys = {
        tuple(foreign_key["constrained_columns"]): foreign_key
        for foreign_key in inspector.get_foreign_keys("users")
        if foreign_key["constrained_columns"]
        in (["department_id"], ["clearance_level_id"])
    }
    assert user_authorization_foreign_keys[("department_id",)][
        "referred_table"
    ] == "departments"
    assert user_authorization_foreign_keys[("department_id",)]["options"][
        "ondelete"
    ] == "RESTRICT"
    assert user_authorization_foreign_keys[("clearance_level_id",)][
        "referred_table"
    ] == "clearance_levels"
    assert user_authorization_foreign_keys[("clearance_level_id",)]["options"][
        "ondelete"
    ] == "RESTRICT"

    clearance_uniques = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints("clearance_levels")
    }
    assert {("name",), ("rank",)} <= clearance_uniques
    clearance_checks = {
        constraint["name"]
        for constraint in inspector.get_check_constraints("clearance_levels")
    }
    assert {
        "ck_clearance_levels_name_rank_controlled",
        "ck_clearance_levels_rank_positive",
    } <= clearance_checks

    assert tuple(
        inspector.get_pk_constraint("user_roles")["constrained_columns"]
    ) == ("user_id", "role_id")
    assert tuple(
        inspector.get_pk_constraint("user_compartments")["constrained_columns"]
    ) == ("user_id", "compartment_id")
    assert inspector.get_indexes("user_roles") == [
        {
            "name": "ix_user_roles_role_id",
            "column_names": ["role_id"],
            "unique": 0,
            "dialect_options": {},
        }
    ]
    assert inspector.get_indexes("user_compartments") == [
        {
            "name": "ix_user_compartments_compartment_id",
            "column_names": ["compartment_id"],
            "unique": 0,
            "dialect_options": {},
        }
    ]
    for table_name in ("user_roles", "user_compartments"):
        assignment_foreign_keys = inspector.get_foreign_keys(table_name)
        assert assignment_foreign_keys
        assert all(
            foreign_key["options"].get("ondelete") == "RESTRICT"
            for foreign_key in assignment_foreign_keys
        )

    metadata = MetaData()
    roles = Table("roles", metadata, autoload_with=engine)
    departments = Table("departments", metadata, autoload_with=engine)
    clearances = Table("clearance_levels", metadata, autoload_with=engine)
    compartments = Table("compartments", metadata, autoload_with=engine)
    with engine.connect() as connection:
        assert set(connection.scalars(select(roles.c.name))) == {
            "Analyst",
            "Senior Analyst",
            "Supervisor",
            "Security Auditor",
            "System Administrator",
        }
        assert set(connection.scalars(select(roles.c.is_active))) == {True}
        assert set(connection.scalars(select(departments.c.name))) == {
            "Cyber Intelligence",
            "Counterintelligence",
            "Strategic Analysis",
            "Operations",
        }
        assert set(connection.scalars(select(departments.c.is_active))) == {True}
        clearance_rows = connection.execute(
            select(clearances.c.name, clearances.c.rank)
        )
        assert set(clearance_rows) == {
            ("UNCLASSIFIED", 10),
            ("CONFIDENTIAL", 20),
            ("SECRET", 30),
            ("TOP SECRET", 40),
        }
        assert set(connection.scalars(select(compartments.c.name))) == {
            "NIGHTFALL",
            "ORION",
            "SENTINEL",
        }
        assert set(connection.scalars(select(compartments.c.is_active))) == {True}

    record_columns = {
        column["name"]: column
        for column in inspector.get_columns("intelligence_records")
    }
    assert set(record_columns) == {
        "id",
        "record_code",
        "title",
        "summary",
        "content",
        "classification_level_id",
        "created_by_user_id",
        "status",
        "created_at",
        "updated_at",
        "retired_at",
    }
    assert record_columns["classification_level_id"]["nullable"] is False
    assert record_columns["created_by_user_id"]["nullable"] is False
    record_uniques = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints(
            "intelligence_records"
        )
    }
    assert ("record_code",) in record_uniques
    record_checks = {
        constraint["name"]
        for constraint in inspector.get_check_constraints(
            "intelligence_records"
        )
    }
    assert {
        "ck_intelligence_records_record_code_canonical",
        "ck_intelligence_records_title_length",
        "ck_intelligence_records_summary_length",
        "ck_intelligence_records_content_length",
        "ck_intelligence_records_status_controlled",
        "ck_intelligence_records_updated_after_creation",
        "ck_intelligence_records_lifecycle_consistent",
    } <= record_checks
    record_foreign_keys = {
        tuple(foreign_key["constrained_columns"]): foreign_key
        for foreign_key in inspector.get_foreign_keys("intelligence_records")
    }
    assert record_foreign_keys[("classification_level_id",)][
        "referred_table"
    ] == "clearance_levels"
    assert record_foreign_keys[("created_by_user_id",)]["referred_table"] == (
        "users"
    )
    assert all(
        foreign_key["options"].get("ondelete") == "RESTRICT"
        for foreign_key in record_foreign_keys.values()
    )
    record_indexes = {
        index["name"]: tuple(index["column_names"])
        for index in inspector.get_indexes("intelligence_records")
    }
    assert record_indexes[
        "ix_intelligence_records_classification_level_id"
    ] == ("classification_level_id",)
    assert record_indexes["ix_intelligence_records_created_by_user_id"] == (
        "created_by_user_id",
    )

    for table_name, reference_column, reverse_index in (
        (
            "record_departments",
            "department_id",
            "ix_record_departments_department_id",
        ),
        (
            "record_compartments",
            "compartment_id",
            "ix_record_compartments_compartment_id",
        ),
    ):
        assert tuple(
            inspector.get_pk_constraint(table_name)["constrained_columns"]
        ) == ("record_id", reference_column)
        relationship_foreign_keys = inspector.get_foreign_keys(table_name)
        assert len(relationship_foreign_keys) == 2
        assert all(
            foreign_key["options"].get("ondelete") == "RESTRICT"
            for foreign_key in relationship_foreign_keys
        )
        relationship_indexes = {
            index["name"]: tuple(index["column_names"])
            for index in inspector.get_indexes(table_name)
        }
        assert relationship_indexes == {reverse_index: (reference_column,)}
    engine.dispose()

    command.downgrade(config, "base")

    engine = create_engine(database_url)
    assert "users" not in inspect(engine).get_table_names()
    engine.dispose()

def test_authorization_migration_preserves_existing_phase_2_user_and_downgrades(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase2-upgrade.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "20260822_0004")

    engine = create_engine(database_url)
    users = Table("users", MetaData(), autoload_with=engine)
    user_id = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    now = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
    with engine.begin() as connection:
        connection.execute(
            users.insert().values(
                id=user_id.hex,
                username="synthetic.legacy",
                display_name="Synthetic Legacy User",
                email=None,
                password_hash="synthetic-nonempty-verifier",
                is_active=True,
                created_at=now,
                updated_at=now,
                disabled_at=None,
            )
        )
    engine.dispose()


    command.upgrade(config, "20260822_0005")
    engine = create_engine(database_url)
    upgraded_users = Table("users", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        row = connection.execute(
            select(
                upgraded_users.c.department_id,
                upgraded_users.c.clearance_level_id,
            ).where(upgraded_users.c.id == user_id.hex)
        ).one()
    assert row.department_id is None
    assert row.clearance_level_id is None
    engine.dispose()

    command.downgrade(config, "20260822_0004")
    engine = create_engine(database_url)
    downgraded_inspector = inspect(engine)
    assert "roles" not in downgraded_inspector.get_table_names()
    assert "user_roles" not in downgraded_inspector.get_table_names()
    assert {
        column["name"] for column in downgraded_inspector.get_columns("users")
    } == {
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
    engine.dispose()


def test_intelligence_record_migration_upgrades_part_1_and_downgrades(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "part1-record-upgrade.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "20260822_0005")

    engine = create_engine(database_url)
    assert "roles" in inspect(engine).get_table_names()
    assert "intelligence_records" not in inspect(engine).get_table_names()
    engine.dispose()

    command.upgrade(config, "20260823_0006")
    engine = create_engine(database_url)
    upgraded_tables = set(inspect(engine).get_table_names())
    assert {
        "intelligence_records",
        "record_departments",
        "record_compartments",
    } <= upgraded_tables
    engine.dispose()

    command.downgrade(config, "20260822_0005")
    engine = create_engine(database_url)
    downgraded_tables = set(inspect(engine).get_table_names())
    assert "intelligence_records" not in downgraded_tables
    assert "record_departments" not in downgraded_tables
    assert "record_compartments" not in downgraded_tables
    assert "roles" in downgraded_tables
    engine.dispose()


def test_mfa_failure_bound_migration_round_trips_only_its_column(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "mfa-failure-bound-round-trip.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "20260823_0006")

    engine = create_engine(database_url)
    before_tables = set(inspect(engine).get_table_names())
    before_columns = {
        column["name"] for column in inspect(engine).get_columns("mfa_challenges")
    }
    assert "failed_factor_attempts" not in before_columns
    engine.dispose()

    command.upgrade(config, "20260826_0007")
    engine = create_engine(database_url)
    inspector = inspect(engine)
    columns = {column["name"]: column for column in inspector.get_columns("mfa_challenges")}
    added = columns["failed_factor_attempts"]
    assert added["nullable"] is False
    assert str(added["default"]).strip("'\"()") == "0"
    checks = {
        constraint["name"]: constraint["sqltext"]
        for constraint in inspector.get_check_constraints("mfa_challenges")
    }
    assert checks["ck_mfa_challenges_failed_factor_attempts_bounded"] == (
        "failed_factor_attempts BETWEEN 0 AND 5"
    )
    assert set(inspector.get_table_names()) == before_tables
    engine.dispose()

    command.downgrade(config, "20260823_0006")
    engine = create_engine(database_url)
    inspector = inspect(engine)
    assert {
        column["name"] for column in inspector.get_columns("mfa_challenges")
    } == before_columns
    assert set(inspector.get_table_names()) == before_tables
    engine.dispose()


def test_audit_event_migration_adds_controlled_append_schema_and_downgrades(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "audit-event-round-trip.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "20260826_0007")

    engine = create_engine(database_url)
    assert "audit_events" not in inspect(engine).get_table_names()
    engine.dispose()

    command.upgrade(config, "20260827_0008")
    engine = create_engine(database_url)
    inspector = inspect(engine)
    assert {column["name"] for column in inspector.get_columns("audit_events")} == {
        "id",
        "occurred_at",
        "event_code",
        "outcome",
        "severity",
        "actor_type",
        "actor_user_id",
        "subject_user_id",
        "target_type",
        "target_id",
        "action",
        "reason_code",
        "request_id",
        "source_correlation",
        "source_key_id",
    }
    assert tuple(inspector.get_pk_constraint("audit_events")["constrained_columns"]) == (
        "id",
    )
    foreign_keys = {
        tuple(item["constrained_columns"]): item
        for item in inspector.get_foreign_keys("audit_events")
    }
    assert foreign_keys[("actor_user_id",)]["referred_table"] == "users"
    assert foreign_keys[("subject_user_id",)]["referred_table"] == "users"
    assert all(item["options"].get("ondelete") == "RESTRICT" for item in foreign_keys.values())
    check_names = {
        item["name"] for item in inspector.get_check_constraints("audit_events")
    }
    assert {
        "ck_audit_events_event_code_controlled",
        "ck_audit_events_outcome_controlled",
        "ck_audit_events_severity_controlled",
        "ck_audit_events_actor_type_controlled",
        "ck_audit_events_action_controlled",
        "ck_audit_events_target_type_controlled",
        "ck_audit_events_reason_code_controlled",
        "ck_audit_events_actor_identity_consistent",
        "ck_audit_events_subject_distinct",
        "ck_audit_events_target_consistent",
        "ck_audit_events_request_context_consistent",
        "ck_audit_events_source_consistent",
    } <= check_names
    indexes = {
        item["name"]: tuple(item["column_names"])
        for item in inspector.get_indexes("audit_events")
    }
    assert indexes == {
        "ix_audit_events_actor_occurred": ("actor_user_id", "occurred_at"),
        "ix_audit_events_code_occurred": ("event_code", "occurred_at"),
        "ix_audit_events_occurred_id": ("occurred_at", "id"),
        "ix_audit_events_request_id": ("request_id",),
    }
    engine.dispose()

    command.downgrade(config, "20260826_0007")
    engine = create_engine(database_url)
    assert "audit_events" not in inspect(engine).get_table_names()
    assert "mfa_challenges" in inspect(engine).get_table_names()
    engine.dispose()


def test_part_2_audit_code_extension_round_trips_only_the_constraint(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "part2-audit-code-round-trip.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "20260827_0008")

    engine = create_engine(database_url)
    before = inspect(engine)
    before_columns = {
        column["name"] for column in before.get_columns("audit_events")
    }
    before_indexes = {
        item["name"]: tuple(item["column_names"])
        for item in before.get_indexes("audit_events")
    }
    audit_events = Table("audit_events", MetaData(), autoload_with=engine)
    base_values = {
        "occurred_at": datetime(2026, 8, 27, 15, 0, tzinfo=timezone.utc),
        "outcome": "SUCCESS",
        "severity": "INFORMATIONAL",
        "actor_type": "SYSTEM",
        "actor_user_id": None,
        "subject_user_id": None,
        "target_type": None,
        "target_id": None,
        "action": "VERIFY_MFA",
        "reason_code": None,
        "request_id": uuid.uuid4().hex,
        "source_correlation": None,
        "source_key_id": None,
    }
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            audit_events.insert().values(
                id=uuid.uuid4().hex,
                event_code="MFA_CHALLENGE_ISSUED",
                **base_values,
            )
        )
    engine.dispose()


    command.upgrade(config, "20260827_0009")
    engine = create_engine(database_url)
    inspector = inspect(engine)
    assert {column["name"] for column in inspector.get_columns("audit_events")} == before_columns
    assert {
        item["name"]: tuple(item["column_names"])
        for item in inspector.get_indexes("audit_events")
    } == before_indexes
    audit_events = Table("audit_events", MetaData(), autoload_with=engine)
    with engine.begin() as connection:
        connection.execute(
            audit_events.insert(),
            [
                {
                    "id": uuid.uuid4().hex,
                    "event_code": "MFA_CHALLENGE_ISSUED",
                    **base_values,
                },
                {
                    "id": uuid.uuid4().hex,
                    "event_code": "LOGOUT_SUCCEEDED",
                    "action": "REVOKE_SESSION",
                    **{key: value for key, value in base_values.items() if key != "action"},
                },
            ],
        )
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            audit_events.insert().values(
                id=uuid.uuid4().hex, event_code="SPECULATIVE_EVENT", **base_values
            )
        )
    with engine.begin() as connection:
        connection.execute(audit_events.delete())
    engine.dispose()

    command.downgrade(config, "20260827_0008")
    engine = create_engine(database_url)
    audit_events = Table("audit_events", MetaData(), autoload_with=engine)
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            audit_events.insert().values(
                id=uuid.uuid4().hex,
                event_code="LOGOUT_SUCCEEDED",
                action="REVOKE_SESSION",
                **{key: value for key, value in base_values.items() if key != "action"},
            )
        )
    engine.dispose()


def test_part_3_collection_code_round_trips_only_the_constraint(tmp_path: Path) -> None:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'part3-audit.sqlite3').as_posix()}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "20260827_0009")
    engine = create_engine(database_url)
    before = inspect(engine)
    columns = tuple(column["name"] for column in before.get_columns("audit_events"))
    indexes = {item["name"]: tuple(item["column_names"]) for item in before.get_indexes("audit_events")}
    engine.dispose()

    command.upgrade(config, "20260827_0010")
    engine = create_engine(database_url)
    after = inspect(engine)
    assert tuple(column["name"] for column in after.get_columns("audit_events")) == columns
    assert {item["name"]: tuple(item["column_names"]) for item in after.get_indexes("audit_events")} == indexes
    table = Table("audit_events", MetaData(), autoload_with=engine)
    values = {
        "id": uuid.uuid4().hex,
        "occurred_at": datetime(2026, 8, 27, 16, 0, tzinfo=timezone.utc),
        "event_code": "RESOURCE_COLLECTION_READ",
        "outcome": "SUCCESS",
        "severity": "INFORMATIONAL",
        "actor_type": "SYSTEM",
        "action": "READ_RESOURCE",
    }
    with engine.begin() as connection:
        connection.execute(table.insert().values(**values))
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(table.insert().values(**{**values, "id": uuid.uuid4().hex, "event_code": "AUDIT_QUERY_EXECUTED"}))
    with engine.begin() as connection:
        connection.execute(table.delete())
    engine.dispose()

    command.downgrade(config, "20260827_0009")
    engine = create_engine(database_url)
    table = Table("audit_events", MetaData(), autoload_with=engine)
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(table.insert().values(**values))
    engine.dispose()
