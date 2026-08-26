"""Security and real-flow tests for the explicit synthetic demo bootstrap."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session

from aegis.api.dependencies import get_db_session
from aegis.core.config import Settings, get_settings
from aegis.db.models import (
    ClearanceLevel, Compartment, Department, IntelligenceRecord,
    RecordCompartment, RecordDepartment, Role, User, UserCompartment, UserRole,
)
from aegis.dev.bootstrap_demo import (
    RECORDS, REQUIRED_REVISION, USERS, DemoBootstrapError, bootstrap_demo,
)
from aegis.main import create_app
from aegis.security.audit_sinks import LoggingAuthenticationAuditSink
from aegis.security.authentication_events import AuthenticationRequestContext
from aegis.security.passwords import PasswordService
from aegis.services.authentication import AuthenticationService, LoginAttemptStatus
from aegis.db.repositories import UserRepository


PASSWORD = "Synthetic-Demo-Password-84!"


def settings(environment: str = "test") -> Settings:
    return Settings(
        environment=environment,
        database_url="sqlite+pysqlite:///:memory:",
        session_cookie_secure=environment not in {"development", "test"},
        _env_file=None,
    )


def prepare_database(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
            {"revision": REQUIRED_REVISION},
        )
    with Session(engine) as session, session.begin():
        session.add_all(
            [
                Role(id=uuid.UUID("30000000-0000-0000-0000-000000000001"), name="Analyst", is_active=True),
                Department(id=uuid.UUID("31000000-0000-0000-0000-000000000001"), name="Cyber Intelligence", is_active=True),
                Department(id=uuid.UUID("31000000-0000-0000-0000-000000000003"), name="Strategic Analysis", is_active=True),
                ClearanceLevel(id=uuid.UUID("32000000-0000-0000-0000-000000000002"), name="CONFIDENTIAL", rank=20),
                ClearanceLevel(id=uuid.UUID("32000000-0000-0000-0000-000000000003"), name="SECRET", rank=30),
                ClearanceLevel(id=uuid.UUID("32000000-0000-0000-0000-000000000004"), name="TOP SECRET", rank=40),
                Compartment(id=uuid.UUID("33000000-0000-0000-0000-000000000001"), name="NIGHTFALL", is_active=True),
                Compartment(id=uuid.UUID("33000000-0000-0000-0000-000000000002"), name="ORION", is_active=True),
            ]
        )


@pytest.fixture
def demo_engine(db_session: Session) -> Engine:
    engine = db_session.get_bind()
    assert isinstance(engine, Engine)
    prepare_database(engine)
    return engine


def test_refuses_non_local_environment_before_database_use() -> None:
    with pytest.raises(DemoBootstrapError, match="only in development or test"):
        bootstrap_demo(settings("production"), PASSWORD)


def test_refuses_wrong_or_missing_schema_before_writes(db_session: Session) -> None:
    engine = db_session.get_bind()
    assert isinstance(engine, Engine)
    with pytest.raises(DemoBootstrapError, match="no Alembic revision"):
        bootstrap_demo(settings(), PASSWORD, engine=engine)
    assert db_session.scalar(select(func.count()).select_from(User)) == 0


def test_refuses_prior_phase_head_without_weakening_exact_revision_guard(
    db_session: Session,
) -> None:
    engine = db_session.get_bind()
    assert isinstance(engine, Engine)
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        )
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES ('20260823_0006')")
        )
    with pytest.raises(DemoBootstrapError, match=REQUIRED_REVISION):
        bootstrap_demo(settings(), PASSWORD, engine=engine)
    assert db_session.scalar(select(func.count()).select_from(User)) == 0


def test_creates_hashed_users_assignments_and_policy_matrix(demo_engine: Engine) -> None:
    report = bootstrap_demo(settings(), PASSWORD, engine=demo_engine)
    assert len(report.created) == len(USERS) + len(RECORDS)
    with Session(demo_engine) as session:
        primary = session.scalar(select(User).where(User.username == "demo.analyst"))
        limited = session.scalar(select(User).where(User.username == "demo.limited"))
        assert primary is not None and limited is not None
        assert primary.password_hash != PASSWORD
        assert PASSWORD not in primary.password_hash
        assert PasswordService().verify(PASSWORD, primary.password_hash)
        assert primary.department.name == "Cyber Intelligence"
        assert primary.clearance_level.name == "SECRET"
        assert {item.role.name for item in primary.role_assignments} == {"Analyst"}
        assert {item.compartment.name for item in primary.compartment_assignments} == {"NIGHTFALL"}
        assert limited.clearance_level.name == "CONFIDENTIAL"
        assert limited.compartment_assignments == []
        assert session.scalar(select(func.count()).select_from(IntelligenceRecord)) == 5
        assert session.scalar(select(func.count()).select_from(RecordDepartment)) == 5
        assert session.scalar(select(func.count()).select_from(RecordCompartment)) == 3
        policies = {
            record.record_code: (
                record.classification_level.name,
                {item.department.name for item in record.department_assignments},
                {item.compartment.name for item in record.compartment_assignments},
            )
            for record in session.scalars(select(IntelligenceRecord))
        }
        assert policies == {
            "INT-90001": ("CONFIDENTIAL", {"Cyber Intelligence"}, set()),
            "INT-90002": ("SECRET", {"Cyber Intelligence"}, {"NIGHTFALL"}),
            "INT-90003": ("TOP SECRET", {"Cyber Intelligence"}, {"NIGHTFALL"}),
            "INT-90004": ("SECRET", {"Strategic Analysis"}, set()),
            "INT-90005": ("SECRET", {"Cyber Intelligence"}, {"ORION"}),
        }
        creator_denied = session.scalar(select(IntelligenceRecord).where(IntelligenceRecord.record_code == "INT-90003"))
        assert creator_denied is not None and creator_denied.created_by_user_id == primary.id


def test_real_authentication_service_accepts_demo_password(demo_engine: Engine) -> None:
    bootstrap_demo(settings(), PASSWORD, engine=demo_engine)
    with Session(demo_engine) as session:
        result = AuthenticationService(
            UserRepository(session), PasswordService(), LoggingAuthenticationAuditSink()
        ).attempt_login(
            "demo.analyst", PASSWORD, AuthenticationRequestContext(request_id=uuid.uuid4())
        )
    assert result.status is LoginAttemptStatus.SUCCESS
    assert result.principal is not None and result.principal.username == "demo.analyst"


def test_idempotent_rerun_has_no_duplicate_users_records_or_links(demo_engine: Engine) -> None:
    first = bootstrap_demo(settings(), PASSWORD, engine=demo_engine)
    second = bootstrap_demo(settings(), PASSWORD, engine=demo_engine)
    assert len(first.created) == 7
    assert second.created == ()
    assert len(second.existed) == 7
    assert second.updated == ()
    with Session(demo_engine) as session:
        assert session.scalar(select(func.count()).select_from(User)) == 2
        assert session.scalar(select(func.count()).select_from(IntelligenceRecord)) == 5
        assert session.scalar(select(func.count()).select_from(UserRole)) == 2
        assert session.scalar(select(func.count()).select_from(UserCompartment)) == 1
        assert session.scalar(select(func.count()).select_from(RecordDepartment)) == 5
        assert session.scalar(select(func.count()).select_from(RecordCompartment)) == 3
        assert session.scalar(select(func.count()).select_from(Role)) == 1
        assert session.scalar(select(func.count()).select_from(Department)) == 2
        assert session.scalar(select(func.count()).select_from(ClearanceLevel)) == 3
        assert session.scalar(select(func.count()).select_from(Compartment)) == 2


def test_real_http_login_collection_allows_and_denies_expected_records(demo_engine: Engine) -> None:
    bootstrap_demo(settings(), PASSWORD, engine=demo_engine)
    database_session = Session(demo_engine, expire_on_commit=False)
    application = create_app()
    configured = settings()
    application.dependency_overrides[get_settings] = lambda: configured
    application.dependency_overrides[get_db_session] = lambda: database_session
    try:
        with TestClient(application) as client:
            login = client.post("/auth/login", json={"username": "demo.analyst", "password": PASSWORD})
            collection = client.get("/records")
            allowed = client.get("/records/INT-90002")
            clearance_denied = client.get("/records/INT-90003")
            department_denied = client.get("/records/INT-90004")
            compartment_denied = client.get("/records/INT-90005")
        assert login.status_code == 200 and login.json() == {"authenticated": True, "mfa_required": False}
        assert [item["record_code"] for item in collection.json()] == ["INT-90001", "INT-90002"]
        assert allowed.status_code == 200
        for response in (clearance_denied, department_denied, compartment_denied):
            assert response.status_code == 404
            assert response.json() == {"detail": "Record not found"}
    finally:
        database_session.close()
