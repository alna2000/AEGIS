"""HTTP and orchestration tests for the first protected record READ path."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, cast
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.api.dependencies import (
    get_audit_service,
    get_db_session,
    get_intelligence_record_read_service,
    get_session_service,
)
from aegis.core.config import Settings, get_settings
from aegis.db.intelligence_record_repositories import IntelligenceRecordContent
from aegis.db.models import (
    AuditEvent,
    ClearanceLevel,
    Compartment,
    Department,
    IntelligenceRecord,
    IntelligenceRecordStatus,
    RecordCompartment,
    RecordDepartment,
    Role,
    User,
    UserCompartment,
    UserRole,
    UserSession,
)
from aegis.main import create_app
from aegis.security.authorization import (
    AuthorizationDecision,
    AuthorizationDenyReason,
    AuthorizationResourceType,
    AuthorizationSubject,
    ResourcePolicy,
    RoleName,
)
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.authorization import AuthorizationSubjectLoadResult
from aegis.services.intelligence_records import (
    AuthorizedIntelligenceRecord,
    IntelligenceRecordReadOutcome,
    IntelligenceRecordReadResult,
    IntelligenceRecordReadService,
    ResourcePolicyLoadResult,
)
from aegis.services.sessions import generate_session_token, hash_session_token


NOW = datetime.now(timezone.utc)
PASSWORD_HASH = "synthetic-nonempty-password-verifier"
CYBER_ID = uuid.UUID("31000000-0000-0000-0000-000000000001")
OPERATIONS_ID = uuid.UUID("31000000-0000-0000-0000-000000000004")
SECRET_ID = uuid.UUID("32000000-0000-0000-0000-000000000003")
TOP_SECRET_ID = uuid.UUID("32000000-0000-0000-0000-000000000004")
ANALYST_ID = uuid.UUID("30000000-0000-0000-0000-000000000001")
AUDITOR_ID = uuid.UUID("30000000-0000-0000-0000-000000000004")
ADMIN_ID = uuid.UUID("30000000-0000-0000-0000-000000000005")
NIGHTFALL_ID = uuid.UUID("33000000-0000-0000-0000-000000000001")
GENERIC_NOT_FOUND = {"detail": "Record not found"}
GENERIC_UNAVAILABLE = {"detail": "Classified record service unavailable"}


class FailingAudit:
    def stage(self, _draft):
        raise RuntimeError("synthetic mandatory audit failure")


def settings() -> Settings:
    return Settings(
        database_url="sqlite+pysqlite:///:memory:",
        environment="development",
        session_cookie_secure=False,
        _env_file=None,
    )


def configure_app(db_session: Session):
    application = create_app()
    configured = settings()
    application.dependency_overrides[get_db_session] = lambda: db_session
    application.dependency_overrides[get_settings] = lambda: configured
    return application, configured


def persist_reference_data(db_session: Session) -> dict[str, Any]:
    references = {
        "cyber": Department(
            id=CYBER_ID, name="Cyber Intelligence", is_active=True
        ),
        "operations": Department(
            id=OPERATIONS_ID, name="Operations", is_active=True
        ),
        "secret": ClearanceLevel(id=SECRET_ID, name="SECRET", rank=30),
        "top_secret": ClearanceLevel(
            id=TOP_SECRET_ID, name="TOP SECRET", rank=40
        ),
        "analyst": Role(id=ANALYST_ID, name="Analyst", is_active=True),
        "auditor": Role(
            id=AUDITOR_ID, name="Security Auditor", is_active=True
        ),
        "admin": Role(
            id=ADMIN_ID, name="System Administrator", is_active=True
        ),
        "nightfall": Compartment(
            id=NIGHTFALL_ID, name="NIGHTFALL", is_active=True
        ),
    }
    db_session.add_all(references.values())
    db_session.flush()
    return references


def persist_user(
    db_session: Session,
    references: dict[str, Any],
    *,
    role: str = "analyst",
    department: str | None = "cyber",
    clearance: str | None = "secret",
    compartment: bool = True,
) -> User:
    user = User(
        username=f"synthetic.reader.{uuid.uuid4().hex[:8]}",
        display_name="Synthetic Record Reader",
        password_hash=PASSWORD_HASH,
        is_active=True,
        department=references[department] if department else None,
        clearance_level=references[clearance] if clearance else None,
    )
    user.role_assignments.append(
        UserRole(role=references[role], assigned_at=NOW)
    )
    if compartment:
        user.compartment_assignments.append(
            UserCompartment(
                compartment=references["nightfall"], assigned_at=NOW
            )
        )
    db_session.add(user)
    db_session.flush()
    return user


def persist_record(
    db_session: Session,
    references: dict[str, Any],
    creator: User,
    *,
    record_code: str = "INT-00001",
    classification: str = "secret",
    department: str = "cyber",
    compartment: bool = True,
    lifecycle: IntelligenceRecordStatus = IntelligenceRecordStatus.ACTIVE,
) -> IntelligenceRecord:
    record = IntelligenceRecord(
        record_code=record_code,
        title="Synthetic Record",
        summary="Synthetic summary",
        content="Synthetic classified-record content.",
        classification_level=references[classification],
        creator=creator,
        status=lifecycle,
        created_at=NOW,
        updated_at=NOW,
        retired_at=NOW if lifecycle is IntelligenceRecordStatus.RETIRED else None,
    )
    record.department_assignments.append(
        RecordDepartment(department=references[department])
    )
    if compartment:
        record.compartment_assignments.append(
            RecordCompartment(compartment=references["nightfall"])
        )
    db_session.add(record)
    db_session.flush()
    return record


def issue_session(db_session: Session, user: User, *, state: str = "active") -> str:
    token = generate_session_token()
    session = UserSession(
        user=user,
        token_hash=cast(str, hash_session_token(token)),
        created_at=NOW - timedelta(hours=2),
        expires_at=(
            NOW - timedelta(hours=1)
            if state == "expired"
            else NOW + timedelta(hours=2)
        ),
        revoked_at=NOW - timedelta(minutes=1) if state == "revoked" else None,
    )
    db_session.add(session)
    db_session.commit()
    return token


def get_record(
    db_session: Session,
    *,
    role: str = "analyst",
    user_department: str | None = "cyber",
    user_clearance: str | None = "secret",
    user_compartment: bool = True,
    record_department: str = "cyber",
    record_classification: str = "secret",
    record_compartment: bool = True,
    lifecycle: IntelligenceRecordStatus = IntelligenceRecordStatus.ACTIVE,
    code: str = "INT-00001",
):
    references = persist_reference_data(db_session)
    user = persist_user(
        db_session,
        references,
        role=role,
        department=user_department,
        clearance=user_clearance,
        compartment=user_compartment,
    )
    record = persist_record(
        db_session,
        references,
        user,
        record_code=code,
        classification=record_classification,
        department=record_department,
        compartment=record_compartment,
        lifecycle=lifecycle,
    )
    token = issue_session(db_session, user)
    application, configured = configure_app(db_session)
    return application, configured, references, user, record, token


def request_record(application, configured: Settings, token: str, code: str):
    with TestClient(application) as client:
        client.cookies.set(configured.session_cookie_name, token)
        return client.get(f"/records/{code}")


def assert_hidden(response) -> None:
    assert response.status_code == 404
    assert response.json() == GENERIC_NOT_FOUND
    assert response.headers["content-type"] == "application/json"
    forbidden = (
        "Synthetic Record",
        "Synthetic summary",
        "classified-record content",
        "SECRET",
        "role",
        "clearance",
        "department",
        "compartment",
        "DRAFT",
        "RETIRED",
        "DENY",
    )
    assert all(value not in response.text for value in forbidden)


def test_authorized_direct_api_read_returns_only_approved_fields(
    db_session: Session,
) -> None:
    application, configured, _, _, _, token = get_record(db_session)

    response = request_record(application, configured, token, "INT-00001")

    assert response.status_code == 200
    assert response.json() == {
        "record_code": "INT-00001",
        "title": "Synthetic Record",
        "summary": "Synthetic summary",
        "content": "Synthetic classified-record content.",
        "classification": "SECRET",
    }
    assert set(response.json()) == {
        "record_code",
        "title",
        "summary",
        "content",
        "classification",
    }
    events = tuple(db_session.scalars(select(AuditEvent).order_by(AuditEvent.occurred_at)))
    assert [event.event_code for event in events] == [
        "AUTHORIZATION_ALLOWED",
        "RESOURCE_READ_SUCCEEDED",
    ]
    assert events[0].target_id == events[1].target_id
    assert events[0].request_id == events[1].request_id


def test_mandatory_audit_failure_returns_no_classified_content(
    db_session: Session,
) -> None:
    application, configured, _, _, _, token = get_record(db_session)
    application.dependency_overrides[get_audit_service] = lambda: FailingAudit()

    response = request_record(application, configured, token, "INT-00001")

    assert response.status_code == 503
    assert response.json() == GENERIC_UNAVAILABLE
    assert "Synthetic classified-record content" not in response.text
    assert db_session.scalar(select(AuditEvent)) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"record_classification": "top_secret"},
        {"record_department": "operations"},
        {"user_compartment": False},
        {"role": "admin", "user_clearance": "top_secret"},
        {"role": "auditor"},
        {"user_department": None},
        {"user_clearance": None},
    ],
    ids=[
        "insufficient-clearance",
        "wrong-department",
        "missing-compartment",
        "administrator-overreach",
        "auditor-overreach",
        "missing-department",
        "missing-clearance",
    ],
)
def test_direct_api_authorization_denials_hide_record(
    db_session: Session, overrides: dict[str, Any]
) -> None:
    application, configured, _, _, _, token = get_record(db_session, **overrides)

    assert_hidden(request_record(application, configured, token, "INT-00001"))


@pytest.mark.parametrize(
    "code",
    [
        "INT-99999",
        "int-00001",
        " INT-00001",
        "INT-00001 ",
        "ABC-00001",
        "INT-123",
        "INT-123456",
        "INT-12A45",
    ],
)
def test_unknown_and_malformed_codes_share_hidden_response_without_422(
    db_session: Session, code: str
) -> None:
    application, configured, _, _, _, token = get_record(db_session)

    assert_hidden(request_record(application, configured, token, code))
    events = tuple(db_session.scalars(select(AuditEvent)))
    assert {event.event_code for event in events} == {
        "AUTHORIZATION_DENIED",
        "RESOURCE_READ_INACCESSIBLE",
    }
    assert all(event.target_id is None for event in events)
    assert all(
        code not in tuple(str(value) for value in vars(event).values())
        for event in events
    )


@pytest.mark.parametrize(
    "lifecycle",
    [IntelligenceRecordStatus.DRAFT, IntelligenceRecordStatus.RETIRED],
)
def test_creator_cannot_read_draft_or_retired_record(
    db_session: Session, lifecycle: IntelligenceRecordStatus
) -> None:
    application, configured, _, _, _, token = get_record(
        db_session, lifecycle=lifecycle
    )

    assert_hidden(request_record(application, configured, token, "INT-00001"))


def test_missing_expired_revoked_and_disabled_sessions_return_401(
    db_session: Session,
) -> None:
    references = persist_reference_data(db_session)
    user = persist_user(db_session, references)
    application, configured = configure_app(db_session)

    with TestClient(application) as client:
        missing = client.get("/records/INT-00001")
    expired_token = issue_session(db_session, user, state="expired")
    expired = request_record(application, configured, expired_token, "INT-00001")
    revoked_token = issue_session(db_session, user, state="revoked")
    revoked = request_record(application, configured, revoked_token, "INT-00001")
    active_token = issue_session(db_session, user)
    user.is_active = False
    user.disabled_at = NOW
    db_session.commit()
    db_session.expire_all()
    disabled = request_record(application, configured, active_token, "INT-00001")

    for response in (missing, expired, revoked, disabled):
        assert response.status_code == 401
        assert response.json() == {"detail": "Authentication required"}


@pytest.mark.parametrize(
    "change",
    ["role", "clearance", "department", "compartment"],
)
def test_current_authorization_state_is_reloaded_after_session_creation(
    db_session: Session, change: str
) -> None:
    application, configured, references, user, _, token = get_record(db_session)
    if change == "role":
        references["analyst"].is_active = False
        references["analyst"].retired_at = NOW
    elif change == "clearance":
        user.clearance_level = None
    elif change == "department":
        references["cyber"].is_active = False
        references["cyber"].retired_at = NOW
    else:
        references["nightfall"].is_active = False
        references["nightfall"].retired_at = NOW
    db_session.commit()
    db_session.expire_all()

    assert_hidden(request_record(application, configured, token, "INT-00001"))


class StaticSubjects:
    def __init__(self, result: AuthorizationSubjectLoadResult) -> None:
        self.result = result

    def load(self, _principal: AuthenticatedPrincipal):
        return self.result


class StaticPolicies:
    def __init__(self, result: ResourcePolicyLoadResult) -> None:
        self.result = result

    def load_by_record_code(self, _record_code: str):
        return self.result


class ContentSpy:
    def __init__(self, value: object = None, *, fail: bool = False) -> None:
        self.value = value
        self.fail = fail
        self.calls = 0

    def get_content_record_by_id(self, _record_id: uuid.UUID):
        self.calls += 1
        if self.fail:
            raise RuntimeError("synthetic content database failure")
        return self.value


def principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(uuid.uuid4(), "synthetic.reader", "Reader")


def subject() -> AuthorizationSubject:
    identity = principal()
    return AuthorizationSubject(
        identity=identity,
        account_usable=True,
        active_roles=frozenset({RoleName.ANALYST}),
        department_id=CYBER_ID,
        department_active=True,
        clearance_rank=30,
        active_compartment_ids=frozenset({NIGHTFALL_ID}),
    )


def policy_result() -> ResourcePolicyLoadResult:
    return ResourcePolicyLoadResult.success(
        uuid.UUID("51000000-0000-0000-0000-000000000001"),
        ResourcePolicy(
            resource_type=AuthorizationResourceType.INTELLIGENCE_RECORD,
            classification_rank=30,
            authorized_department_ids=frozenset({CYBER_ID}),
            required_compartment_ids=frozenset({NIGHTFALL_ID}),
        ),
    )


def valid_content() -> IntelligenceRecordContent:
    return IntelligenceRecordContent(
        id=cast(uuid.UUID, policy_result().record_id),
        record_code="INT-00001",
        title="Synthetic Record",
        summary=None,
        content="Synthetic content",
        classification="SECRET",
        status="ACTIVE",
    )


def read_service(
    content: ContentSpy,
    *,
    subject_result: AuthorizationSubjectLoadResult | None = None,
    loaded_policy: ResourcePolicyLoadResult | None = None,
    evaluator=AuthorizationDecision.allow,
) -> IntelligenceRecordReadService:
    loaded_subject = subject_result or AuthorizationSubjectLoadResult.success(
        subject()
    )
    return IntelligenceRecordReadService(
        cast(Any, StaticSubjects(loaded_subject)),
        cast(Any, StaticPolicies(loaded_policy or policy_result())),
        cast(Any, content),
        evaluator=lambda *_: evaluator(),
    )


@pytest.mark.parametrize(
    ("loaded_policy", "evaluator", "expected"),
    [
        (
            ResourcePolicyLoadResult.failure(AuthorizationDenyReason.RESOURCE_MISSING),
            AuthorizationDecision.allow,
            IntelligenceRecordReadOutcome.INACCESSIBLE,
        ),
        (
            ResourcePolicyLoadResult.failure(
                AuthorizationDenyReason.INVALID_RESOURCE_POLICY
            ),
            AuthorizationDecision.allow,
            IntelligenceRecordReadOutcome.INACCESSIBLE,
        ),
        (
            policy_result(),
            lambda: AuthorizationDecision.deny(
                AuthorizationDenyReason.INSUFFICIENT_CLEARANCE
            ),
            IntelligenceRecordReadOutcome.INACCESSIBLE,
        ),
        (
            policy_result(),
            lambda: AuthorizationDecision.deny(
                AuthorizationDenyReason.POLICY_EVALUATION_ERROR
            ),
            IntelligenceRecordReadOutcome.UNAVAILABLE,
        ),
    ],
)
def test_content_is_not_loaded_before_explicit_allow(
    loaded_policy: ResourcePolicyLoadResult,
    evaluator,
    expected: IntelligenceRecordReadOutcome,
) -> None:
    content = ContentSpy(valid_content())

    result = read_service(
        content, loaded_policy=loaded_policy, evaluator=evaluator
    ).read(principal(), "INT-00001")

    assert result.outcome is expected
    assert result.record is None
    assert content.calls == 0


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (ContentSpy(None), IntelligenceRecordReadOutcome.INACCESSIBLE),
        (ContentSpy(fail=True), IntelligenceRecordReadOutcome.UNAVAILABLE),
        (
            ContentSpy(
                IntelligenceRecordContent(
                    id=uuid.uuid4(),
                    record_code="INT-00001",
                    title="Synthetic Record",
                    summary=None,
                    content="Synthetic content",
                    classification="SECRET",
                    status="ACTIVE",
                )
            ),
            IntelligenceRecordReadOutcome.UNAVAILABLE,
        ),
        (
            ContentSpy(
                IntelligenceRecordContent(
                    id=cast(uuid.UUID, policy_result().record_id),
                    record_code="INT-00002",
                    title="Synthetic Record",
                    summary=None,
                    content="Synthetic content",
                    classification="SECRET",
                    status="ACTIVE",
                )
            ),
            IntelligenceRecordReadOutcome.UNAVAILABLE,
        ),
        (
            ContentSpy(
                IntelligenceRecordContent(
                    id=cast(uuid.UUID, policy_result().record_id),
                    record_code="INT-00001",
                    title="Synthetic Record",
                    summary=None,
                    content="Synthetic content",
                    classification="TOP SECRET",
                    status="ACTIVE",
                )
            ),
            IntelligenceRecordReadOutcome.UNAVAILABLE,
        ),
        (
            ContentSpy(
                IntelligenceRecordContent(
                    id=cast(uuid.UUID, policy_result().record_id),
                    record_code="INT-00001",
                    title="Synthetic Record",
                    summary=None,
                    content="Synthetic content",
                    classification="SECRET",
                    status="RETIRED",
                )
            ),
            IntelligenceRecordReadOutcome.UNAVAILABLE,
        ),
    ],
    ids=[
        "disappeared",
        "database-failure",
        "id-mismatch",
        "code-mismatch",
        "classification-mismatch",
        "lifecycle-mismatch",
    ],
)
def test_post_allow_content_failures_are_controlled(
    content: ContentSpy, expected: IntelligenceRecordReadOutcome
) -> None:
    result = read_service(content).read(principal(), "INT-00001")

    assert result.outcome is expected
    assert result.record is None
    assert content.calls == 1


def test_explicit_allow_loads_content_once() -> None:
    content = ContentSpy(valid_content())

    result = read_service(content).read(principal(), "INT-00001")

    assert result.outcome is IntelligenceRecordReadOutcome.AUTHORIZED
    assert result.record == AuthorizedIntelligenceRecord(
        record_code="INT-00001",
        title="Synthetic Record",
        summary=None,
        content="Synthetic content",
        classification="SECRET",
    )
    assert content.calls == 1


def test_subject_and_policy_infrastructure_failures_return_unavailable() -> None:
    content = ContentSpy(valid_content())
    subject_failure = read_service(
        content,
        subject_result=AuthorizationSubjectLoadResult.failure(
            AuthorizationDenyReason.SUBJECT_LOAD_ERROR
        ),
    ).read(principal(), "INT-00001")
    policy_failure = read_service(
        content,
        loaded_policy=ResourcePolicyLoadResult.failure(
            AuthorizationDenyReason.RESOURCE_LOAD_ERROR
        ),
    ).read(principal(), "INT-00001")

    assert subject_failure.outcome is IntelligenceRecordReadOutcome.UNAVAILABLE
    assert policy_failure.outcome is IntelligenceRecordReadOutcome.UNAVAILABLE
    assert content.calls == 0


def test_read_result_invariants_reject_contradictory_states() -> None:
    with pytest.raises(ValueError):
        IntelligenceRecordReadResult(IntelligenceRecordReadOutcome.AUTHORIZED)
    with pytest.raises(ValueError):
        IntelligenceRecordReadResult(
            IntelligenceRecordReadOutcome.INACCESSIBLE,
            AuthorizedIntelligenceRecord(
                "INT-00001", "title", None, "content", "SECRET"
            ),
        )


def test_read_outcome_does_not_compare_equal_to_raw_string() -> None:
    assert IntelligenceRecordReadOutcome.AUTHORIZED != "AUTHORIZED"
    with pytest.raises(ValueError):
        IntelligenceRecordReadResult(cast(Any, "AUTHORIZED"))


@pytest.mark.parametrize(
    ("outcome", "status_code", "body"),
    [
        (
            IntelligenceRecordReadOutcome.INACCESSIBLE,
            404,
            GENERIC_NOT_FOUND,
        ),
        (
            IntelligenceRecordReadOutcome.UNAVAILABLE,
            503,
            GENERIC_UNAVAILABLE,
        ),
        (
            IntelligenceRecordReadOutcome.AUTHENTICATION_REQUIRED,
            401,
            {"detail": "Authentication required"},
        ),
    ],
)
def test_route_maps_controlled_failures_to_generic_bodies(
    db_session: Session,
    outcome: IntelligenceRecordReadOutcome,
    status_code: int,
    body: dict[str, str],
) -> None:
    references = persist_reference_data(db_session)
    user = persist_user(db_session, references)
    token = issue_session(db_session, user)
    application, configured = configure_app(db_session)
    application.dependency_overrides[get_intelligence_record_read_service] = (
        lambda: StaticReadService(IntelligenceRecordReadResult(outcome))
    )

    response = request_record(application, configured, token, "INT-00001")

    assert response.status_code == status_code
    assert response.json() == body


@pytest.mark.parametrize("failure", ["malformed", "exception"])
def test_route_maps_unexpected_read_service_failure_to_generic_503(
    db_session: Session, failure: str
) -> None:
    references = persist_reference_data(db_session)
    user = persist_user(db_session, references)
    token = issue_session(db_session, user)
    application, configured = configure_app(db_session)
    application.dependency_overrides[get_intelligence_record_read_service] = (
        lambda: UnexpectedReadService(failure)
    )

    response = request_record(application, configured, token, "INT-00001")

    assert response.status_code == 503
    assert response.json() == GENERIC_UNAVAILABLE
    assert "synthetic unexpected read failure" not in response.text


def test_authentication_infrastructure_failure_keeps_authentication_503(
    db_session: Session,
) -> None:
    application, configured = configure_app(db_session)
    application.dependency_overrides[get_session_service] = (
        lambda: FailingSessionResolution()
    )

    with TestClient(application) as client:
        client.cookies.set(configured.session_cookie_name, generate_session_token())
        response = client.get("/records/INT-00001")

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service unavailable"}
    assert response.headers["content-type"] == "application/json"


class StaticReadService:
    def __init__(self, result: IntelligenceRecordReadResult) -> None:
        self.result = result

    def read(self, _principal: AuthenticatedPrincipal, _record_code: str):
        return self.result


class UnexpectedReadService:
    def __init__(self, failure: str) -> None:
        self.failure = failure

    def read(self, _principal: AuthenticatedPrincipal, _record_code: str):
        if self.failure == "exception":
            raise RuntimeError("synthetic unexpected read failure")
        return "AUTHORIZED"


class FailingSessionResolution:
    def resolve_session(self, _raw_token: str | None):
        raise RuntimeError("synthetic authentication database failure")
