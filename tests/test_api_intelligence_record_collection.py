"""Security tests for the bounded classified-record collection endpoint."""

from __future__ import annotations

from dataclasses import replace
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
    get_intelligence_record_collection_read_service,
    get_session_service,
)
from aegis.core.config import Settings, get_settings
from aegis.db.intelligence_record_repositories import (
    ActiveReferencePolicyFacts,
    ClearancePolicyFacts,
    IntelligenceRecordCollectionEntry,
    IntelligenceRecordPolicyFacts,
    RecordReferencePolicyFacts,
)
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
    AuthorizationAction,
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
    AuthorizedIntelligenceRecordCollectionEntry,
    IntelligenceRecordCollectionReadOutcome,
    IntelligenceRecordCollectionReadResult,
    IntelligenceRecordCollectionReadService,
    IntelligenceRecordPolicyCandidate,
    IntelligenceRecordPolicyService,
    ResourcePolicyCollectionFailure,
    ResourcePolicyCollectionLoadResult,
)
from aegis.services.sessions import generate_session_token, hash_session_token


NOW = datetime.now(timezone.utc)
PASSWORD_HASH = "synthetic-nonempty-password-verifier"
CYBER_ID = uuid.UUID("31000000-0000-0000-0000-000000000001")
OPERATIONS_ID = uuid.UUID("31000000-0000-0000-0000-000000000004")
SECRET_ID = uuid.UUID("32000000-0000-0000-0000-000000000003")
TOP_SECRET_ID = uuid.UUID("32000000-0000-0000-0000-000000000004")
ANALYST_ID = uuid.UUID("30000000-0000-0000-0000-000000000001")
SENIOR_ID = uuid.UUID("30000000-0000-0000-0000-000000000002")
SUPERVISOR_ID = uuid.UUID("30000000-0000-0000-0000-000000000003")
AUDITOR_ID = uuid.UUID("30000000-0000-0000-0000-000000000004")
ADMIN_ID = uuid.UUID("30000000-0000-0000-0000-000000000005")
NIGHTFALL_ID = uuid.UUID("33000000-0000-0000-0000-000000000001")
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


def persist_references(db_session: Session) -> dict[str, Any]:
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
        "senior": Role(
            id=SENIOR_ID, name="Senior Analyst", is_active=True
        ),
        "supervisor": Role(
            id=SUPERVISOR_ID, name="Supervisor", is_active=True
        ),
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
    clearance: str | None = "secret",
    department: str | None = "cyber",
    compartment: bool = True,
) -> User:
    user = User(
        username=f"synthetic.collection.{uuid.uuid4().hex[:8]}",
        display_name="Synthetic Collection Reader",
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
    code: str,
    *,
    classification: str = "secret",
    department: str = "cyber",
    compartment: bool = False,
    lifecycle: IntelligenceRecordStatus = IntelligenceRecordStatus.ACTIVE,
) -> IntelligenceRecord:
    record = IntelligenceRecord(
        record_code=code,
        title=f"Title {code}",
        summary=f"Summary {code}",
        content=f"Content {code}",
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
    raw_token = generate_session_token()
    db_session.add(
        UserSession(
            user=user,
            token_hash=cast(str, hash_session_token(raw_token)),
            created_at=NOW - timedelta(hours=1),
            expires_at=(
                NOW - timedelta(minutes=1)
                if state == "expired"
                else NOW + timedelta(hours=2)
            ),
            revoked_at=NOW if state == "revoked" else None,
        )
    )
    db_session.commit()
    return raw_token


def request_collection(application, configured: Settings, token: str):
    with TestClient(application) as client:
        client.cookies.set(configured.session_cookie_name, token)
        return client.get("/records")


def prepare_collection(
    db_session: Session,
    *,
    role: str = "analyst",
    clearance: str | None = "secret",
    department: str | None = "cyber",
    compartment: bool = True,
):
    references = persist_references(db_session)
    user = persist_user(
        db_session,
        references,
        role=role,
        clearance=clearance,
        department=department,
        compartment=compartment,
    )
    token = issue_session(db_session, user)
    application, configured = configure_app(db_session)
    return application, configured, references, user, token


def test_mixed_direct_api_collection_returns_only_authorized_metadata(
    db_session: Session,
) -> None:
    application, configured, references, user, token = prepare_collection(
        db_session, compartment=False
    )
    persist_record(db_session, references, user, "INT-00006", lifecycle=IntelligenceRecordStatus.RETIRED)
    persist_record(db_session, references, user, "INT-00003", department="operations")
    persist_record(db_session, references, user, "INT-00001")
    persist_record(db_session, references, user, "INT-00004", compartment=True)
    persist_record(db_session, references, user, "INT-00002", classification="top_secret")
    persist_record(db_session, references, user, "INT-00005", lifecycle=IntelligenceRecordStatus.DRAFT)
    db_session.commit()

    response = request_collection(application, configured, token)

    assert response.status_code == 200
    assert response.json() == [
        {
            "record_code": "INT-00001",
            "title": "Title INT-00001",
            "classification": "SECRET",
        },
    ]
    assert response.headers["content-type"] == "application/json"
    assert not any("count" in name.lower() for name in response.headers)
    assert "summary" not in response.text.lower()
    assert "content" not in response.text.lower()
    for hidden_code in ("INT-00002", "INT-00003", "INT-00005", "INT-00006"):
        assert hidden_code not in response.text
    events = tuple(db_session.scalars(select(AuditEvent)))
    assert len(events) == 1
    assert events[0].event_code == "RESOURCE_COLLECTION_READ"
    assert events[0].target_type == "ENDPOINT"
    assert events[0].target_id is None


def test_collection_audit_failure_returns_generic_503_without_metadata(
    db_session: Session,
) -> None:
    application, configured, references, user, token = prepare_collection(db_session)
    persist_record(db_session, references, user, "INT-00001")
    db_session.commit()
    application.dependency_overrides[get_audit_service] = lambda: FailingAudit()

    response = request_collection(application, configured, token)

    assert response.status_code == 503
    assert response.json() == GENERIC_UNAVAILABLE
    assert "Title INT-00001" not in response.text
    assert db_session.scalar(select(AuditEvent)) is None


def test_authorized_collection_is_sorted_after_authorization(
    db_session: Session,
) -> None:
    application, configured, references, user, token = prepare_collection(db_session)
    for code in ("INT-00009", "INT-00001", "INT-00005"):
        persist_record(db_session, references, user, code)
    db_session.commit()

    response = request_collection(application, configured, token)

    assert [entry["record_code"] for entry in response.json()] == [
        "INT-00001",
        "INT-00005",
        "INT-00009",
    ]


@pytest.mark.parametrize("role", ["analyst", "senior", "supervisor"])
def test_intelligence_roles_can_list_records_when_abac_passes(
    db_session: Session, role: str
) -> None:
    application, configured, references, user, token = prepare_collection(
        db_session, role=role
    )
    persist_record(db_session, references, user, "INT-00001")
    db_session.commit()

    assert request_collection(application, configured, token).status_code == 200
    assert request_collection(application, configured, token).json()[0][
        "record_code"
    ] == "INT-00001"


@pytest.mark.parametrize("role", ["admin", "auditor"])
def test_administrator_and_auditor_receive_empty_collection(
    db_session: Session, role: str
) -> None:
    application, configured, references, user, token = prepare_collection(
        db_session, role=role, clearance="top_secret"
    )
    persist_record(db_session, references, user, "INT-00001")
    db_session.commit()

    response = request_collection(application, configured, token)

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.parametrize(
    "user_change",
    ["role", "clearance", "department", "compartment"],
)
def test_collection_reloads_current_authorization_state(
    db_session: Session, user_change: str
) -> None:
    application, configured, references, user, token = prepare_collection(db_session)
    persist_record(db_session, references, user, "INT-00001", compartment=True)
    if user_change == "role":
        references["analyst"].is_active = False
        references["analyst"].retired_at = NOW
    elif user_change == "clearance":
        user.clearance_level = None
    elif user_change == "department":
        user.department = references["operations"]
    else:
        db_session.delete(user.compartment_assignments[0])
    db_session.commit()
    db_session.expire_all()

    response = request_collection(application, configured, token)

    assert response.status_code == 200
    assert response.json() == []


def test_disabled_account_loses_collection_access_without_relogin(
    db_session: Session,
) -> None:
    application, configured, references, user, token = prepare_collection(db_session)
    persist_record(db_session, references, user, "INT-00001")
    user.is_active = False
    user.disabled_at = NOW
    db_session.commit()
    db_session.expire_all()

    response = request_collection(application, configured, token)

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


def test_missing_expired_and_revoked_sessions_return_401(
    db_session: Session,
) -> None:
    references = persist_references(db_session)
    user = persist_user(db_session, references)
    application, configured = configure_app(db_session)
    with TestClient(application) as client:
        missing = client.get("/records")
    expired = request_collection(
        application, configured, issue_session(db_session, user, state="expired")
    )
    revoked = request_collection(
        application, configured, issue_session(db_session, user, state="revoked")
    )

    for response in (missing, expired, revoked):
        assert response.status_code == 401
        assert response.json() == {"detail": "Authentication required"}


def valid_subject() -> AuthorizationSubject:
    return AuthorizationSubject(
        identity=AuthenticatedPrincipal(uuid.uuid4(), "synthetic.reader", "Reader"),
        account_usable=True,
        active_roles=frozenset({RoleName.ANALYST}),
        department_id=CYBER_ID,
        department_active=True,
        clearance_rank=30,
        active_compartment_ids=frozenset({NIGHTFALL_ID}),
    )


def candidate(index: int = 1) -> IntelligenceRecordPolicyCandidate:
    return IntelligenceRecordPolicyCandidate(
        record_id=uuid.UUID(f"51000000-0000-0000-0000-{index:012d}"),
        record_code=f"INT-{index:05d}",
        policy=ResourcePolicy(
            resource_type=AuthorizationResourceType.INTELLIGENCE_RECORD,
            classification_rank=30,
            authorized_department_ids=frozenset({CYBER_ID}),
            required_compartment_ids=frozenset({NIGHTFALL_ID}),
        ),
    )


def projection(
    source: IntelligenceRecordPolicyCandidate | None = None,
) -> IntelligenceRecordCollectionEntry:
    selected = source or candidate()
    return IntelligenceRecordCollectionEntry(
        id=selected.record_id,
        record_code=selected.record_code,
        title=f"Title {selected.record_code}",
        classification="SECRET",
        status="ACTIVE",
    )


class StaticSubjects:
    def __init__(self, result: AuthorizationSubjectLoadResult) -> None:
        self.result = result

    def load(self, _principal: AuthenticatedPrincipal):
        return self.result


class StaticPolicies:
    def __init__(self, result: ResourcePolicyCollectionLoadResult) -> None:
        self.result = result
        self.calls = 0

    def load_collection(self):
        self.calls += 1
        return self.result


class CollectionContentSpy:
    def __init__(self, result: object = (), *, fail: bool = False) -> None:
        self.result = result
        self.fail = fail
        self.calls: list[tuple[uuid.UUID, ...]] = []

    def get_collection_entries_by_ids(self, record_ids: tuple[uuid.UUID, ...]):
        self.calls.append(record_ids)
        if self.fail:
            raise RuntimeError("synthetic collection representation failure")
        return self.result


def collection_service(
    policies: StaticPolicies,
    content: CollectionContentSpy,
    *,
    subject_result: AuthorizationSubjectLoadResult | None = None,
    evaluator=None,
) -> IntelligenceRecordCollectionReadService:
    return IntelligenceRecordCollectionReadService(
        cast(
            Any,
            StaticSubjects(
                subject_result
                or AuthorizationSubjectLoadResult.success(valid_subject())
            ),
        ),
        cast(Any, policies),
        cast(Any, content),
        evaluator=evaluator or (lambda *_: AuthorizationDecision.allow()),
    )


def test_search_and_read_must_both_explicitly_allow() -> None:
    policy = StaticPolicies(ResourcePolicyCollectionLoadResult.success((candidate(),)))
    content = CollectionContentSpy((projection(),))

    for denied_action in (AuthorizationAction.SEARCH, AuthorizationAction.READ):
        actions: list[AuthorizationAction] = []

        def evaluator(_subject, action, _policy):
            actions.append(action)
            if action is denied_action:
                return AuthorizationDecision.deny(
                    AuthorizationDenyReason.NO_ROLE_CAPABILITY
                )
            return AuthorizationDecision.allow()

        result = collection_service(
            policy, content, evaluator=evaluator
        ).read(valid_subject().identity)
        assert result.outcome is IntelligenceRecordCollectionReadOutcome.AUTHORIZED
        assert result.entries == ()
        assert content.calls == []
        assert AuthorizationAction.SEARCH in actions
        if denied_action is AuthorizationAction.READ:
            assert AuthorizationAction.READ in actions


def test_metadata_batch_receives_only_dually_authorized_ids() -> None:
    first, second = candidate(1), candidate(2)
    policies = StaticPolicies(
        ResourcePolicyCollectionLoadResult.success((first, second))
    )
    content = CollectionContentSpy((projection(first),))

    def evaluator(_subject, action, policy):
        if policy is second.policy and action is AuthorizationAction.READ:
            return AuthorizationDecision.deny(
                AuthorizationDenyReason.NO_ROLE_CAPABILITY
            )
        return AuthorizationDecision.allow()

    result = collection_service(
        policies, content, evaluator=evaluator
    ).read(valid_subject().identity)

    assert result.outcome is IntelligenceRecordCollectionReadOutcome.AUTHORIZED
    assert content.calls == [(first.record_id,)]
    assert result.entries == (
        AuthorizedIntelligenceRecordCollectionEntry(
            "INT-00001", "Title INT-00001", "SECRET"
        ),
    )


@pytest.mark.parametrize(
    "failure",
    [
        ResourcePolicyCollectionFailure.LOAD_ERROR,
        ResourcePolicyCollectionFailure.INVALID_POLICY,
        ResourcePolicyCollectionFailure.CAPACITY_EXCEEDED,
    ],
)
def test_policy_collection_failure_never_loads_metadata(
    failure: ResourcePolicyCollectionFailure,
) -> None:
    policies = StaticPolicies(ResourcePolicyCollectionLoadResult.failed(failure))
    content = CollectionContentSpy((projection(),))

    result = collection_service(policies, content).read(valid_subject().identity)

    assert result.outcome is IntelligenceRecordCollectionReadOutcome.UNAVAILABLE
    assert result.entries is None
    assert content.calls == []


def test_subject_failure_never_loads_candidates_or_metadata() -> None:
    policies = StaticPolicies(
        ResourcePolicyCollectionLoadResult.success((candidate(),))
    )
    content = CollectionContentSpy((projection(),))
    service = collection_service(
        policies,
        content,
        subject_result=AuthorizationSubjectLoadResult.failure(
            AuthorizationDenyReason.SUBJECT_LOAD_ERROR
        ),
    )

    result = service.read(valid_subject().identity)

    assert result.outcome is IntelligenceRecordCollectionReadOutcome.UNAVAILABLE
    assert policies.calls == 0
    assert content.calls == []


@pytest.mark.parametrize(
    "failing_action", [AuthorizationAction.SEARCH, AuthorizationAction.READ]
)
def test_evaluator_error_fails_entire_collection_without_metadata(
    failing_action: AuthorizationAction,
) -> None:
    policies = StaticPolicies(
        ResourcePolicyCollectionLoadResult.success((candidate(),))
    )
    content = CollectionContentSpy((projection(),))

    def evaluator(_subject, action, _policy):
        if action is failing_action:
            return AuthorizationDecision.deny(
                AuthorizationDenyReason.POLICY_EVALUATION_ERROR
            )
        return AuthorizationDecision.allow()

    result = collection_service(
        policies, content, evaluator=evaluator
    ).read(valid_subject().identity)

    assert result.outcome is IntelligenceRecordCollectionReadOutcome.UNAVAILABLE
    assert content.calls == []


def test_thrown_or_malformed_evaluator_result_fails_closed() -> None:
    policies = StaticPolicies(
        ResourcePolicyCollectionLoadResult.success((candidate(),))
    )
    for evaluator in (
        lambda *_: "ALLOW",
        lambda *_: (_ for _ in ()).throw(RuntimeError("synthetic evaluator failure")),
    ):
        content = CollectionContentSpy((projection(),))
        result = collection_service(
            policies, content, evaluator=evaluator
        ).read(valid_subject().identity)
        assert result.outcome is IntelligenceRecordCollectionReadOutcome.UNAVAILABLE
        assert content.calls == []


def test_empty_authorized_collection_skips_metadata_query() -> None:
    policies = StaticPolicies(ResourcePolicyCollectionLoadResult.success(()))
    content = CollectionContentSpy((projection(),))

    result = collection_service(policies, content).read(valid_subject().identity)

    assert result.outcome is IntelligenceRecordCollectionReadOutcome.AUTHORIZED
    assert result.entries == ()
    assert content.calls == []


def test_representation_database_failure_returns_unavailable() -> None:
    policies = StaticPolicies(
        ResourcePolicyCollectionLoadResult.success((candidate(),))
    )
    content = CollectionContentSpy(fail=True)

    result = collection_service(policies, content).read(valid_subject().identity)

    assert result.outcome is IntelligenceRecordCollectionReadOutcome.UNAVAILABLE


@pytest.mark.parametrize(
    "projections",
    [
        (),
        (projection(), projection()),
        (replace(projection(), id=uuid.uuid4()),),
        (replace(projection(), record_code="INT-00002"),),
        (replace(projection(), classification="TOP SECRET"),),
        (replace(projection(), status="RETIRED"),),
        (replace(projection(), title=" untrimmed"),),
        ("malformed",),
        [projection()],
    ],
    ids=[
        "missing",
        "duplicate",
        "unknown-id",
        "code-mismatch",
        "classification-mismatch",
        "lifecycle-mismatch",
        "malformed-title",
        "malformed-type",
        "mutable-container",
    ],
)
def test_collection_consistency_failures_return_unavailable(
    projections: object,
) -> None:
    policies = StaticPolicies(
        ResourcePolicyCollectionLoadResult.success((candidate(),))
    )
    content = CollectionContentSpy(projections)

    result = collection_service(policies, content).read(valid_subject().identity)

    assert result.outcome is IntelligenceRecordCollectionReadOutcome.UNAVAILABLE
    assert result.entries is None


def policy_facts(index: int) -> IntelligenceRecordPolicyFacts:
    record_id = uuid.UUID(f"52000000-0000-0000-0000-{index:012d}")
    department = ActiveReferencePolicyFacts(
        id=CYBER_ID,
        name="Cyber Intelligence",
        is_active=True,
        retired_at=None,
    )
    return IntelligenceRecordPolicyFacts(
        id=record_id,
        record_code=f"INT-{index:05d}",
        status="ACTIVE",
        classification_level_id=SECRET_ID,
        classification=ClearancePolicyFacts(SECRET_ID, "SECRET", 30),
        created_by_user_id=uuid.uuid4(),
        created_at=NOW,
        updated_at=NOW,
        retired_at=None,
        department_relationships=(
            RecordReferencePolicyFacts(record_id, CYBER_ID, department),
        ),
        compartment_relationships=(),
    )


class BoundedPolicyRepository:
    def __init__(self, count: int, *, fail: bool = False) -> None:
        self.count = count
        self.fail = fail
        self.limits: list[int] = []

    def list_policy_records(self, *, limit: int):
        self.limits.append(limit)
        if self.fail:
            raise RuntimeError("synthetic candidate database failure")
        return tuple(policy_facts(index) for index in range(1, self.count + 1))


@pytest.mark.parametrize(
    ("count", "success", "failure"),
    [
        (100, True, None),
        (101, False, ResourcePolicyCollectionFailure.CAPACITY_EXCEEDED),
    ],
)
def test_policy_candidate_cap_fetches_101_without_silent_truncation(
    count: int,
    success: bool,
    failure: ResourcePolicyCollectionFailure | None,
) -> None:
    repository = BoundedPolicyRepository(count)
    result = IntelligenceRecordPolicyService(cast(Any, repository)).load_collection()

    assert repository.limits == [101]
    assert (result.candidates is not None) is success
    assert result.failure is failure
    if success:
        assert len(cast(tuple, result.candidates)) == 100


def test_maximum_100_candidates_are_dually_evaluated_and_batch_loaded() -> None:
    candidates = tuple(candidate(index) for index in range(1, 101))
    policies = StaticPolicies(ResourcePolicyCollectionLoadResult.success(candidates))
    content = CollectionContentSpy(tuple(projection(item) for item in candidates))
    actions: list[AuthorizationAction] = []

    def evaluator(_subject, action, _policy):
        actions.append(action)
        return AuthorizationDecision.allow()

    result = collection_service(
        policies, content, evaluator=evaluator
    ).read(valid_subject().identity)

    assert result.outcome is IntelligenceRecordCollectionReadOutcome.AUTHORIZED
    assert len(cast(tuple, result.entries)) == 100
    assert actions.count(AuthorizationAction.SEARCH) == 100
    assert actions.count(AuthorizationAction.READ) == 100
    assert content.calls == [tuple(item.record_id for item in candidates)]


def test_candidate_database_and_invalid_policy_fail_entire_load() -> None:
    failed = IntelligenceRecordPolicyService(
        cast(Any, BoundedPolicyRepository(0, fail=True))
    ).load_collection()
    repository = BoundedPolicyRepository(1)
    invalid_facts = replace(policy_facts(1), status="BROKEN")
    repository.list_policy_records = lambda **_: (  # type: ignore[method-assign]
        invalid_facts,
    )
    invalid = IntelligenceRecordPolicyService(cast(Any, repository)).load_collection()

    assert failed.failure is ResourcePolicyCollectionFailure.LOAD_ERROR
    assert invalid.failure is ResourcePolicyCollectionFailure.INVALID_POLICY


def test_collection_result_invariants_and_raw_string_hardening() -> None:
    assert IntelligenceRecordCollectionReadOutcome.AUTHORIZED != "AUTHORIZED"
    with pytest.raises(ValueError):
        IntelligenceRecordCollectionReadResult(cast(Any, "AUTHORIZED"), ())
    with pytest.raises(ValueError):
        IntelligenceRecordCollectionReadResult(
            IntelligenceRecordCollectionReadOutcome.AUTHORIZED
        )
    with pytest.raises(ValueError):
        IntelligenceRecordCollectionReadResult(
            IntelligenceRecordCollectionReadOutcome.UNAVAILABLE, ()
        )


@pytest.mark.parametrize(
    ("outcome", "status_code", "body"),
    [
        (
            IntelligenceRecordCollectionReadOutcome.UNAVAILABLE,
            503,
            GENERIC_UNAVAILABLE,
        ),
        (
            IntelligenceRecordCollectionReadOutcome.AUTHENTICATION_REQUIRED,
            401,
            {"detail": "Authentication required"},
        ),
    ],
)
def test_collection_route_maps_controlled_failures_to_generic_bodies(
    db_session: Session,
    outcome: IntelligenceRecordCollectionReadOutcome,
    status_code: int,
    body: dict[str, str],
) -> None:
    references = persist_references(db_session)
    user = persist_user(db_session, references)
    token = issue_session(db_session, user)
    application, configured = configure_app(db_session)
    application.dependency_overrides[
        get_intelligence_record_collection_read_service
    ] = lambda: StaticCollectionReadService(
        IntelligenceRecordCollectionReadResult(outcome)
    )

    response = request_collection(application, configured, token)

    assert response.status_code == status_code
    assert response.json() == body


@pytest.mark.parametrize("failure", ["malformed", "exception"])
def test_collection_route_maps_unexpected_service_failure_to_generic_503(
    db_session: Session, failure: str
) -> None:
    references = persist_references(db_session)
    user = persist_user(db_session, references)
    token = issue_session(db_session, user)
    application, configured = configure_app(db_session)
    application.dependency_overrides[
        get_intelligence_record_collection_read_service
    ] = lambda: UnexpectedCollectionReadService(failure)

    response = request_collection(application, configured, token)

    assert response.status_code == 503
    assert response.json() == GENERIC_UNAVAILABLE
    assert "synthetic unexpected collection failure" not in response.text


def test_collection_authentication_infrastructure_failure_remains_owned_by_auth(
    db_session: Session,
) -> None:
    application, configured = configure_app(db_session)
    application.dependency_overrides[get_session_service] = (
        lambda: FailingSessionResolution()
    )

    with TestClient(application) as client:
        client.cookies.set(configured.session_cookie_name, generate_session_token())
        response = client.get("/records")

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service unavailable"}


class StaticCollectionReadService:
    def __init__(self, result: IntelligenceRecordCollectionReadResult) -> None:
        self.result = result

    def read(self, _principal: AuthenticatedPrincipal):
        return self.result


class UnexpectedCollectionReadService:
    def __init__(self, failure: str) -> None:
        self.failure = failure

    def read(self, _principal: AuthenticatedPrincipal):
        if self.failure == "exception":
            raise RuntimeError("synthetic unexpected collection failure")
        return "AUTHORIZED"


class FailingSessionResolution:
    def resolve_session(self, _raw_token: str | None):
        raise RuntimeError("synthetic authentication database failure")
