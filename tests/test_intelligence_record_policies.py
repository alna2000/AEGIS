"""Record policy loading, conversion, and central evaluator integration tests."""

from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, cast
import uuid

import pytest
from sqlalchemy.orm import Session

from aegis.db.intelligence_record_repositories import (
    ActiveReferencePolicyFacts,
    ClearancePolicyFacts,
    IntelligenceRecordPolicyFacts,
    IntelligenceRecordPolicyRepository,
    RecordReferencePolicyFacts,
)
from aegis.db.models import (
    ClearanceLevel,
    Compartment,
    Department,
    IntelligenceRecord,
    IntelligenceRecordStatus,
    RecordCompartment,
    RecordDepartment,
    User,
)
from aegis.security.authorization import (
    AuthorizationAction,
    AuthorizationDenyReason,
    AuthorizationOutcome,
    AuthorizationSubject,
    RoleName,
    authorize,
)
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.intelligence_records import IntelligenceRecordPolicyService


FIXED_NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
CYBER_ID = uuid.UUID("31000000-0000-0000-0000-000000000001")
COUNTERINTEL_ID = uuid.UUID("31000000-0000-0000-0000-000000000002")
SECRET_ID = uuid.UUID("32000000-0000-0000-0000-000000000003")
NIGHTFALL_ID = uuid.UUID("33000000-0000-0000-0000-000000000001")
ORION_ID = uuid.UUID("33000000-0000-0000-0000-000000000002")


def persist_policy_record(
    db_session: Session,
    *,
    status: IntelligenceRecordStatus = IntelligenceRecordStatus.ACTIVE,
    department_count: int = 1,
    compartment_count: int = 0,
) -> tuple[IntelligenceRecord, User, list[Department], list[Compartment]]:
    clearance = ClearanceLevel(id=SECRET_ID, name="SECRET", rank=30)
    departments = [
        Department(id=CYBER_ID, name="Cyber Intelligence", is_active=True),
        Department(
            id=COUNTERINTEL_ID,
            name="Counterintelligence",
            is_active=True,
        ),
    ]
    compartments = [
        Compartment(id=NIGHTFALL_ID, name="NIGHTFALL", is_active=True),
        Compartment(id=ORION_ID, name="ORION", is_active=True),
    ]
    creator = User(
        username="synthetic.policy.creator",
        display_name="Synthetic Policy Creator",
        password_hash="synthetic-nonempty-verifier",
        is_active=True,
    )
    record = IntelligenceRecord(
        record_code="INT-00482",
        title="Synthetic Policy Record",
        summary=None,
        content="Synthetic content is deliberately absent from policy facts.",
        classification_level=clearance,
        creator=creator,
        status=status,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        retired_at=FIXED_NOW if status is IntelligenceRecordStatus.RETIRED else None,
    )
    record.department_assignments.extend(
        RecordDepartment(department=department)
        for department in departments[:department_count]
    )
    record.compartment_assignments.extend(
        RecordCompartment(compartment=compartment)
        for compartment in compartments[:compartment_count]
    )
    db_session.add_all([*departments, *compartments, record])
    db_session.flush()
    return record, creator, departments, compartments


def load_policy(db_session: Session, record_id: uuid.UUID):
    db_session.expire_all()
    return IntelligenceRecordPolicyService(
        IntelligenceRecordPolicyRepository(db_session)
    ).load(record_id)


def subject_for(
    user: User,
    *,
    roles: frozenset[RoleName] = frozenset({RoleName.ANALYST}),
    department_id: uuid.UUID = CYBER_ID,
    clearance_rank: int = 30,
    compartments: frozenset[uuid.UUID] = frozenset(),
) -> AuthorizationSubject:
    return AuthorizationSubject(
        identity=AuthenticatedPrincipal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
        ),
        account_usable=True,
        active_roles=roles,
        department_id=department_id,
        department_active=True,
        clearance_rank=clearance_rank,
        active_compartment_ids=compartments,
    )


@pytest.mark.parametrize(
    ("department_count", "compartment_count"),
    [(1, 0), (2, 1), (2, 2)],
)
def test_active_record_converts_normalized_relationships_to_resource_policy(
    db_session: Session,
    department_count: int,
    compartment_count: int,
) -> None:
    record, _, departments, compartments = persist_policy_record(
        db_session,
        department_count=department_count,
        compartment_count=compartment_count,
    )

    result = load_policy(db_session, record.id)

    assert result.failure_reason is None
    assert result.record_id == record.id
    assert result.policy is not None
    assert result.policy.usable is True
    assert result.policy.classification_rank == 30
    assert result.policy.authorized_department_ids == frozenset(
        department.id for department in departments[:department_count]
    )
    assert result.policy.required_compartment_ids == frozenset(
        compartment.id for compartment in compartments[:compartment_count]
    )


@pytest.mark.parametrize(
    "status", [IntelligenceRecordStatus.DRAFT, IntelligenceRecordStatus.RETIRED]
)
def test_draft_and_retired_records_convert_to_unusable_policy(
    db_session: Session, status: IntelligenceRecordStatus
) -> None:
    record, creator, _, _ = persist_policy_record(
        db_session,
        status=status,
        department_count=0 if status is IntelligenceRecordStatus.DRAFT else 1,
    )

    result = load_policy(db_session, record.id)

    assert result.policy is not None
    assert result.policy.usable is False
    assert authorize(
        subject_for(creator), AuthorizationAction.READ, result.policy
    ).deny_reason is AuthorizationDenyReason.RESOURCE_UNUSABLE


def test_active_record_without_department_policy_fails_closed(
    db_session: Session,
) -> None:
    record, _, _, _ = persist_policy_record(db_session, department_count=0)

    result = load_policy(db_session, record.id)

    assert result.policy is None
    assert result.failure_reason is AuthorizationDenyReason.INVALID_RESOURCE_POLICY


@pytest.mark.parametrize("invalid_reference", ["department", "compartment"])
def test_inactive_record_reference_fails_closed(
    db_session: Session, invalid_reference: str
) -> None:
    record, _, departments, compartments = persist_policy_record(
        db_session,
        compartment_count=1,
    )
    reference = departments[0] if invalid_reference == "department" else compartments[0]
    reference.is_active = False
    reference.retired_at = FIXED_NOW
    db_session.flush()

    result = load_policy(db_session, record.id)

    assert result.policy is None
    assert result.failure_reason is AuthorizationDenyReason.INVALID_RESOURCE_POLICY


def test_invalid_classification_and_malformed_relationships_fail_closed(
    db_session: Session,
) -> None:
    record, _, _, _ = persist_policy_record(db_session)
    repository = IntelligenceRecordPolicyRepository(db_session)
    facts = repository.get_policy_record_by_id(record.id)
    assert facts is not None
    assert facts.classification is not None
    invalid_classification = replace(
        facts,
        classification=replace(facts.classification, rank=999),
    )
    duplicate_relationship = replace(
        facts,
        department_relationships=(
            facts.department_relationships[0],
            facts.department_relationships[0],
        ),
    )
    missing_reference = replace(
        facts,
        department_relationships=(
            replace(facts.department_relationships[0], reference=None),
        ),
    )

    for malformed in (
        invalid_classification,
        duplicate_relationship,
        missing_reference,
        replace(facts, record_code="int-00482"),
    ):
        service = IntelligenceRecordPolicyService(
            cast(Any, StaticRepository(malformed))
        )
        result = service.load(record.id)
        assert result.policy is None
        assert result.failure_reason is (
            AuthorizationDenyReason.INVALID_RESOURCE_POLICY
        )


def test_missing_record_and_database_error_are_controlled(
    db_session: Session,
) -> None:
    missing_id = uuid.uuid4()
    missing = load_policy(db_session, missing_id)
    assert missing.failure_reason is AuthorizationDenyReason.RESOURCE_MISSING

    failing = IntelligenceRecordPolicyService(cast(Any, FailingRepository()))
    failed = failing.load(missing_id)
    assert failed.failure_reason is AuthorizationDenyReason.RESOURCE_LOAD_ERROR


def test_repository_returns_restricted_policy_facts_without_content(
    db_session: Session,
) -> None:
    record, _, _, _ = persist_policy_record(db_session)

    facts = IntelligenceRecordPolicyRepository(db_session).get_policy_record_by_id(
        record.id
    )

    assert isinstance(facts, IntelligenceRecordPolicyFacts)
    assert not hasattr(facts, "content")
    assert not hasattr(facts, "title")
    assert not hasattr(facts, "summary")


def test_persisted_policy_uses_existing_evaluator_for_allow_and_deny(
    db_session: Session,
) -> None:
    record, creator, _, _ = persist_policy_record(
        db_session,
        department_count=2,
        compartment_count=2,
    )
    result = load_policy(db_session, record.id)
    assert result.policy is not None
    policy = result.policy

    allowed = authorize(
        subject_for(
            creator,
            compartments=frozenset({NIGHTFALL_ID, ORION_ID}),
        ),
        AuthorizationAction.READ,
        policy,
    )
    assert allowed.outcome is AuthorizationOutcome.ALLOW

    insufficient = authorize(
        subject_for(
            creator,
            clearance_rank=20,
            compartments=frozenset({NIGHTFALL_ID, ORION_ID}),
        ),
        AuthorizationAction.READ,
        policy,
    )
    assert insufficient.deny_reason is AuthorizationDenyReason.INSUFFICIENT_CLEARANCE

    wrong_department = authorize(
        subject_for(
            creator,
            department_id=uuid.uuid4(),
            compartments=frozenset({NIGHTFALL_ID, ORION_ID}),
        ),
        AuthorizationAction.READ,
        policy,
    )
    assert wrong_department.deny_reason is (
        AuthorizationDenyReason.DEPARTMENT_NOT_AUTHORIZED
    )

    missing_compartment = authorize(
        subject_for(creator, compartments=frozenset({NIGHTFALL_ID})),
        AuthorizationAction.READ,
        policy,
    )
    assert missing_compartment.deny_reason is (
        AuthorizationDenyReason.MISSING_COMPARTMENT
    )


def test_creator_and_identifier_alone_never_authorize(db_session: Session) -> None:
    record, creator, _, _ = persist_policy_record(db_session)
    result = load_policy(db_session, record.id)
    assert result.policy is not None

    creator_only = authorize(
        subject_for(creator, roles=frozenset()),
        AuthorizationAction.READ,
        result.policy,
    )
    assert creator_only.deny_reason is AuthorizationDenyReason.NO_ROLE_CAPABILITY
    identifier_only = authorize(None, AuthorizationAction.READ, result.policy)
    assert identifier_only.deny_reason is AuthorizationDenyReason.SUBJECT_MISSING


class StaticRepository:
    def __init__(self, facts: IntelligenceRecordPolicyFacts) -> None:
        self._facts = facts

    def get_policy_record_by_id(
        self, _record_id: uuid.UUID
    ) -> IntelligenceRecordPolicyFacts:
        return self._facts


class FailingRepository:
    def get_policy_record_by_id(
        self, _record_id: uuid.UUID
    ) -> IntelligenceRecordPolicyFacts | None:
        raise RuntimeError("synthetic database failure")


def test_unexpected_fact_shape_never_produces_policy() -> None:
    relationship = RecordReferencePolicyFacts(
        record_id=uuid.uuid4(),
        reference_id=uuid.uuid4(),
        reference=ActiveReferencePolicyFacts(
            id=uuid.uuid4(),
            name="Cyber Intelligence",
            is_active=True,
            retired_at=None,
        ),
    )
    facts = IntelligenceRecordPolicyFacts(
        id=relationship.record_id,
        record_code="INT-00001",
        status=IntelligenceRecordStatus.ACTIVE.value,
        classification_level_id=SECRET_ID,
        classification=ClearancePolicyFacts(
            id=SECRET_ID,
            name="SECRET",
            rank=30,
        ),
        created_by_user_id=uuid.uuid4(),
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        retired_at=None,
        department_relationships=(relationship,),
        compartment_relationships=(),
    )

    result = IntelligenceRecordPolicyService(
        cast(Any, StaticRepository(facts))
    ).load(facts.id)

    assert result.policy is None
    assert result.failure_reason is AuthorizationDenyReason.INVALID_RESOURCE_POLICY
