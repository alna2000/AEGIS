"""Server-side authorization subject persistence and loading tests."""

from datetime import datetime, timezone
from typing import Any, cast
import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value

from aegis.db.authorization_repositories import AuthorizationSubjectRepository
from aegis.db.models import (
    ClearanceLevel,
    Compartment,
    Department,
    Role,
    User,
    UserCompartment,
    UserRole,
)
from aegis.security.authorization import AuthorizationDenyReason, RoleName
from aegis.security.passwords import PasswordService
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.authorization import AuthorizationSubjectService


FIXED_NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
CYBER = uuid.UUID("31000000-0000-0000-0000-000000000001")
SECRET = uuid.UUID("32000000-0000-0000-0000-000000000003")
ANALYST = uuid.UUID("30000000-0000-0000-0000-000000000001")
NIGHTFALL = uuid.UUID("33000000-0000-0000-0000-000000000001")


def persist_reference_data(db_session: Session) -> tuple[
    Department, ClearanceLevel, Role, Compartment
]:
    department = Department(
        id=CYBER,
        name="Cyber Intelligence",
        is_active=True,
    )
    clearance = ClearanceLevel(id=SECRET, name="SECRET", rank=30)
    role = Role(id=ANALYST, name="Analyst", is_active=True)
    compartment = Compartment(
        id=NIGHTFALL,
        name="NIGHTFALL",
        is_active=True,
    )
    db_session.add_all([department, clearance, role, compartment])
    db_session.flush()
    return department, clearance, role, compartment


def persist_user(
    db_session: Session,
    *,
    department: Department | None = None,
    clearance: ClearanceLevel | None = None,
    is_active: bool = True,
) -> User:
    user = User(
        username="synthetic.authorization",
        display_name="Synthetic Authorization User",
        email=None,
        password_hash=PasswordService().hash("Synthetic-Authorization-81!"),
        is_active=is_active,
        disabled_at=None if is_active else FIXED_NOW,
        department=department,
        clearance_level=clearance,
    )
    db_session.add(user)
    db_session.flush()
    return user


def principal_for(user: User) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=user.id,
        username="caller-controlled-name-is-ignored",
        display_name="Caller-Controlled Display Is Ignored",
    )


def load_subject(
    db_session: Session, principal: AuthenticatedPrincipal
):
    return AuthorizationSubjectService(
        AuthorizationSubjectRepository(db_session)
    ).load(principal)


def test_loader_builds_immutable_subject_from_current_database_state(
    db_session: Session,
) -> None:
    department, clearance, role, compartment = persist_reference_data(db_session)
    user = persist_user(db_session, department=department, clearance=clearance)
    db_session.add_all(
        [
            UserRole(
                user=user,
                role=role,
                assigned_at=FIXED_NOW,
                assigned_by_user_id=None,
            ),
            UserCompartment(
                user=user,
                compartment=compartment,
                assigned_at=FIXED_NOW,
                assigned_by_user_id=None,
            ),
        ]
    )
    db_session.flush()
    db_session.expire_all()

    result = load_subject(db_session, principal_for(user))

    assert result.failure_reason is None
    assert result.subject is not None
    assert result.subject.identity.user_id == user.id
    assert result.subject.identity.username == "synthetic.authorization"
    assert result.subject.identity.display_name == "Synthetic Authorization User"
    assert result.subject.account_usable is True
    assert result.subject.active_roles == frozenset({RoleName.ANALYST})
    assert result.subject.department_id == CYBER
    assert result.subject.department_active is True
    assert result.subject.clearance_rank == 30
    assert result.subject.active_compartment_ids == frozenset({NIGHTFALL})
    assert result.subject.state_valid is True


def test_missing_transitional_assignments_remain_missing_and_never_default(
    db_session: Session,
) -> None:
    user = persist_user(db_session)

    result = load_subject(db_session, principal_for(user))

    assert result.subject is not None
    assert result.subject.department_id is None
    assert result.subject.department_active is False
    assert result.subject.clearance_rank is None
    assert result.subject.active_roles == frozenset()
    assert result.subject.active_compartment_ids == frozenset()


def test_inactive_account_is_loaded_as_unusable(db_session: Session) -> None:
    user = persist_user(db_session, is_active=False)

    result = load_subject(db_session, principal_for(user))

    assert result.subject is not None
    assert result.subject.account_usable is False


def test_retired_role_department_and_compartment_never_become_active_facts(
    db_session: Session,
) -> None:
    department, clearance, role, compartment = persist_reference_data(db_session)
    department.is_active = False
    department.retired_at = FIXED_NOW
    role.is_active = False
    role.retired_at = FIXED_NOW
    compartment.is_active = False
    compartment.retired_at = FIXED_NOW
    user = persist_user(db_session, department=department, clearance=clearance)
    db_session.add_all(
        [
            UserRole(user=user, role=role, assigned_at=FIXED_NOW),
            UserCompartment(
                user=user, compartment=compartment, assigned_at=FIXED_NOW
            ),
        ]
    )
    db_session.flush()

    result = load_subject(db_session, principal_for(user))

    assert result.subject is not None
    assert result.subject.department_id == CYBER
    assert result.subject.department_active is False
    assert result.subject.active_roles == frozenset()
    assert result.subject.active_compartment_ids == frozenset()
    assert result.subject.state_valid is True


def test_unknown_or_malformed_reference_state_marks_subject_invalid(
    db_session: Session,
) -> None:
    department, clearance, role, _ = persist_reference_data(db_session)
    user = persist_user(db_session, department=department, clearance=clearance)
    assignment = UserRole(user=user, role=role, assigned_at=FIXED_NOW)
    db_session.add(assignment)
    db_session.flush()
    _ = user.role_assignments
    role.name = "Unexpected Role"

    with db_session.no_autoflush:
        result = AuthorizationSubjectService._convert(user)

    assert result.state_valid is False
    assert result.active_roles == frozenset()


def test_duplicate_loaded_assignment_state_marks_subject_invalid(
    db_session: Session,
) -> None:
    department, clearance, role, _ = persist_reference_data(db_session)
    user = persist_user(db_session, department=department, clearance=clearance)
    assignment = UserRole(user=user, role=role, assigned_at=FIXED_NOW)
    set_committed_value(user, "role_assignments", [assignment, assignment])

    with db_session.no_autoflush:
        converted = AuthorizationSubjectService._convert(user)

    assert converted.state_valid is False


def test_missing_user_and_database_failure_return_controlled_failures(
    db_session: Session,
) -> None:
    missing = AuthenticatedPrincipal(
        user_id=uuid.uuid4(),
        username="synthetic.missing",
        display_name="Synthetic Missing",
    )
    assert load_subject(db_session, missing).failure_reason is (
        AuthorizationDenyReason.SUBJECT_MISSING
    )

    class FailingRepository:
        def get_by_user_id(self, _user_id: uuid.UUID) -> User | None:
            raise RuntimeError("synthetic database failure")

    service = AuthorizationSubjectService(
        cast(Any, FailingRepository())
    )
    assert service.load(missing).failure_reason is (
        AuthorizationDenyReason.SUBJECT_LOAD_ERROR
    )


def test_assignment_pairs_are_unique_and_self_assignment_is_rejected(
    db_session: Session,
) -> None:
    department, clearance, role, _ = persist_reference_data(db_session)
    user = persist_user(db_session, department=department, clearance=clearance)
    db_session.add(UserRole(user=user, role=role, assigned_at=FIXED_NOW))
    db_session.flush()

    db_session.add(
        UserRole(
            user_id=user.id,
            role_id=role.id,
            assigned_at=FIXED_NOW,
        )
    )
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    department, clearance, role, _ = persist_reference_data(db_session)
    user = persist_user(db_session, department=department, clearance=clearance)
    db_session.add(
        UserRole(
            user=user,
            role=role,
            assigned_at=FIXED_NOW,
            assigned_by_user_id=user.id,
        )
    )
    with pytest.raises(IntegrityError):
        db_session.flush()
