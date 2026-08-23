"""Convert authoritative persistence state into immutable authorization facts."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from aegis.db.authorization_repositories import AuthorizationSubjectRepository
from aegis.db.models import User
from aegis.security.authorization import (
    AuthorizationDenyReason,
    AuthorizationSubject,
    CONTROLLED_CLEARANCE_NAME_RANKS,
    CONTROLLED_COMPARTMENT_NAMES,
    CONTROLLED_DEPARTMENT_NAMES,
    RoleName,
)
from aegis.services.authentication import AuthenticatedPrincipal


@dataclass(frozen=True, slots=True)
class AuthorizationSubjectLoadResult:
    """Controlled success or failure from authoritative subject loading."""

    subject: AuthorizationSubject | None
    failure_reason: AuthorizationDenyReason | None

    def __post_init__(self) -> None:
        if (self.subject is None) == (self.failure_reason is None):
            raise ValueError("subject loading requires exactly one result state")

    @classmethod
    def success(
        cls, subject: AuthorizationSubject
    ) -> AuthorizationSubjectLoadResult:
        return cls(subject=subject, failure_reason=None)

    @classmethod
    def failure(
        cls, reason: AuthorizationDenyReason
    ) -> AuthorizationSubjectLoadResult:
        return cls(subject=None, failure_reason=reason)


class AuthorizationSubjectService:
    """Load authorization state by server-controlled authenticated user ID."""

    def __init__(self, subjects: AuthorizationSubjectRepository) -> None:
        self._subjects = subjects

    def load(
        self, principal: AuthenticatedPrincipal
    ) -> AuthorizationSubjectLoadResult:
        if not isinstance(principal, AuthenticatedPrincipal) or not isinstance(
            principal.user_id, uuid.UUID
        ):
            return AuthorizationSubjectLoadResult.failure(
                AuthorizationDenyReason.SUBJECT_MISSING
            )
        try:
            user = self._subjects.get_by_user_id(principal.user_id)
            if user is None:
                return AuthorizationSubjectLoadResult.failure(
                    AuthorizationDenyReason.SUBJECT_MISSING
                )
            return AuthorizationSubjectLoadResult.success(self._convert(user))
        except Exception:
            return AuthorizationSubjectLoadResult.failure(
                AuthorizationDenyReason.SUBJECT_LOAD_ERROR
            )

    @staticmethod
    def _convert(user: User) -> AuthorizationSubject:
        state_valid = True

        active_roles: set[RoleName] = set()
        seen_role_ids: set[uuid.UUID] = set()
        for assignment in user.role_assignments:
            role = assignment.role
            if (
                role is None
                or assignment.role_id in seen_role_ids
                or role.id != assignment.role_id
                or not _valid_assignment_time(assignment.assigned_at)
            ):
                state_valid = False
                continue
            seen_role_ids.add(assignment.role_id)
            try:
                role_name = RoleName(role.name)
            except (TypeError, ValueError):
                state_valid = False
                continue
            if not _valid_lifecycle(role.is_active, role.retired_at):
                state_valid = False
                continue
            if role.is_active:
                active_roles.add(role_name)

        department_id = user.department_id
        department_active = False
        if user.department is None:
            if department_id is not None:
                state_valid = False
        elif (
            user.department.id != department_id
            or user.department.name not in CONTROLLED_DEPARTMENT_NAMES
            or not _valid_lifecycle(
                user.department.is_active, user.department.retired_at
            )
        ):
            state_valid = False
        else:
            department_active = user.department.is_active

        clearance_rank: int | None = None
        if user.clearance_level is None:
            if user.clearance_level_id is not None:
                state_valid = False
        elif (
            user.clearance_level.id != user.clearance_level_id
            or CONTROLLED_CLEARANCE_NAME_RANKS.get(user.clearance_level.name)
            != user.clearance_level.rank
        ):
            state_valid = False
        else:
            clearance_rank = user.clearance_level.rank

        active_compartment_ids: set[uuid.UUID] = set()
        seen_compartment_ids: set[uuid.UUID] = set()
        for assignment in user.compartment_assignments:
            compartment = assignment.compartment
            if (
                compartment is None
                or assignment.compartment_id in seen_compartment_ids
                or compartment.id != assignment.compartment_id
                or compartment.name not in CONTROLLED_COMPARTMENT_NAMES
                or not _valid_assignment_time(assignment.assigned_at)
            ):
                state_valid = False
                continue
            seen_compartment_ids.add(assignment.compartment_id)
            if not _valid_lifecycle(compartment.is_active, compartment.retired_at):
                state_valid = False
                continue
            if compartment.is_active:
                active_compartment_ids.add(compartment.id)

        return AuthorizationSubject(
            identity=AuthenticatedPrincipal(
                user_id=user.id,
                username=user.username,
                display_name=user.display_name,
            ),
            account_usable=user.is_usable_for_authentication,
            active_roles=frozenset(active_roles),
            department_id=department_id,
            department_active=department_active,
            clearance_rank=clearance_rank,
            active_compartment_ids=frozenset(active_compartment_ids),
            state_valid=state_valid,
        )


def _valid_lifecycle(is_active: object, retired_at: object) -> bool:
    return type(is_active) is bool and (
        (is_active and retired_at is None)
        or (not is_active and _valid_assignment_time(retired_at))
    )


def _valid_assignment_time(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )
