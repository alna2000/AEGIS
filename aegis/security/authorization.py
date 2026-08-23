"""Pure, typed, default-deny authorization policy boundary."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping

from aegis.services.authentication import AuthenticatedPrincipal


class AuthorizationAction(str, Enum):
    READ = "READ"
    SEARCH = "SEARCH"
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    EXPORT = "EXPORT"
    ADMINISTER = "ADMINISTER"
    AUDIT = "AUDIT"


class AuthorizationResourceType(str, Enum):
    INTELLIGENCE_RECORD = "INTELLIGENCE_RECORD"
    USER_ACCOUNT = "USER_ACCOUNT"
    AUDIT_EVENT = "AUDIT_EVENT"
    SYSTEM_CONFIGURATION = "SYSTEM_CONFIGURATION"


class AuthorizationOutcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class AuthorizationDenyReason(str, Enum):
    SUBJECT_MISSING = "SUBJECT_MISSING"
    SUBJECT_UNUSABLE = "SUBJECT_UNUSABLE"
    SUBJECT_POLICY_INVALID = "SUBJECT_POLICY_INVALID"
    SUBJECT_LOAD_ERROR = "SUBJECT_LOAD_ERROR"
    NO_ROLE_CAPABILITY = "NO_ROLE_CAPABILITY"
    MISSING_DEPARTMENT = "MISSING_DEPARTMENT"
    INVALID_DEPARTMENT = "INVALID_DEPARTMENT"
    DEPARTMENT_NOT_AUTHORIZED = "DEPARTMENT_NOT_AUTHORIZED"
    MISSING_CLEARANCE = "MISSING_CLEARANCE"
    INSUFFICIENT_CLEARANCE = "INSUFFICIENT_CLEARANCE"
    MISSING_COMPARTMENT = "MISSING_COMPARTMENT"
    INVALID_RESOURCE_POLICY = "INVALID_RESOURCE_POLICY"
    RESOURCE_UNUSABLE = "RESOURCE_UNUSABLE"
    RESOURCE_MISSING = "RESOURCE_MISSING"
    RESOURCE_LOAD_ERROR = "RESOURCE_LOAD_ERROR"
    UNSUPPORTED_ACTION = "UNSUPPORTED_ACTION"
    UNSUPPORTED_RESOURCE_TYPE = "UNSUPPORTED_RESOURCE_TYPE"
    POLICY_EVALUATION_ERROR = "POLICY_EVALUATION_ERROR"


class RoleName(str, Enum):
    ANALYST = "Analyst"
    SENIOR_ANALYST = "Senior Analyst"
    SUPERVISOR = "Supervisor"
    SECURITY_AUDITOR = "Security Auditor"
    SYSTEM_ADMINISTRATOR = "System Administrator"


CONTROLLED_CLEARANCE_NAME_RANKS: Mapping[str, int] = MappingProxyType(
    {
        "UNCLASSIFIED": 10,
        "CONFIDENTIAL": 20,
        "SECRET": 30,
        "TOP SECRET": 40,
    }
)
CONTROLLED_CLEARANCE_RANKS = frozenset(CONTROLLED_CLEARANCE_NAME_RANKS.values())
CONTROLLED_DEPARTMENT_NAMES = frozenset(
    {
        "Cyber Intelligence",
        "Counterintelligence",
        "Strategic Analysis",
        "Operations",
    }
)
CONTROLLED_COMPARTMENT_NAMES = frozenset({"NIGHTFALL", "ORION", "SENTINEL"})


@dataclass(frozen=True, slots=True)
class AuthorizationSubject:
    """Current server-loaded authorization facts, separate from authentication."""

    identity: AuthenticatedPrincipal
    account_usable: bool
    active_roles: frozenset[RoleName]
    department_id: uuid.UUID | None
    department_active: bool
    clearance_rank: int | None
    active_compartment_ids: frozenset[uuid.UUID]
    state_valid: bool = True


@dataclass(frozen=True, slots=True)
class ResourcePolicy:
    """Content-free internal policy snapshot for one candidate resource."""

    resource_type: AuthorizationResourceType
    usable: bool = True
    classification_rank: int | None = None
    authorized_department_ids: frozenset[uuid.UUID] = frozenset()
    required_compartment_ids: frozenset[uuid.UUID] = frozenset()


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """One explicit policy result with an internal reason only for denial."""

    outcome: AuthorizationOutcome
    deny_reason: AuthorizationDenyReason | None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, AuthorizationOutcome):
            raise ValueError("authorization outcome must be a controlled enum")
        if self.deny_reason is not None and not isinstance(
            self.deny_reason, AuthorizationDenyReason
        ):
            raise ValueError("deny reason must be a controlled enum")
        if self.outcome is AuthorizationOutcome.ALLOW and self.deny_reason is not None:
            raise ValueError("an ALLOW decision cannot contain a deny reason")
        if self.outcome is AuthorizationOutcome.DENY and self.deny_reason is None:
            raise ValueError("a DENY decision requires a controlled reason")

    @classmethod
    def allow(cls) -> AuthorizationDecision:
        return cls(AuthorizationOutcome.ALLOW, None)

    @classmethod
    def deny(cls, reason: AuthorizationDenyReason) -> AuthorizationDecision:
        return cls(AuthorizationOutcome.DENY, reason)


# Capabilities permit policy evaluation to continue; they are not unconditional
# operational grants. Future endpoint-owning parts must add every applicable
# action-specific workflow/context restriction to the central policy boundary.
_ANALYST_INTELLIGENCE_ACTIONS = frozenset(
    {
        AuthorizationAction.READ,
        AuthorizationAction.SEARCH,
        AuthorizationAction.CREATE,
        AuthorizationAction.UPDATE,
    }
)


ROLE_CAPABILITIES: Mapping[
    RoleName,
    Mapping[AuthorizationResourceType, frozenset[AuthorizationAction]],
] = MappingProxyType(
    {
        RoleName.ANALYST: MappingProxyType(
            {
                AuthorizationResourceType.INTELLIGENCE_RECORD: (
                    _ANALYST_INTELLIGENCE_ACTIONS
                )
            }
        ),
        RoleName.SENIOR_ANALYST: MappingProxyType(
            {
                AuthorizationResourceType.INTELLIGENCE_RECORD: (
                    _ANALYST_INTELLIGENCE_ACTIONS
                    | {AuthorizationAction.EXPORT}
                )
            }
        ),
        RoleName.SUPERVISOR: MappingProxyType(
            {
                AuthorizationResourceType.INTELLIGENCE_RECORD: (
                    _ANALYST_INTELLIGENCE_ACTIONS
                    | {AuthorizationAction.DELETE, AuthorizationAction.EXPORT}
                )
            }
        ),
        RoleName.SECURITY_AUDITOR: MappingProxyType(
            {
                AuthorizationResourceType.AUDIT_EVENT: frozenset(
                    {AuthorizationAction.AUDIT}
                )
            }
        ),
        RoleName.SYSTEM_ADMINISTRATOR: MappingProxyType(
            {
                AuthorizationResourceType.USER_ACCOUNT: frozenset(
                    {AuthorizationAction.ADMINISTER}
                ),
                AuthorizationResourceType.SYSTEM_CONFIGURATION: frozenset(
                    {AuthorizationAction.ADMINISTER}
                ),
            }
        ),
    }
)


def authorize(
    subject: AuthorizationSubject | None,
    action: AuthorizationAction,
    resource_policy: ResourcePolicy,
) -> AuthorizationDecision:
    """Evaluate Part 1 facts deterministically; unexpected errors deny.

    Part 1 has no endpoint enforcement. An action capability never waives future
    workflow/context restrictions that must be added before operational use.
    """

    try:
        return _evaluate_authorization(subject, action, resource_policy)
    except Exception:
        return AuthorizationDecision.deny(
            AuthorizationDenyReason.POLICY_EVALUATION_ERROR
        )


def _evaluate_authorization(
    subject: AuthorizationSubject | None,
    action: AuthorizationAction,
    resource_policy: ResourcePolicy,
) -> AuthorizationDecision:
    if not isinstance(action, AuthorizationAction):
        return AuthorizationDecision.deny(AuthorizationDenyReason.UNSUPPORTED_ACTION)
    if subject is None:
        return AuthorizationDecision.deny(AuthorizationDenyReason.SUBJECT_MISSING)
    if not isinstance(subject, AuthorizationSubject) or not _valid_subject(subject):
        return AuthorizationDecision.deny(
            AuthorizationDenyReason.SUBJECT_POLICY_INVALID
        )
    if subject.account_usable is not True:
        return AuthorizationDecision.deny(AuthorizationDenyReason.SUBJECT_UNUSABLE)
    if subject.state_valid is not True:
        return AuthorizationDecision.deny(
            AuthorizationDenyReason.SUBJECT_POLICY_INVALID
        )
    if not isinstance(resource_policy, ResourcePolicy):
        return AuthorizationDecision.deny(
            AuthorizationDenyReason.INVALID_RESOURCE_POLICY
        )
    if not isinstance(resource_policy.resource_type, AuthorizationResourceType):
        return AuthorizationDecision.deny(
            AuthorizationDenyReason.UNSUPPORTED_RESOURCE_TYPE
        )
    if resource_policy.usable is not True:
        return AuthorizationDecision.deny(AuthorizationDenyReason.RESOURCE_UNUSABLE)

    if not _role_permits(subject, action, resource_policy.resource_type):
        return AuthorizationDecision.deny(
            AuthorizationDenyReason.NO_ROLE_CAPABILITY
        )

    if (
        resource_policy.resource_type
        is not AuthorizationResourceType.INTELLIGENCE_RECORD
    ):
        if not _valid_non_intelligence_policy(resource_policy):
            return AuthorizationDecision.deny(
                AuthorizationDenyReason.INVALID_RESOURCE_POLICY
            )
        return AuthorizationDecision.allow()

    if not _valid_classified_resource_policy(resource_policy):
        return AuthorizationDecision.deny(
            AuthorizationDenyReason.INVALID_RESOURCE_POLICY
        )
    if subject.clearance_rank is None:
        return AuthorizationDecision.deny(AuthorizationDenyReason.MISSING_CLEARANCE)
    if not _valid_clearance_rank(subject.clearance_rank):
        return AuthorizationDecision.deny(
            AuthorizationDenyReason.SUBJECT_POLICY_INVALID
        )
    if subject.clearance_rank < resource_policy.classification_rank:
        return AuthorizationDecision.deny(
            AuthorizationDenyReason.INSUFFICIENT_CLEARANCE
        )
    if subject.department_id is None:
        return AuthorizationDecision.deny(AuthorizationDenyReason.MISSING_DEPARTMENT)
    if subject.department_active is not True:
        return AuthorizationDecision.deny(AuthorizationDenyReason.INVALID_DEPARTMENT)
    if subject.department_id not in resource_policy.authorized_department_ids:
        return AuthorizationDecision.deny(
            AuthorizationDenyReason.DEPARTMENT_NOT_AUTHORIZED
        )
    if not resource_policy.required_compartment_ids.issubset(
        subject.active_compartment_ids
    ):
        return AuthorizationDecision.deny(
            AuthorizationDenyReason.MISSING_COMPARTMENT
        )
    return AuthorizationDecision.allow()


def _valid_subject(subject: AuthorizationSubject) -> bool:
    return (
        isinstance(subject.identity, AuthenticatedPrincipal)
        and isinstance(subject.identity.user_id, uuid.UUID)
        and isinstance(subject.identity.username, str)
        and bool(subject.identity.username)
        and isinstance(subject.identity.display_name, str)
        and bool(subject.identity.display_name)
        and type(subject.account_usable) is bool
        and type(subject.department_active) is bool
        and type(subject.state_valid) is bool
        and _valid_role_set(subject.active_roles)
        and (
            subject.department_id is None
            or isinstance(subject.department_id, uuid.UUID)
        )
        and (
            subject.clearance_rank is None
            or type(subject.clearance_rank) is int
        )
        and _valid_uuid_set(subject.active_compartment_ids)
    )


def _valid_role_set(value: object) -> bool:
    return type(value) is frozenset and all(
        isinstance(role, RoleName) for role in value
    )


def _valid_uuid_set(value: object) -> bool:
    return type(value) is frozenset and all(
        isinstance(identifier, uuid.UUID) for identifier in value
    )


def _valid_clearance_rank(value: object) -> bool:
    return type(value) is int and value in CONTROLLED_CLEARANCE_RANKS


def _role_permits(
    subject: AuthorizationSubject,
    action: AuthorizationAction,
    resource_type: AuthorizationResourceType,
) -> bool:
    return any(
        action in ROLE_CAPABILITIES[role].get(resource_type, frozenset())
        for role in subject.active_roles
    )


def _valid_non_intelligence_policy(resource_policy: ResourcePolicy) -> bool:
    return (
        resource_policy.classification_rank is None
        and _valid_uuid_set(resource_policy.authorized_department_ids)
        and not resource_policy.authorized_department_ids
        and _valid_uuid_set(resource_policy.required_compartment_ids)
        and not resource_policy.required_compartment_ids
    )


def _valid_classified_resource_policy(resource_policy: ResourcePolicy) -> bool:
    return (
        _valid_clearance_rank(resource_policy.classification_rank)
        and _valid_uuid_set(resource_policy.authorized_department_ids)
        and bool(resource_policy.authorized_department_ids)
        and _valid_uuid_set(resource_policy.required_compartment_ids)
    )
