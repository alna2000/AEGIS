"""Pure centralized authorization policy tests."""

from dataclasses import fields
from typing import Any, cast
import uuid

import pytest

import aegis.security.authorization as authorization_module
from aegis.security.authorization import (
    ROLE_CAPABILITIES,
    AuthorizationAction,
    AuthorizationDecision,
    AuthorizationDenyReason,
    AuthorizationOutcome,
    AuthorizationResourceType,
    AuthorizationSubject,
    ResourcePolicy,
    RoleName,
    authorize,
)
from aegis.services.authentication import AuthenticatedPrincipal


CYBER = uuid.UUID("31000000-0000-0000-0000-000000000001")
OPERATIONS = uuid.UUID("31000000-0000-0000-0000-000000000004")
NIGHTFALL = uuid.UUID("33000000-0000-0000-0000-000000000001")
ORION = uuid.UUID("33000000-0000-0000-0000-000000000002")


def subject(
    *,
    roles: frozenset[RoleName] = frozenset({RoleName.ANALYST}),
    clearance_rank: int | None = 30,
    department_id: uuid.UUID | None = CYBER,
    department_active: bool = True,
    compartments: frozenset[uuid.UUID] = frozenset(),
    account_usable: bool = True,
    state_valid: bool = True,
) -> AuthorizationSubject:
    return AuthorizationSubject(
        identity=AuthenticatedPrincipal(
            user_id=uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            username="synthetic.subject",
            display_name="Synthetic Subject",
        ),
        account_usable=account_usable,
        active_roles=roles,
        department_id=department_id,
        department_active=department_active,
        clearance_rank=clearance_rank,
        active_compartment_ids=compartments,
        state_valid=state_valid,
    )


def intelligence_policy(
    *,
    classification_rank: int | None = 20,
    departments: frozenset[uuid.UUID] = frozenset({CYBER}),
    compartments: frozenset[uuid.UUID] = frozenset(),
    usable: bool = True,
) -> ResourcePolicy:
    return ResourcePolicy(
        resource_type=AuthorizationResourceType.INTELLIGENCE_RECORD,
        usable=usable,
        classification_rank=classification_rank,
        authorized_department_ids=departments,
        required_compartment_ids=compartments,
    )


@pytest.mark.parametrize(
    ("current_subject", "policy"),
    [
        (subject(clearance_rank=30), intelligence_policy(classification_rank=20)),
        (subject(clearance_rank=30), intelligence_policy(classification_rank=30)),
        (subject(clearance_rank=40), intelligence_policy(classification_rank=30)),
        (
            subject(compartments=frozenset({NIGHTFALL})),
            intelligence_policy(compartments=frozenset({NIGHTFALL})),
        ),
        (
            subject(compartments=frozenset({NIGHTFALL, ORION})),
            intelligence_policy(compartments=frozenset({NIGHTFALL, ORION})),
        ),
        (
            subject(department_id=OPERATIONS),
            intelligence_policy(departments=frozenset({CYBER, OPERATIONS})),
        ),
    ],
)
def test_classified_intelligence_positive_cases_allow(
    current_subject: AuthorizationSubject,
    policy: ResourcePolicy,
) -> None:
    assert authorize(current_subject, AuthorizationAction.READ, policy) == (
        AuthorizationDecision.allow()
    )


@pytest.mark.parametrize(
    ("current_subject", "policy", "expected_reason"),
    [
        (
            subject(account_usable=False),
            intelligence_policy(),
            AuthorizationDenyReason.SUBJECT_UNUSABLE,
        ),
        (
            subject(roles=frozenset()),
            intelligence_policy(),
            AuthorizationDenyReason.NO_ROLE_CAPABILITY,
        ),
        (
            subject(department_id=None, department_active=False),
            intelligence_policy(),
            AuthorizationDenyReason.MISSING_DEPARTMENT,
        ),
        (
            subject(department_active=False),
            intelligence_policy(),
            AuthorizationDenyReason.INVALID_DEPARTMENT,
        ),
        (
            subject(department_id=OPERATIONS),
            intelligence_policy(),
            AuthorizationDenyReason.DEPARTMENT_NOT_AUTHORIZED,
        ),
        (
            subject(clearance_rank=None),
            intelligence_policy(),
            AuthorizationDenyReason.MISSING_CLEARANCE,
        ),
        (
            subject(clearance_rank=20),
            intelligence_policy(classification_rank=30),
            AuthorizationDenyReason.INSUFFICIENT_CLEARANCE,
        ),
        (
            subject(),
            intelligence_policy(compartments=frozenset({NIGHTFALL})),
            AuthorizationDenyReason.MISSING_COMPARTMENT,
        ),
        (
            subject(compartments=frozenset({NIGHTFALL})),
            intelligence_policy(compartments=frozenset({NIGHTFALL, ORION})),
            AuthorizationDenyReason.MISSING_COMPARTMENT,
        ),
        (
            subject(),
            intelligence_policy(classification_rank=25),
            AuthorizationDenyReason.INVALID_RESOURCE_POLICY,
        ),
        (
            subject(),
            intelligence_policy(departments=frozenset()),
            AuthorizationDenyReason.INVALID_RESOURCE_POLICY,
        ),
        (
            subject(),
            intelligence_policy(classification_rank=None),
            AuthorizationDenyReason.INVALID_RESOURCE_POLICY,
        ),
        (
            subject(state_valid=False),
            intelligence_policy(),
            AuthorizationDenyReason.SUBJECT_POLICY_INVALID,
        ),
        (
            subject(clearance_rank=25),
            intelligence_policy(),
            AuthorizationDenyReason.SUBJECT_POLICY_INVALID,
        ),
    ],
)
def test_classified_intelligence_fail_closed_cases_deny(
    current_subject: AuthorizationSubject,
    policy: ResourcePolicy,
    expected_reason: AuthorizationDenyReason,
) -> None:
    assert authorize(current_subject, AuthorizationAction.READ, policy) == (
        AuthorizationDecision.deny(expected_reason)
    )


def test_missing_subject_and_unusable_resource_deny() -> None:
    assert authorize(None, AuthorizationAction.READ, intelligence_policy()) == (
        AuthorizationDecision.deny(AuthorizationDenyReason.SUBJECT_MISSING)
    )
    assert authorize(
        subject(), AuthorizationAction.READ, intelligence_policy(usable=False)
    ) == AuthorizationDecision.deny(AuthorizationDenyReason.RESOURCE_UNUSABLE)


@pytest.mark.parametrize(
    "role",
    [RoleName.SYSTEM_ADMINISTRATOR, RoleName.SECURITY_AUDITOR],
)
def test_administrator_and_auditor_roles_do_not_grant_intelligence_read(
    role: RoleName,
) -> None:
    privileged_subject = subject(
        roles=frozenset({role}), clearance_rank=40, department_id=CYBER
    )
    assert authorize(
        privileged_subject, AuthorizationAction.READ, intelligence_policy()
    ) == AuthorizationDecision.deny(AuthorizationDenyReason.NO_ROLE_CAPABILITY)


def test_administrator_can_administer_only_appropriate_resources() -> None:
    administrator = subject(
        roles=frozenset({RoleName.SYSTEM_ADMINISTRATOR}),
        department_id=None,
        department_active=False,
        clearance_rank=None,
    )
    account_policy = ResourcePolicy(AuthorizationResourceType.USER_ACCOUNT)
    assert authorize(
        administrator, AuthorizationAction.ADMINISTER, account_policy
    ).outcome is AuthorizationOutcome.ALLOW
    assert authorize(
        administrator, AuthorizationAction.AUDIT, account_policy
    ) == AuthorizationDecision.deny(AuthorizationDenyReason.NO_ROLE_CAPABILITY)


def test_auditor_can_audit_but_cannot_read_audit_resource() -> None:
    auditor = subject(
        roles=frozenset({RoleName.SECURITY_AUDITOR}),
        department_id=None,
        department_active=False,
        clearance_rank=None,
    )
    audit_policy = ResourcePolicy(AuthorizationResourceType.AUDIT_EVENT)
    assert authorize(
        auditor, AuthorizationAction.AUDIT, audit_policy
    ).outcome is AuthorizationOutcome.ALLOW
    assert authorize(auditor, AuthorizationAction.READ, audit_policy) == (
        AuthorizationDecision.deny(AuthorizationDenyReason.NO_ROLE_CAPABILITY)
    )


def test_combined_roles_expand_capability_but_never_bypass_abac() -> None:
    combined = subject(
        roles=frozenset({RoleName.SYSTEM_ADMINISTRATOR, RoleName.ANALYST}),
        clearance_rank=20,
        department_id=OPERATIONS,
    )
    result = authorize(
        combined,
        AuthorizationAction.READ,
        intelligence_policy(classification_rank=30),
    )
    assert result == AuthorizationDecision.deny(
        AuthorizationDenyReason.INSUFFICIENT_CLEARANCE
    )


def test_capability_mapping_is_explicit_and_version_controlled() -> None:
    assert ROLE_CAPABILITIES[RoleName.ANALYST][
        AuthorizationResourceType.INTELLIGENCE_RECORD
    ] == {
        AuthorizationAction.READ,
        AuthorizationAction.SEARCH,
        AuthorizationAction.CREATE,
        AuthorizationAction.UPDATE,
    }
    assert AuthorizationAction.EXPORT in ROLE_CAPABILITIES[RoleName.SENIOR_ANALYST][
        AuthorizationResourceType.INTELLIGENCE_RECORD
    ]
    assert {
        AuthorizationAction.DELETE,
        AuthorizationAction.EXPORT,
    } <= ROLE_CAPABILITIES[RoleName.SUPERVISOR][
        AuthorizationResourceType.INTELLIGENCE_RECORD
    ]


def test_unsupported_action_resource_and_malformed_non_intelligence_policy_deny(
) -> None:
    unknown_resource = ResourcePolicy(
        resource_type=cast(Any, "UNKNOWN_RESOURCE")
    )
    assert authorize(subject(), AuthorizationAction.READ, unknown_resource) == (
        AuthorizationDecision.deny(
            AuthorizationDenyReason.UNSUPPORTED_RESOURCE_TYPE
        )
    )
    assert authorize(
        subject(), cast(Any, "UNKNOWN_ACTION"), intelligence_policy()
    ) == AuthorizationDecision.deny(AuthorizationDenyReason.UNSUPPORTED_ACTION)

    administrator = subject(
        roles=frozenset({RoleName.SYSTEM_ADMINISTRATOR}),
        department_id=None,
        department_active=False,
        clearance_rank=None,
    )
    malformed_account = ResourcePolicy(
        resource_type=AuthorizationResourceType.USER_ACCOUNT,
        classification_rank=10,
    )
    assert authorize(
        administrator, AuthorizationAction.ADMINISTER, malformed_account
    ) == AuthorizationDecision.deny(
        AuthorizationDenyReason.INVALID_RESOURCE_POLICY
    )


def test_unexpected_evaluation_exception_becomes_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> AuthorizationDecision:
        raise RuntimeError("synthetic policy failure")

    monkeypatch.setattr(authorization_module, "_evaluate_authorization", fail)
    assert authorize(subject(), AuthorizationAction.READ, intelligence_policy()) == (
        AuthorizationDecision.deny(
            AuthorizationDenyReason.POLICY_EVALUATION_ERROR
        )
    )


def test_decision_invariants_reject_ambiguous_results() -> None:
    with pytest.raises(ValueError):
        AuthorizationDecision(
            AuthorizationOutcome.ALLOW,
            AuthorizationDenyReason.NO_ROLE_CAPABILITY,
        )
    with pytest.raises(ValueError):
        AuthorizationDecision(AuthorizationOutcome.DENY, None)
    with pytest.raises(ValueError):
        AuthorizationDecision(cast(Any, "ALLOW"), None)
    with pytest.raises(ValueError):
        AuthorizationDecision(
            AuthorizationOutcome.DENY,
            cast(Any, "NO_ROLE_CAPABILITY"),
        )


@pytest.mark.parametrize("rank", [999, 25, 0, "30", True])
def test_unknown_or_malformed_subject_clearance_rank_denies(rank: object) -> None:
    result = authorize(
        subject(clearance_rank=cast(Any, rank)),
        AuthorizationAction.READ,
        intelligence_policy(),
    )
    assert result == AuthorizationDecision.deny(
        AuthorizationDenyReason.SUBJECT_POLICY_INVALID
    )


@pytest.mark.parametrize("rank", [999, 25, 0, "30", True])
def test_unknown_or_malformed_resource_classification_rank_denies(
    rank: object,
) -> None:
    result = authorize(
        subject(),
        AuthorizationAction.READ,
        intelligence_policy(classification_rank=cast(Any, rank)),
    )
    assert result == AuthorizationDecision.deny(
        AuthorizationDenyReason.INVALID_RESOURCE_POLICY
    )


def test_authenticated_principal_remains_identity_only() -> None:
    assert {field.name for field in fields(AuthenticatedPrincipal)} == {
        "user_id",
        "username",
        "display_name",
    }
