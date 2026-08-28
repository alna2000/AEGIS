"""Extend the controlled collection audit event code.

Revision ID: 20260827_0010
Revises: 20260827_0009
"""

from typing import Sequence

from alembic import op


revision: str = "20260827_0010"
down_revision: str | None = "20260827_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_PART_2_CODES = (
    "event_code IN ("
    "'PASSWORD_AUTH_SUCCEEDED', 'PASSWORD_AUTH_FAILED', "
    "'MFA_FACTOR_SUCCEEDED', 'MFA_FACTOR_FAILED', "
    "'MFA_CHALLENGE_EXHAUSTED', 'MFA_CHALLENGE_ISSUED', "
    "'SESSION_ESTABLISHED', 'SESSION_REVOKED', 'LOGOUT_SUCCEEDED', "
    "'AUTHORIZATION_ALLOWED', 'AUTHORIZATION_DENIED', 'AUTHORIZATION_ERROR', "
    "'RESOURCE_READ_SUCCEEDED', 'RESOURCE_READ_INACCESSIBLE', "
    "'ABUSE_ADMISSION_DENIED', 'ABUSE_STORE_UNAVAILABLE', "
    "'CONCURRENCY_SATURATED', 'AUDIT_PERSISTENCE_FAILED')"
)

_PART_3_CODES = (
    "event_code IN ("
    "'PASSWORD_AUTH_SUCCEEDED', 'PASSWORD_AUTH_FAILED', "
    "'MFA_FACTOR_SUCCEEDED', 'MFA_FACTOR_FAILED', "
    "'MFA_CHALLENGE_EXHAUSTED', 'MFA_CHALLENGE_ISSUED', "
    "'SESSION_ESTABLISHED', 'SESSION_REVOKED', 'LOGOUT_SUCCEEDED', "
    "'AUTHORIZATION_ALLOWED', 'AUTHORIZATION_DENIED', 'AUTHORIZATION_ERROR', "
    "'RESOURCE_READ_SUCCEEDED', 'RESOURCE_COLLECTION_READ', "
    "'RESOURCE_READ_INACCESSIBLE', 'ABUSE_ADMISSION_DENIED', "
    "'ABUSE_STORE_UNAVAILABLE', 'CONCURRENCY_SATURATED', "
    "'AUDIT_PERSISTENCE_FAILED')"
)


def _replace_event_code_constraint(expression: str) -> None:
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_constraint(
            "ck_audit_events_event_code_controlled", type_="check"
        )
        batch_op.create_check_constraint(
            "ck_audit_events_event_code_controlled", expression
        )


def upgrade() -> None:
    """Allow exactly the reviewed collection-level event code."""

    _replace_event_code_constraint(_PART_3_CODES)


def downgrade() -> None:
    """Restore the exact Part 2 controlled event-code vocabulary."""

    _replace_event_code_constraint(_PART_2_CODES)
