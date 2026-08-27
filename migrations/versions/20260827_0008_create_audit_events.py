"""Create append-oriented persistent security audit events.

Revision ID: 20260827_0008
Revises: 20260826_0007
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260827_0008"
down_revision: str | None = "20260826_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add durable evidence storage without adding event producers or readers."""

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_code", sa.String(length=40), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("subject_user_id", sa.Uuid(), nullable=True),
        sa.Column("target_type", sa.String(length=32), nullable=True),
        sa.Column("target_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("reason_code", sa.String(length=40), nullable=True),
        sa.Column("request_id", sa.Uuid(), nullable=True),
        sa.Column("source_correlation", sa.LargeBinary(length=32), nullable=True),
        sa.Column("source_key_id", sa.String(length=32), nullable=True),
        sa.CheckConstraint(
            "event_code IN ("
            "'PASSWORD_AUTH_SUCCEEDED', 'PASSWORD_AUTH_FAILED', "
            "'MFA_FACTOR_SUCCEEDED', 'MFA_FACTOR_FAILED', "
            "'MFA_CHALLENGE_EXHAUSTED', 'SESSION_ESTABLISHED', "
            "'SESSION_REVOKED', 'AUTHORIZATION_ALLOWED', "
            "'AUTHORIZATION_DENIED', 'AUTHORIZATION_ERROR', "
            "'RESOURCE_READ_SUCCEEDED', 'RESOURCE_READ_INACCESSIBLE', "
            "'ABUSE_ADMISSION_DENIED', 'ABUSE_STORE_UNAVAILABLE', "
            "'CONCURRENCY_SATURATED', 'AUDIT_PERSISTENCE_FAILED')",
            name="ck_audit_events_event_code_controlled",
        ),
        sa.CheckConstraint(
            "outcome IN ('SUCCESS', 'FAILURE', 'ALLOW', 'DENY', 'LIMITED', 'ERROR')",
            name="ck_audit_events_outcome_controlled",
        ),
        sa.CheckConstraint(
            "severity IN ('INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH')",
            name="ck_audit_events_severity_controlled",
        ),
        sa.CheckConstraint(
            "actor_type IN ('ANONYMOUS', 'USER', 'SYSTEM')",
            name="ck_audit_events_actor_type_controlled",
        ),
        sa.CheckConstraint(
            "action IN ('AUTHENTICATE', 'VERIFY_MFA', 'ESTABLISH_SESSION', "
            "'REVOKE_SESSION', 'AUTHORIZE', 'READ_RESOURCE', "
            "'APPLY_ABUSE_CONTROL', 'PERSIST_AUDIT')",
            name="ck_audit_events_action_controlled",
        ),
        sa.CheckConstraint(
            "target_type IS NULL OR target_type IN ('USER', 'MFA_CHALLENGE', "
            "'SESSION', 'INTELLIGENCE_RECORD', 'ENDPOINT', 'AUDIT_EVENT', "
            "'SECURITY_SUBSYSTEM')",
            name="ck_audit_events_target_type_controlled",
        ),
        sa.CheckConstraint(
            "reason_code IS NULL OR reason_code IN ("
            "'CREDENTIALS_REJECTED', 'ACCOUNT_UNUSABLE', 'IDENTIFIER_REJECTED', "
            "'TOTP_REJECTED', 'TOTP_REPLAYED', 'MFA_CREDENTIAL_UNUSABLE', "
            "'CHALLENGE_FAILURE_LIMIT', 'POLICY_DENIED', "
            "'POLICY_EVALUATION_ERROR', 'RESOURCE_INACCESSIBLE', 'RATE_LIMIT', "
            "'COOLDOWN', 'CONCURRENCY', 'STORE_CAPACITY', 'STORE_UNAVAILABLE', "
            "'DATABASE_ERROR', 'AUDIT_ERROR')",
            name="ck_audit_events_reason_code_controlled",
        ),
        sa.CheckConstraint(
            "(actor_type = 'USER' AND actor_user_id IS NOT NULL) OR "
            "(actor_type IN ('ANONYMOUS', 'SYSTEM') AND actor_user_id IS NULL)",
            name="ck_audit_events_actor_identity_consistent",
        ),
        sa.CheckConstraint(
            "subject_user_id IS NULL OR actor_user_id IS NULL OR "
            "subject_user_id <> actor_user_id",
            name="ck_audit_events_subject_distinct",
        ),
        sa.CheckConstraint(
            "target_id IS NULL OR target_type IS NOT NULL",
            name="ck_audit_events_target_consistent",
        ),
        sa.CheckConstraint(
            "actor_type = 'SYSTEM' OR request_id IS NOT NULL",
            name="ck_audit_events_request_context_consistent",
        ),
        sa.CheckConstraint(
            "(source_correlation IS NULL AND source_key_id IS NULL) OR "
            "(source_correlation IS NOT NULL AND length(source_correlation) = 32 "
            "AND source_key_id IS NOT NULL AND length(source_key_id) BETWEEN 1 AND 32)",
            name="ck_audit_events_source_consistent",
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name="fk_audit_events_actor_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["subject_user_id"],
            ["users.id"],
            name="fk_audit_events_subject_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
    )
    op.create_index(
        "ix_audit_events_occurred_id",
        "audit_events",
        ["occurred_at", "id"],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_code_occurred",
        "audit_events",
        ["event_code", "occurred_at"],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_actor_occurred",
        "audit_events",
        ["actor_user_id", "occurred_at"],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_request_id",
        "audit_events",
        ["request_id"],
        unique=False,
    )


def downgrade() -> None:
    """Remove the unused Part 1 audit foundation."""

    op.drop_index("ix_audit_events_request_id", table_name="audit_events")
    op.drop_index("ix_audit_events_actor_occurred", table_name="audit_events")
    op.drop_index("ix_audit_events_code_occurred", table_name="audit_events")
    op.drop_index("ix_audit_events_occurred_id", table_name="audit_events")
    op.drop_table("audit_events")
