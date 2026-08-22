"""Create short-lived hash-only MFA challenges.

Revision ID: 20260822_0004
Revises: 20260822_0003
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260822_0004"
down_revision: str | None = "20260822_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the reviewed temporary MFA challenge schema."""

    op.create_table(
        "mfa_challenges",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.CheckConstraint(
            "length(token_hash) = 64 AND token_hash = lower(token_hash)",
            name="ck_mfa_challenges_token_hash_format",
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_mfa_challenges_expiry_after_creation",
        ),
        sa.CheckConstraint(
            "consumed_at IS NULL OR consumed_at >= created_at",
            name="ck_mfa_challenges_consumed_after_creation",
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name="ck_mfa_challenges_revoked_after_creation",
        ),
        sa.CheckConstraint(
            "consumed_at IS NULL OR revoked_at IS NULL",
            name="ck_mfa_challenges_single_terminal_state",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_mfa_challenges_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_mfa_challenges"),
        sa.UniqueConstraint("token_hash", name="uq_mfa_challenges_token_hash"),
    )
    op.create_index(
        "ix_mfa_challenges_user_lifecycle",
        "mfa_challenges",
        ["user_id", "consumed_at", "revoked_at", "expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_mfa_challenges_expires_at",
        "mfa_challenges",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    """Remove MFA challenges without changing credentials or sessions."""

    op.drop_index("ix_mfa_challenges_expires_at", table_name="mfa_challenges")
    op.drop_index(
        "ix_mfa_challenges_user_lifecycle", table_name="mfa_challenges"
    )
    op.drop_table("mfa_challenges")
