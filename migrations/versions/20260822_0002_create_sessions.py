"""Create hash-only server-side authentication sessions.

Revision ID: 20260822_0002
Revises: 20260822_0001
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260822_0002"
down_revision: str | None = "20260822_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the reviewed server-side session schema."""

    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.CheckConstraint(
            "length(token_hash) = 64 AND token_hash = lower(token_hash)",
            name="ck_sessions_token_hash_format",
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_sessions_expiry_after_creation",
        ),
        sa.CheckConstraint(
            "last_seen_at IS NULL OR last_seen_at >= created_at",
            name="ck_sessions_last_seen_after_creation",
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name="ck_sessions_revoked_after_creation",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_sessions_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_sessions"),
        sa.UniqueConstraint("token_hash", name="uq_sessions_token_hash"),
    )
    op.create_index(
        "ix_sessions_user_lifecycle",
        "sessions",
        ["user_id", "revoked_at", "expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_sessions_expires_at",
        "sessions",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    """Remove server-side sessions without changing user accounts."""

    op.drop_index("ix_sessions_expires_at", table_name="sessions")
    op.drop_index("ix_sessions_user_lifecycle", table_name="sessions")
    op.drop_table("sessions")
