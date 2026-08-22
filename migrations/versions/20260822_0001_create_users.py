"""Create the authentication users table.

Revision ID: 20260822_0001
Revises: None
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "20260822_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the minimum user-account persistence schema."""

    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=True),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "username = lower(username)", name="ck_users_username_canonical"
        ),
        sa.CheckConstraint(
            "length(username) BETWEEN 3 AND 64",
            name="ck_users_username_length",
        ),
        sa.CheckConstraint(
            "length(display_name) BETWEEN 1 AND 120",
            name="ck_users_display_name_length",
        ),
        sa.CheckConstraint(
            "email IS NULL OR email = lower(email)",
            name="ck_users_email_canonical",
        ),
        sa.CheckConstraint(
            "length(password_hash) > 0",
            name="ck_users_password_hash_not_empty",
        ),
        sa.CheckConstraint(
            "is_active = false OR disabled_at IS NULL",
            name="ck_users_active_not_disabled",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.UniqueConstraint("username", name="uq_users_username"),
    )


def downgrade() -> None:
    """Remove the authentication users table."""

    op.drop_table("users")
