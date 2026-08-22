"""Create encrypted TOTP MFA credential state.

Revision ID: 20260822_0003
Revises: 20260822_0002
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260822_0003"
down_revision: str | None = "20260822_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create encrypted, lifecycle-aware, replay-protected TOTP state."""

    op.create_table(
        "mfa_credentials",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "method_type",
            sa.String(length=16),
            server_default="TOTP",
            nullable=False,
        ),
        sa.Column("encrypted_secret", sa.String(length=512), nullable=False),
        sa.Column("encryption_key_id", sa.String(length=64), nullable=False),
        sa.Column(
            "enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_accepted_counter", sa.BigInteger(), nullable=True),
        sa.CheckConstraint(
            "method_type = 'TOTP'", name="ck_mfa_credentials_method_type"
        ),
        sa.CheckConstraint(
            "length(encrypted_secret) > 0",
            name="ck_mfa_credentials_encrypted_secret_not_empty",
        ),
        sa.CheckConstraint(
            "length(encryption_key_id) BETWEEN 1 AND 64",
            name="ck_mfa_credentials_key_id_length",
        ),
        sa.CheckConstraint(
            "enabled = false OR disabled_at IS NULL",
            name="ck_mfa_credentials_enabled_not_disabled",
        ),
        sa.CheckConstraint(
            "last_used_at IS NULL OR last_used_at >= created_at",
            name="ck_mfa_credentials_last_used_after_creation",
        ),
        sa.CheckConstraint(
            "disabled_at IS NULL OR disabled_at >= created_at",
            name="ck_mfa_credentials_disabled_after_creation",
        ),
        sa.CheckConstraint(
            "last_accepted_counter IS NULL OR last_accepted_counter >= 0",
            name="ck_mfa_credentials_counter_nonnegative",
        ),
        sa.CheckConstraint(
            "(last_used_at IS NULL) = (last_accepted_counter IS NULL)",
            name="ck_mfa_credentials_usage_state_complete",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_mfa_credentials_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_mfa_credentials"),
    )
    op.create_index(
        "uq_mfa_credentials_non_disabled_totp_user",
        "mfa_credentials",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("disabled_at IS NULL AND method_type = 'TOTP'"),
        sqlite_where=sa.text("disabled_at IS NULL AND method_type = 'TOTP'"),
    )


def downgrade() -> None:
    """Remove TOTP credentials without changing users or sessions."""

    op.drop_index(
        "uq_mfa_credentials_non_disabled_totp_user",
        table_name="mfa_credentials",
    )
    op.drop_table("mfa_credentials")
