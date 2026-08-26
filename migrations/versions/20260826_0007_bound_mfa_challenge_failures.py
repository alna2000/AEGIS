"""Bound failed TOTP attempts per MFA challenge.

Revision ID: 20260826_0007
Revises: 20260823_0006
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260826_0007"
down_revision: str | None = "20260823_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("mfa_challenges") as batch_op:
        batch_op.add_column(
            sa.Column(
                "failed_factor_attempts",
                sa.Integer(),
                server_default="0",
                nullable=False,
            )
        )
        batch_op.create_check_constraint(
            "ck_mfa_challenges_failed_factor_attempts_bounded",
            "failed_factor_attempts BETWEEN 0 AND 5",
        )


def downgrade() -> None:
    with op.batch_alter_table("mfa_challenges") as batch_op:
        batch_op.drop_constraint(
            "ck_mfa_challenges_failed_factor_attempts_bounded", type_="check"
        )
        batch_op.drop_column("failed_factor_attempts")
