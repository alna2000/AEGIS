"""Create synthetic intelligence records and record-side policy state.

Revision ID: 20260823_0006
Revises: 20260822_0005
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260823_0006"
down_revision: str | None = "20260822_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add record persistence without adding record workflows or HTTP access."""

    op.create_table(
        "intelligence_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("record_code", sa.String(length=9), nullable=False),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("summary", sa.String(length=1000), nullable=True),
        sa.Column("content", sa.String(length=10000), nullable=False),
        sa.Column("classification_level_id", sa.Uuid(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "length(record_code) = 9 AND "
            "substr(record_code, 1, 4) = 'INT-' AND "
            "record_code = upper(record_code) AND "
            "substr(record_code, 5, 1) BETWEEN '0' AND '9' AND "
            "substr(record_code, 6, 1) BETWEEN '0' AND '9' AND "
            "substr(record_code, 7, 1) BETWEEN '0' AND '9' AND "
            "substr(record_code, 8, 1) BETWEEN '0' AND '9' AND "
            "substr(record_code, 9, 1) BETWEEN '0' AND '9'",
            name="ck_intelligence_records_record_code_canonical",
        ),
        sa.CheckConstraint(
            "length(title) BETWEEN 1 AND 160 AND title = trim(title)",
            name="ck_intelligence_records_title_length",
        ),
        sa.CheckConstraint(
            "summary IS NULL OR "
            "(length(summary) BETWEEN 1 AND 1000 AND summary = trim(summary))",
            name="ck_intelligence_records_summary_length",
        ),
        sa.CheckConstraint(
            "length(content) BETWEEN 1 AND 10000",
            name="ck_intelligence_records_content_length",
        ),
        sa.CheckConstraint(
            "status IN ('DRAFT', 'ACTIVE', 'RETIRED')",
            name="ck_intelligence_records_status_controlled",
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name="ck_intelligence_records_updated_after_creation",
        ),
        sa.CheckConstraint(
            "(status IN ('DRAFT', 'ACTIVE') AND retired_at IS NULL) OR "
            "(status = 'RETIRED' AND retired_at IS NOT NULL "
            "AND retired_at >= created_at)",
            name="ck_intelligence_records_lifecycle_consistent",
        ),
        sa.ForeignKeyConstraint(
            ["classification_level_id"],
            ["clearance_levels.id"],
            name="fk_intelligence_records_classification_clearance",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_intelligence_records_created_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_intelligence_records"),
        sa.UniqueConstraint(
            "record_code", name="uq_intelligence_records_record_code"
        ),
    )
    op.create_index(
        "ix_intelligence_records_classification_level_id",
        "intelligence_records",
        ["classification_level_id"],
        unique=False,
    )
    op.create_index(
        "ix_intelligence_records_created_by_user_id",
        "intelligence_records",
        ["created_by_user_id"],
        unique=False,
    )
    op.create_table(
        "record_departments",
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("department_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["department_id"],
            ["departments.id"],
            name="fk_record_departments_department_id_departments",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["record_id"],
            ["intelligence_records.id"],
            name="fk_record_departments_record_id_intelligence_records",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "record_id", "department_id", name="pk_record_departments"
        ),
    )
    op.create_index(
        "ix_record_departments_department_id",
        "record_departments",
        ["department_id"],
        unique=False,
    )
    op.create_table(
        "record_compartments",
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("compartment_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["compartment_id"],
            ["compartments.id"],
            name="fk_record_compartments_compartment_id_compartments",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["record_id"],
            ["intelligence_records.id"],
            name="fk_record_compartments_record_id_intelligence_records",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "record_id", "compartment_id", name="pk_record_compartments"
        ),
    )
    op.create_index(
        "ix_record_compartments_compartment_id",
        "record_compartments",
        ["compartment_id"],
        unique=False,
    )


def downgrade() -> None:
    """Remove record-side state and return to the Part 1 schema."""

    op.drop_index(
        "ix_record_compartments_compartment_id",
        table_name="record_compartments",
    )
    op.drop_table("record_compartments")
    op.drop_index(
        "ix_record_departments_department_id",
        table_name="record_departments",
    )
    op.drop_table("record_departments")
    op.drop_index(
        "ix_intelligence_records_created_by_user_id",
        table_name="intelligence_records",
    )
    op.drop_index(
        "ix_intelligence_records_classification_level_id",
        table_name="intelligence_records",
    )
    op.drop_table("intelligence_records")
