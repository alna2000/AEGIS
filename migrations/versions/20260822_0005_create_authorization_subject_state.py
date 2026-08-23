"""Create normalized authorization subject state.

Revision ID: 20260822_0005
Revises: 20260822_0004
"""

from typing import Sequence
import uuid

from alembic import op
import sqlalchemy as sa


revision: str = "20260822_0005"
down_revision: str | None = "20260822_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Stable public identifiers for controlled, non-secret reference data. They are
# deliberately explicit so environments receive identical policy identifiers.
ROLE_ROWS = (
    ("30000000-0000-0000-0000-000000000001", "Analyst"),
    ("30000000-0000-0000-0000-000000000002", "Senior Analyst"),
    ("30000000-0000-0000-0000-000000000003", "Supervisor"),
    ("30000000-0000-0000-0000-000000000004", "Security Auditor"),
    ("30000000-0000-0000-0000-000000000005", "System Administrator"),
)
DEPARTMENT_ROWS = (
    ("31000000-0000-0000-0000-000000000001", "Cyber Intelligence"),
    ("31000000-0000-0000-0000-000000000002", "Counterintelligence"),
    ("31000000-0000-0000-0000-000000000003", "Strategic Analysis"),
    ("31000000-0000-0000-0000-000000000004", "Operations"),
)
CLEARANCE_ROWS = (
    ("32000000-0000-0000-0000-000000000001", "UNCLASSIFIED", 10),
    ("32000000-0000-0000-0000-000000000002", "CONFIDENTIAL", 20),
    ("32000000-0000-0000-0000-000000000003", "SECRET", 30),
    ("32000000-0000-0000-0000-000000000004", "TOP SECRET", 40),
)
COMPARTMENT_ROWS = (
    ("33000000-0000-0000-0000-000000000001", "NIGHTFALL"),
    ("33000000-0000-0000-0000-000000000002", "ORION"),
    ("33000000-0000-0000-0000-000000000003", "SENTINEL"),
)


def _create_reference_tables() -> None:
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.String(length=256), nullable=True),
        sa.Column(
            "is_active", sa.Boolean(), server_default=sa.true(), nullable=False
        ),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "name IN ('Analyst', 'Senior Analyst', 'Supervisor', "
            "'Security Auditor', 'System Administrator')",
            name="ck_roles_name_controlled",
        ),
        sa.CheckConstraint(
            "description IS NULL OR length(description) BETWEEN 1 AND 256",
            name="ck_roles_description_length",
        ),
        sa.CheckConstraint(
            "(is_active = true AND retired_at IS NULL) OR "
            "(is_active = false AND retired_at IS NOT NULL)",
            name="ck_roles_lifecycle_consistent",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_roles"),
        sa.UniqueConstraint("name", name="uq_roles_name"),
    )
    op.create_table(
        "departments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.String(length=256), nullable=True),
        sa.Column(
            "is_active", sa.Boolean(), server_default=sa.true(), nullable=False
        ),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "name IN ('Cyber Intelligence', 'Counterintelligence', "
            "'Strategic Analysis', 'Operations')",
            name="ck_departments_name_controlled",
        ),
        sa.CheckConstraint(
            "description IS NULL OR length(description) BETWEEN 1 AND 256",
            name="ck_departments_description_length",
        ),
        sa.CheckConstraint(
            "(is_active = true AND retired_at IS NULL) OR "
            "(is_active = false AND retired_at IS NOT NULL)",
            name="ck_departments_lifecycle_consistent",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_departments"),
        sa.UniqueConstraint("name", name="uq_departments_name"),
    )
    op.create_table(
        "clearance_levels",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=32), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "(name = 'UNCLASSIFIED' AND rank = 10) OR "
            "(name = 'CONFIDENTIAL' AND rank = 20) OR "
            "(name = 'SECRET' AND rank = 30) OR "
            "(name = 'TOP SECRET' AND rank = 40)",
            name="ck_clearance_levels_name_rank_controlled",
        ),
        sa.CheckConstraint(
            "rank > 0", name="ck_clearance_levels_rank_positive"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_clearance_levels"),
        sa.UniqueConstraint("name", name="uq_clearance_levels_name"),
        sa.UniqueConstraint("rank", name="uq_clearance_levels_rank"),
    )
    op.create_table(
        "compartments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=32), nullable=False),
        sa.Column("description", sa.String(length=256), nullable=True),
        sa.Column(
            "is_active", sa.Boolean(), server_default=sa.true(), nullable=False
        ),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "name IN ('NIGHTFALL', 'ORION', 'SENTINEL')",
            name="ck_compartments_name_controlled",
        ),
        sa.CheckConstraint(
            "description IS NULL OR length(description) BETWEEN 1 AND 256",
            name="ck_compartments_description_length",
        ),
        sa.CheckConstraint(
            "(is_active = true AND retired_at IS NULL) OR "
            "(is_active = false AND retired_at IS NOT NULL)",
            name="ck_compartments_lifecycle_consistent",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_compartments"),
        sa.UniqueConstraint("name", name="uq_compartments_name"),
    )


def _insert_reference_data() -> None:
    role_table = sa.table(
        "roles",
        sa.column("id", sa.Uuid()),
        sa.column("name", sa.String()),
        sa.column("description", sa.String()),
        sa.column("is_active", sa.Boolean()),
        sa.column("retired_at", sa.DateTime(timezone=True)),
    )
    department_table = sa.table(
        "departments",
        sa.column("id", sa.Uuid()),
        sa.column("name", sa.String()),
        sa.column("description", sa.String()),
        sa.column("is_active", sa.Boolean()),
        sa.column("retired_at", sa.DateTime(timezone=True)),
    )
    clearance_table = sa.table(
        "clearance_levels",
        sa.column("id", sa.Uuid()),
        sa.column("name", sa.String()),
        sa.column("rank", sa.Integer()),
    )
    compartment_table = sa.table(
        "compartments",
        sa.column("id", sa.Uuid()),
        sa.column("name", sa.String()),
        sa.column("description", sa.String()),
        sa.column("is_active", sa.Boolean()),
        sa.column("retired_at", sa.DateTime(timezone=True)),
    )

    op.bulk_insert(
        role_table,
        [
            {
                "id": uuid.UUID(identifier),
                "name": name,
                "description": None,
                "is_active": True,
                "retired_at": None,
            }
            for identifier, name in ROLE_ROWS
        ],
        multiinsert=False,
    )
    op.bulk_insert(
        department_table,
        [
            {
                "id": uuid.UUID(identifier),
                "name": name,
                "description": None,
                "is_active": True,
                "retired_at": None,
            }
            for identifier, name in DEPARTMENT_ROWS
        ],
        multiinsert=False,
    )
    op.bulk_insert(
        clearance_table,
        [
            {"id": uuid.UUID(identifier), "name": name, "rank": rank}
            for identifier, name, rank in CLEARANCE_ROWS
        ],
        multiinsert=False,
    )
    op.bulk_insert(
        compartment_table,
        [
            {
                "id": uuid.UUID(identifier),
                "name": name,
                "description": None,
                "is_active": True,
                "retired_at": None,
            }
            for identifier, name in COMPARTMENT_ROWS
        ],
        multiinsert=False,
    )


def _extend_users() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("department_id", sa.Uuid(), nullable=True))
        batch_op.add_column(
            sa.Column("clearance_level_id", sa.Uuid(), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_users_department_id_departments",
            "departments",
            ["department_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_foreign_key(
            "fk_users_clearance_level_id_clearance_levels",
            "clearance_levels",
            ["clearance_level_id"],
            ["id"],
            ondelete="RESTRICT",
        )


def _create_assignment_tables() -> None:
    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assigned_by_user_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "assigned_by_user_id IS NULL OR assigned_by_user_id <> user_id",
            name="ck_user_roles_no_self_assignment",
        ),
        sa.ForeignKeyConstraint(
            ["assigned_by_user_id"],
            ["users.id"],
            name="fk_user_roles_assigned_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_user_roles_role_id_roles",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_roles_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("user_id", "role_id", name="pk_user_roles"),
    )
    op.create_index(
        "ix_user_roles_role_id", "user_roles", ["role_id"], unique=False
    )
    op.create_table(
        "user_compartments",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("compartment_id", sa.Uuid(), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assigned_by_user_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "assigned_by_user_id IS NULL OR assigned_by_user_id <> user_id",
            name="ck_user_compartments_no_self_assignment",
        ),
        sa.ForeignKeyConstraint(
            ["assigned_by_user_id"],
            ["users.id"],
            name="fk_user_compartments_assigned_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["compartment_id"],
            ["compartments.id"],
            name="fk_user_compartments_compartment_id_compartments",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_compartments_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "user_id", "compartment_id", name="pk_user_compartments"
        ),
    )
    op.create_index(
        "ix_user_compartments_compartment_id",
        "user_compartments",
        ["compartment_id"],
        unique=False,
    )


def upgrade() -> None:
    """Add current server-side authorization subject facts only."""

    _create_reference_tables()
    _insert_reference_data()
    _extend_users()
    _create_assignment_tables()


def downgrade() -> None:
    """Return to the Phase 2 schema without deleting users."""

    op.drop_index(
        "ix_user_compartments_compartment_id", table_name="user_compartments"
    )
    op.drop_table("user_compartments")
    op.drop_index("ix_user_roles_role_id", table_name="user_roles")
    op.drop_table("user_roles")
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint(
            "fk_users_clearance_level_id_clearance_levels", type_="foreignkey"
        )
        batch_op.drop_constraint(
            "fk_users_department_id_departments", type_="foreignkey"
        )
        batch_op.drop_column("clearance_level_id")
        batch_op.drop_column("department_id")
    op.drop_table("compartments")
    op.drop_table("clearance_levels")
    op.drop_table("departments")
    op.drop_table("roles")
