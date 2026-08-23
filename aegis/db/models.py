"""Authentication persistence models."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from aegis.db.base import Base
from aegis.db.types import UTCDateTime
from aegis.security.identity import (
    normalize_display_name,
    normalize_email,
    normalize_username,
)


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


class Role(Base):
    """Controlled version-policy role reference data."""

    __tablename__ = "roles"
    __table_args__ = (
        CheckConstraint(
            "name IN ('Analyst', 'Senior Analyst', 'Supervisor', "
            "'Security Auditor', 'System Administrator')",
            name="ck_roles_name_controlled",
        ),
        CheckConstraint(
            "description IS NULL OR length(description) BETWEEN 1 AND 256",
            name="ck_roles_description_length",
        ),
        CheckConstraint(
            "(is_active = true AND retired_at IS NULL) OR "
            "(is_active = false AND retired_at IS NOT NULL)",
            name="ck_roles_lifecycle_consistent",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(256), nullable=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    retired_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    user_assignments: Mapped[list[UserRole]] = relationship(
        back_populates="role",
        passive_deletes=True,
    )


class Department(Base):
    """Controlled primary-department reference data."""

    __tablename__ = "departments"
    __table_args__ = (
        CheckConstraint(
            "name IN ('Cyber Intelligence', 'Counterintelligence', "
            "'Strategic Analysis', 'Operations')",
            name="ck_departments_name_controlled",
        ),
        CheckConstraint(
            "description IS NULL OR length(description) BETWEEN 1 AND 256",
            name="ck_departments_description_length",
        ),
        CheckConstraint(
            "(is_active = true AND retired_at IS NULL) OR "
            "(is_active = false AND retired_at IS NOT NULL)",
            name="ck_departments_lifecycle_consistent",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(256), nullable=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    retired_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    users: Mapped[list[User]] = relationship(
        back_populates="department",
        passive_deletes=True,
    )


class ClearanceLevel(Base):
    """Controlled immutable clearance/classification ordering."""

    __tablename__ = "clearance_levels"
    __table_args__ = (
        CheckConstraint(
            "(name = 'UNCLASSIFIED' AND rank = 10) OR "
            "(name = 'CONFIDENTIAL' AND rank = 20) OR "
            "(name = 'SECRET' AND rank = 30) OR "
            "(name = 'TOP SECRET' AND rank = 40)",
            name="ck_clearance_levels_name_rank_controlled",
        ),
        CheckConstraint("rank > 0", name="ck_clearance_levels_rank_positive"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    rank: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)

    users: Mapped[list[User]] = relationship(
        back_populates="clearance_level",
        passive_deletes=True,
    )


class Compartment(Base):
    """Controlled need-to-know compartment reference data."""

    __tablename__ = "compartments"
    __table_args__ = (
        CheckConstraint(
            "name IN ('NIGHTFALL', 'ORION', 'SENTINEL')",
            name="ck_compartments_name_controlled",
        ),
        CheckConstraint(
            "description IS NULL OR length(description) BETWEEN 1 AND 256",
            name="ck_compartments_description_length",
        ),
        CheckConstraint(
            "(is_active = true AND retired_at IS NULL) OR "
            "(is_active = false AND retired_at IS NOT NULL)",
            name="ck_compartments_lifecycle_consistent",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(256), nullable=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    retired_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    user_assignments: Mapped[list[UserCompartment]] = relationship(
        back_populates="compartment",
        passive_deletes=True,
    )


class User(Base):
    """Persisted synthetic user identity for password authentication."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "username = lower(username)",
            name="ck_users_username_canonical",
        ),
        CheckConstraint(
            "length(username) BETWEEN 3 AND 64",
            name="ck_users_username_length",
        ),
        CheckConstraint(
            "length(display_name) BETWEEN 1 AND 120",
            name="ck_users_display_name_length",
        ),
        CheckConstraint(
            "email IS NULL OR email = lower(email)",
            name="ck_users_email_canonical",
        ),
        CheckConstraint(
            "length(password_hash) > 0",
            name="ck_users_password_hash_not_empty",
        ),
        CheckConstraint(
            "is_active = false OR disabled_at IS NULL",
            name="ck_users_active_not_disabled",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str | None] = mapped_column(
        String(254), unique=True, nullable=True
    )
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )
    disabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    department_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        nullable=True,
    )
    clearance_level_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("clearance_levels.id", ondelete="RESTRICT"),
        nullable=True,
    )
    department: Mapped[Department | None] = relationship(back_populates="users")
    clearance_level: Mapped[ClearanceLevel | None] = relationship(
        back_populates="users"
    )
    role_assignments: Mapped[list[UserRole]] = relationship(
        foreign_keys="UserRole.user_id",
        back_populates="user",
        passive_deletes=True,
    )
    compartment_assignments: Mapped[list[UserCompartment]] = relationship(
        foreign_keys="UserCompartment.user_id",
        back_populates="user",
        passive_deletes=True,
    )
    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user",
        passive_deletes=True,
    )
    mfa_credentials: Mapped[list[MfaCredential]] = relationship(
        back_populates="user",
        passive_deletes=True,
    )
    mfa_challenges: Mapped[list[MfaChallenge]] = relationship(
        back_populates="user",
        passive_deletes=True,
    )

    @property
    def is_usable_for_authentication(self) -> bool:
        """Return whether this account may become an authenticated principal."""

        return self.is_active and self.disabled_at is None

    @validates("username")
    def _canonicalize_username(self, _key: str, value: str) -> str:
        return normalize_username(value)

    @validates("display_name")
    def _validate_display_name(self, _key: str, value: str) -> str:
        return normalize_display_name(value)

    @validates("email")
    def _canonicalize_email(self, _key: str, value: str | None) -> str | None:
        return normalize_email(value)


class UserRole(Base):
    """Current normalized user-to-role assignment with provenance."""

    __tablename__ = "user_roles"
    __table_args__ = (
        CheckConstraint(
            "assigned_by_user_id IS NULL OR assigned_by_user_id <> user_id",
            name="ck_user_roles_no_self_assignment",
        ),
        Index("ix_user_roles_role_id", "role_id"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("roles.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    assigned_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=utc_now
    )
    # Null is reserved for migration/bootstrap operations; no HTTP assignment
    # workflow exists in Phase 3 Part 1.
    assigned_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )

    user: Mapped[User] = relationship(
        foreign_keys=[user_id], back_populates="role_assignments"
    )
    role: Mapped[Role] = relationship(back_populates="user_assignments")
    assigned_by: Mapped[User | None] = relationship(
        foreign_keys=[assigned_by_user_id]
    )


class UserCompartment(Base):
    """Current normalized user-to-compartment assignment with provenance."""

    __tablename__ = "user_compartments"
    __table_args__ = (
        CheckConstraint(
            "assigned_by_user_id IS NULL OR assigned_by_user_id <> user_id",
            name="ck_user_compartments_no_self_assignment",
        ),
        Index("ix_user_compartments_compartment_id", "compartment_id"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    compartment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("compartments.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    assigned_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=utc_now
    )
    # Null is reserved for migration/bootstrap operations; no HTTP assignment
    # workflow exists in Phase 3 Part 1.
    assigned_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )

    user: Mapped[User] = relationship(
        foreign_keys=[user_id], back_populates="compartment_assignments"
    )
    compartment: Mapped[Compartment] = relationship(
        back_populates="user_assignments"
    )
    assigned_by: Mapped[User | None] = relationship(
        foreign_keys=[assigned_by_user_id]
    )


class UserSession(Base):
    """Hash-only server-side authentication session state."""

    __tablename__ = "sessions"
    __table_args__ = (
        CheckConstraint(
            "length(token_hash) = 64 AND token_hash = lower(token_hash)",
            name="ck_sessions_token_hash_format",
        ),
        CheckConstraint(
            "expires_at > created_at",
            name="ck_sessions_expiry_after_creation",
        ),
        CheckConstraint(
            "last_seen_at IS NULL OR last_seen_at >= created_at",
            name="ck_sessions_last_seen_after_creation",
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name="ck_sessions_revoked_after_creation",
        ),
        Index("ix_sessions_user_lifecycle", "user_id", "revoked_at", "expires_at"),
        Index("ix_sessions_expires_at", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(), nullable=True
    )
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")


class MfaCredential(Base):
    """Encrypted, lifecycle-aware TOTP credential state."""

    __tablename__ = "mfa_credentials"
    __table_args__ = (
        CheckConstraint(
            "method_type = 'TOTP'",
            name="ck_mfa_credentials_method_type",
        ),
        CheckConstraint(
            "length(encrypted_secret) > 0",
            name="ck_mfa_credentials_encrypted_secret_not_empty",
        ),
        CheckConstraint(
            "length(encryption_key_id) BETWEEN 1 AND 64",
            name="ck_mfa_credentials_key_id_length",
        ),
        CheckConstraint(
            "enabled = false OR disabled_at IS NULL",
            name="ck_mfa_credentials_enabled_not_disabled",
        ),
        CheckConstraint(
            "last_used_at IS NULL OR last_used_at >= created_at",
            name="ck_mfa_credentials_last_used_after_creation",
        ),
        CheckConstraint(
            "disabled_at IS NULL OR disabled_at >= created_at",
            name="ck_mfa_credentials_disabled_after_creation",
        ),
        CheckConstraint(
            "last_accepted_counter IS NULL OR last_accepted_counter >= 0",
            name="ck_mfa_credentials_counter_nonnegative",
        ),
        CheckConstraint(
            "(last_used_at IS NULL) = (last_accepted_counter IS NULL)",
            name="ck_mfa_credentials_usage_state_complete",
        ),
        Index(
            "uq_mfa_credentials_non_disabled_totp_user",
            "user_id",
            unique=True,
            postgresql_where=text("disabled_at IS NULL AND method_type = 'TOTP'"),
            sqlite_where=text("disabled_at IS NULL AND method_type = 'TOTP'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    method_type: Mapped[str] = mapped_column(
        String(16), nullable=False, default="TOTP", server_default="TOTP"
    )
    encrypted_secret: Mapped[str] = mapped_column(String(512), nullable=False)
    encryption_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=utc_now
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(), nullable=True
    )
    disabled_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(), nullable=True
    )
    last_accepted_counter: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )

    user: Mapped[User] = relationship(back_populates="mfa_credentials")


class MfaChallenge(Base):
    """Hash-only, short-lived password-verified MFA challenge state."""

    __tablename__ = "mfa_challenges"
    __table_args__ = (
        CheckConstraint(
            "length(token_hash) = 64 AND token_hash = lower(token_hash)",
            name="ck_mfa_challenges_token_hash_format",
        ),
        CheckConstraint(
            "expires_at > created_at",
            name="ck_mfa_challenges_expiry_after_creation",
        ),
        CheckConstraint(
            "consumed_at IS NULL OR consumed_at >= created_at",
            name="ck_mfa_challenges_consumed_after_creation",
        ),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name="ck_mfa_challenges_revoked_after_creation",
        ),
        CheckConstraint(
            "consumed_at IS NULL OR revoked_at IS NULL",
            name="ck_mfa_challenges_single_terminal_state",
        ),
        Index(
            "ix_mfa_challenges_user_lifecycle",
            "user_id",
            "consumed_at",
            "revoked_at",
            "expires_at",
        ),
        Index("ix_mfa_challenges_expires_at", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)

    user: Mapped[User] = relationship(back_populates="mfa_challenges")
