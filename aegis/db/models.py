"""Authentication persistence models."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
import re

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
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


class IntelligenceRecordStatus(str, Enum):
    """Controlled persistence lifecycle for synthetic intelligence records."""

    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


_RECORD_CODE_PATTERN = re.compile(r"^INT-[0-9]{5}$")


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
    record_assignments: Mapped[list[RecordDepartment]] = relationship(
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
    intelligence_records: Mapped[list[IntelligenceRecord]] = relationship(
        back_populates="classification_level",
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
    record_assignments: Mapped[list[RecordCompartment]] = relationship(
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
    created_intelligence_records: Mapped[list[IntelligenceRecord]] = relationship(
        foreign_keys="IntelligenceRecord.created_by_user_id",
        back_populates="creator",
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


class IntelligenceRecord(Base):
    """Persisted synthetic intelligence content and record-side policy state."""

    __tablename__ = "intelligence_records"
    __table_args__ = (
        CheckConstraint(
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
        CheckConstraint(
            "length(title) BETWEEN 1 AND 160 AND title = trim(title)",
            name="ck_intelligence_records_title_length",
        ),
        CheckConstraint(
            "summary IS NULL OR "
            "(length(summary) BETWEEN 1 AND 1000 AND summary = trim(summary))",
            name="ck_intelligence_records_summary_length",
        ),
        CheckConstraint(
            "length(content) BETWEEN 1 AND 10000",
            name="ck_intelligence_records_content_length",
        ),
        CheckConstraint(
            "status IN ('DRAFT', 'ACTIVE', 'RETIRED')",
            name="ck_intelligence_records_status_controlled",
        ),
        CheckConstraint(
            "updated_at >= created_at",
            name="ck_intelligence_records_updated_after_creation",
        ),
        CheckConstraint(
            "(status IN ('DRAFT', 'ACTIVE') AND retired_at IS NULL) OR "
            "(status = 'RETIRED' AND retired_at IS NOT NULL "
            "AND retired_at >= created_at)",
            name="ck_intelligence_records_lifecycle_consistent",
        ),
        Index(
            "ix_intelligence_records_classification_level_id",
            "classification_level_id",
        ),
        Index(
            "ix_intelligence_records_created_by_user_id",
            "created_by_user_id",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    record_code: Mapped[str] = mapped_column(String(9), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    summary: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    content: Mapped[str] = mapped_column(String(10000), nullable=False)
    classification_level_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("clearance_levels.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=IntelligenceRecordStatus.DRAFT.value
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=utc_now, onupdate=utc_now
    )
    retired_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(), nullable=True
    )

    classification_level: Mapped[ClearanceLevel] = relationship(
        back_populates="intelligence_records"
    )
    creator: Mapped[User] = relationship(
        foreign_keys=[created_by_user_id],
        back_populates="created_intelligence_records",
    )
    department_assignments: Mapped[list[RecordDepartment]] = relationship(
        back_populates="record",
        passive_deletes=True,
    )
    compartment_assignments: Mapped[list[RecordCompartment]] = relationship(
        back_populates="record",
        passive_deletes=True,
    )

    @validates("record_code")
    def _validate_record_code(self, _key: str, value: str) -> str:
        if not isinstance(value, str) or _RECORD_CODE_PATTERN.fullmatch(value) is None:
            raise ValueError("record code must match INT-99999")
        return value

    @validates("title")
    def _validate_title(self, _key: str, value: str) -> str:
        if (
            not isinstance(value, str)
            or value != value.strip()
            or not 1 <= len(value) <= 160
        ):
            raise ValueError("record title must be trimmed and 1 to 160 characters")
        return value

    @validates("summary")
    def _validate_summary(self, _key: str, value: str | None) -> str | None:
        if value is not None and (
            not isinstance(value, str)
            or value != value.strip()
            or not 1 <= len(value) <= 1000
        ):
            raise ValueError("record summary must be null or trimmed and bounded")
        return value

    @validates("content")
    def _validate_content(self, _key: str, value: str) -> str:
        if not isinstance(value, str) or not 1 <= len(value) <= 10000:
            raise ValueError("record content must be 1 to 10000 characters")
        return value

    @validates("status")
    def _validate_status(
        self, _key: str, value: str | IntelligenceRecordStatus
    ) -> str:
        try:
            return IntelligenceRecordStatus(value).value
        except (TypeError, ValueError) as error:
            raise ValueError("record status must be controlled") from error


class RecordDepartment(Base):
    """One explicit department authorized for a synthetic record."""

    __tablename__ = "record_departments"
    __table_args__ = (
        Index("ix_record_departments_department_id", "department_id"),
    )

    record_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("intelligence_records.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    department_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("departments.id", ondelete="RESTRICT"),
        primary_key=True,
    )

    record: Mapped[IntelligenceRecord] = relationship(
        back_populates="department_assignments"
    )
    department: Mapped[Department] = relationship(
        back_populates="record_assignments"
    )


class RecordCompartment(Base):
    """One explicit compartment required by a synthetic record."""

    __tablename__ = "record_compartments"
    __table_args__ = (
        Index("ix_record_compartments_compartment_id", "compartment_id"),
    )

    record_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("intelligence_records.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    compartment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("compartments.id", ondelete="RESTRICT"),
        primary_key=True,
    )

    record: Mapped[IntelligenceRecord] = relationship(
        back_populates="compartment_assignments"
    )
    compartment: Mapped[Compartment] = relationship(
        back_populates="record_assignments"
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
        CheckConstraint(
            "failed_factor_attempts BETWEEN 0 AND 5",
            name="ck_mfa_challenges_failed_factor_attempts_bounded",
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
    failed_factor_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)

    user: Mapped[User] = relationship(back_populates="mfa_challenges")


class AuditEvent(Base):
    """Append-oriented durable security evidence with controlled fields only."""

    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(
            "event_code IN ("
            "'PASSWORD_AUTH_SUCCEEDED', 'PASSWORD_AUTH_FAILED', "
            "'MFA_FACTOR_SUCCEEDED', 'MFA_FACTOR_FAILED', "
            "'MFA_CHALLENGE_EXHAUSTED', 'MFA_CHALLENGE_ISSUED', "
            "'SESSION_ESTABLISHED', 'SESSION_REVOKED', 'LOGOUT_SUCCEEDED', "
            "'AUTHORIZATION_ALLOWED', "
            "'AUTHORIZATION_DENIED', 'AUTHORIZATION_ERROR', "
            "'RESOURCE_READ_SUCCEEDED', 'RESOURCE_READ_INACCESSIBLE', "
            "'ABUSE_ADMISSION_DENIED', 'ABUSE_STORE_UNAVAILABLE', "
            "'CONCURRENCY_SATURATED', 'AUDIT_PERSISTENCE_FAILED')",
            name="ck_audit_events_event_code_controlled",
        ),
        CheckConstraint(
            "outcome IN ('SUCCESS', 'FAILURE', 'ALLOW', 'DENY', 'LIMITED', 'ERROR')",
            name="ck_audit_events_outcome_controlled",
        ),
        CheckConstraint(
            "severity IN ('INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH')",
            name="ck_audit_events_severity_controlled",
        ),
        CheckConstraint(
            "actor_type IN ('ANONYMOUS', 'USER', 'SYSTEM')",
            name="ck_audit_events_actor_type_controlled",
        ),
        CheckConstraint(
            "action IN ('AUTHENTICATE', 'VERIFY_MFA', 'ESTABLISH_SESSION', "
            "'REVOKE_SESSION', 'AUTHORIZE', 'READ_RESOURCE', "
            "'APPLY_ABUSE_CONTROL', 'PERSIST_AUDIT')",
            name="ck_audit_events_action_controlled",
        ),
        CheckConstraint(
            "target_type IS NULL OR target_type IN ('USER', 'MFA_CHALLENGE', "
            "'SESSION', 'INTELLIGENCE_RECORD', 'ENDPOINT', 'AUDIT_EVENT', "
            "'SECURITY_SUBSYSTEM')",
            name="ck_audit_events_target_type_controlled",
        ),
        CheckConstraint(
            "reason_code IS NULL OR reason_code IN ("
            "'CREDENTIALS_REJECTED', 'ACCOUNT_UNUSABLE', 'IDENTIFIER_REJECTED', "
            "'TOTP_REJECTED', 'TOTP_REPLAYED', 'MFA_CREDENTIAL_UNUSABLE', "
            "'CHALLENGE_FAILURE_LIMIT', 'POLICY_DENIED', "
            "'POLICY_EVALUATION_ERROR', 'RESOURCE_INACCESSIBLE', 'RATE_LIMIT', "
            "'COOLDOWN', 'CONCURRENCY', 'STORE_CAPACITY', 'STORE_UNAVAILABLE', "
            "'DATABASE_ERROR', 'AUDIT_ERROR')",
            name="ck_audit_events_reason_code_controlled",
        ),
        CheckConstraint(
            "(actor_type = 'USER' AND actor_user_id IS NOT NULL) OR "
            "(actor_type IN ('ANONYMOUS', 'SYSTEM') AND actor_user_id IS NULL)",
            name="ck_audit_events_actor_identity_consistent",
        ),
        CheckConstraint(
            "subject_user_id IS NULL OR actor_user_id IS NULL OR "
            "subject_user_id <> actor_user_id",
            name="ck_audit_events_subject_distinct",
        ),
        CheckConstraint(
            "target_id IS NULL OR target_type IS NOT NULL",
            name="ck_audit_events_target_consistent",
        ),
        CheckConstraint(
            "actor_type = 'SYSTEM' OR request_id IS NOT NULL",
            name="ck_audit_events_request_context_consistent",
        ),
        CheckConstraint(
            "(source_correlation IS NULL AND source_key_id IS NULL) OR "
            "(source_correlation IS NOT NULL AND length(source_correlation) = 32 "
            "AND source_key_id IS NOT NULL AND length(source_key_id) BETWEEN 1 AND 32)",
            name="ck_audit_events_source_consistent",
        ),
        Index("ix_audit_events_occurred_id", "occurred_at", "id"),
        Index("ix_audit_events_code_occurred", "event_code", "occurred_at"),
        Index("ix_audit_events_actor_occurred", "actor_user_id", "occurred_at"),
        Index("ix_audit_events_request_id", "request_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    event_code: Mapped[str] = mapped_column(String(40), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    subject_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), nullable=True
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(40), nullable=True)
    request_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), nullable=True
    )
    source_correlation: Mapped[bytes | None] = mapped_column(
        LargeBinary(32), nullable=True
    )
    source_key_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
