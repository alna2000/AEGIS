"""Authentication persistence models."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, String, Uuid
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
    sessions: Mapped[list[UserSession]] = relationship(
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
