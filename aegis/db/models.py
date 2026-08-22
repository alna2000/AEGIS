"""Authentication persistence models."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, CheckConstraint, DateTime, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, validates

from aegis.db.base import Base
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
