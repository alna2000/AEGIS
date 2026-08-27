"""Central server-side session creation, resolution, and revocation."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from aegis.db.models import UserSession
from aegis.db.repositories import SessionRepository
from aegis.security.authentication_events import AuthenticationRequestContext
from aegis.services.authentication import AuthenticatedPrincipal


SESSION_TOKEN_BYTES = 32
SESSION_TOKEN_CHARACTERS = 43
_SESSION_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class SessionServiceError(RuntimeError):
    """Raised when secure session material or state cannot be created safely."""


@dataclass(frozen=True, slots=True)
class IssuedSession:
    """One newly issued client credential and its non-secret lifecycle data."""

    session_id: uuid.UUID
    raw_token: str = field(repr=False)
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ResolvedSession:
    """A currently usable session resolved to identity only."""

    session_id: uuid.UUID
    principal: AuthenticatedPrincipal


@dataclass(frozen=True, slots=True)
class RevokedSession:
    """Internal identity of one session actually revoked by this transaction."""

    session_id: uuid.UUID
    user_id: uuid.UUID


def generate_session_token() -> str:
    """Return a URL-safe opaque token containing 256 bits of randomness."""

    return base64.urlsafe_b64encode(secrets.token_bytes(SESSION_TOKEN_BYTES)).rstrip(
        b"="
    ).decode("ascii")


def hash_session_token(raw_token: str | None) -> str | None:
    """Return a deterministic SHA-256 lookup hash for a valid opaque token."""

    if not isinstance(raw_token, str) or not _SESSION_TOKEN_PATTERN.fullmatch(raw_token):
        return None
    return hashlib.sha256(raw_token.encode("ascii")).hexdigest()


class SessionService:
    """Own every server-side session lifecycle and usability decision."""

    def __init__(
        self,
        sessions: SessionRepository,
        *,
        lifetime: timedelta,
        clock: Callable[[], datetime] | None = None,
        token_generator: Callable[[], str] = generate_session_token,
    ) -> None:
        if lifetime <= timedelta(0):
            raise ValueError("session lifetime must be positive")
        self._sessions = sessions
        self._lifetime = lifetime
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._token_generator = token_generator

    def create_session(
        self,
        principal: AuthenticatedPrincipal,
        context: AuthenticationRequestContext,
    ) -> IssuedSession:
        """Create fresh server-selected session material in the current transaction."""

        now = self._current_time()
        raw_token = self._token_generator()
        token_hash = hash_session_token(raw_token)
        if token_hash is None:
            raise SessionServiceError("secure session token generation failed")

        expires_at = now + self._lifetime
        model = self._sessions.add(
            UserSession(
                user_id=principal.user_id,
                token_hash=token_hash,
                created_at=now,
                expires_at=expires_at,
                source_ip=context.source_ip,
                user_agent=context.user_agent,
            )
        )
        self._sessions.flush()
        return IssuedSession(
            session_id=model.id,
            raw_token=raw_token,
            expires_at=expires_at,
        )

    def resolve_session(self, raw_token: str | None) -> ResolvedSession | None:
        """Resolve a presented token only when session and account remain usable."""

        token_hash = hash_session_token(raw_token)
        if token_hash is None:
            return None
        user_session = self._sessions.get_by_token_hash(token_hash)
        if user_session is None or not self._is_usable(user_session):
            return None
        user = user_session.user
        return ResolvedSession(
            session_id=user_session.id,
            principal=AuthenticatedPrincipal(
                user_id=user.id,
                username=user.username,
                display_name=user.display_name,
            ),
        )

    def revoke_session(self, raw_token: str | None) -> bool:
        """Revoke a known presented session; missing and invalid tokens are harmless."""

        return self.revoke_session_with_identity(raw_token) is not None

    def revoke_session_with_identity(
        self, raw_token: str | None
    ) -> RevokedSession | None:
        """Revoke and return internal identity only when state actually changes."""

        token_hash = hash_session_token(raw_token)
        if token_hash is None:
            return None
        user_session = self._sessions.get_by_token_hash(token_hash)
        if user_session is None or user_session.revoked_at is not None:
            return None
        now = self._current_time()
        created_at = self._as_utc(user_session.created_at)
        user_session.revoked_at = max(now, created_at)
        self._sessions.flush()
        return RevokedSession(
            session_id=user_session.id,
            user_id=user_session.user_id,
        )

    def _is_usable(self, user_session: UserSession) -> bool:
        try:
            now = self._current_time()
            created_at = self._as_utc(user_session.created_at)
            expires_at = self._as_utc(user_session.expires_at)
            last_seen_at = (
                self._as_utc(user_session.last_seen_at)
                if user_session.last_seen_at is not None
                else None
            )
            revoked_at = (
                self._as_utc(user_session.revoked_at)
                if user_session.revoked_at is not None
                else None
            )
        except (TypeError, ValueError, OverflowError):
            return False

        return (
            user_session.user is not None
            and user_session.user.is_usable_for_authentication
            and created_at <= now < expires_at
            and (last_seen_at is None or created_at <= last_seen_at <= now)
            and revoked_at is None
        )

    def _current_time(self) -> datetime:
        return self._as_utc(self._clock())

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError("session timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)
