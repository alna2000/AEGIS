"""Short-lived, hash-only MFA challenge creation and consumption."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from aegis.db.models import MfaChallenge
from aegis.db.repositories import MfaChallengeRepository, MfaCredentialRepository
from aegis.security.authentication_events import AuthenticationRequestContext
from aegis.services.authentication import AuthenticatedPrincipal


MFA_CHALLENGE_TOKEN_BYTES = 32
MFA_CHALLENGE_TOKEN_CHARACTERS = 43
_MFA_CHALLENGE_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class MfaChallengeServiceError(RuntimeError):
    """Raised when secure challenge material or state cannot be created."""


@dataclass(frozen=True, slots=True)
class IssuedMfaChallenge:
    """One raw challenge credential returned only to the cookie boundary."""

    raw_token: str = field(repr=False)
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ResolvedMfaChallenge:
    """Locked usable challenge state bound to a password-verified identity."""

    challenge_id: uuid.UUID
    principal: AuthenticatedPrincipal
    _challenge: MfaChallenge = field(repr=False)


def generate_mfa_challenge_token() -> str:
    """Return a distinct URL-safe challenge token with 256 bits of entropy."""

    return base64.urlsafe_b64encode(
        secrets.token_bytes(MFA_CHALLENGE_TOKEN_BYTES)
    ).rstrip(b"=").decode("ascii")


def hash_mfa_challenge_token(raw_token: str | None) -> str | None:
    """Return a deterministic lookup hash only for well-formed challenge tokens."""

    if not isinstance(raw_token, str) or not _MFA_CHALLENGE_TOKEN_PATTERN.fullmatch(
        raw_token
    ):
        return None
    return hashlib.sha256(raw_token.encode("ascii")).hexdigest()


class MfaChallengeService:
    """Own MFA requirement decisions and challenge lifecycle transitions."""

    def __init__(
        self,
        challenges: MfaChallengeRepository,
        credentials: MfaCredentialRepository,
        *,
        lifetime: timedelta,
        clock: Callable[[], datetime] | None = None,
        token_generator: Callable[[], str] = generate_mfa_challenge_token,
    ) -> None:
        if lifetime <= timedelta(0):
            raise ValueError("MFA challenge lifetime must be positive")
        self._challenges = challenges
        self._credentials = credentials
        self._lifetime = lifetime
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._token_generator = token_generator

    def requires_totp(self, principal: AuthenticatedPrincipal) -> bool:
        """Return whether the user currently has an enabled TOTP credential."""

        credential = self._credentials.get_current_totp(
            principal.user_id, for_update=True
        )
        return credential is not None and credential.enabled

    def create_challenge(
        self,
        principal: AuthenticatedPrincipal,
        context: AuthenticationRequestContext,
    ) -> IssuedMfaChallenge:
        """Revoke prior open challenges and stage one fresh challenge."""

        now = self._current_time()
        raw_token = self._token_generator()
        token_hash = hash_mfa_challenge_token(raw_token)
        if token_hash is None:
            raise MfaChallengeServiceError("secure MFA challenge generation failed")

        for existing in self._challenges.get_open_for_user_for_update(
            principal.user_id
        ):
            existing.revoked_at = max(now, self._as_utc(existing.created_at))

        expires_at = now + self._lifetime
        self._challenges.add(
            MfaChallenge(
                user_id=principal.user_id,
                token_hash=token_hash,
                created_at=now,
                expires_at=expires_at,
                source_ip=context.source_ip,
                user_agent=context.user_agent,
            )
        )
        self._challenges.flush()
        return IssuedMfaChallenge(raw_token=raw_token, expires_at=expires_at)

    def resolve_challenge(
        self, raw_token: str | None
    ) -> ResolvedMfaChallenge | None:
        """Lock and resolve a usable challenge to its current user identity."""

        token_hash = hash_mfa_challenge_token(raw_token)
        if token_hash is None:
            return None
        challenge = self._challenges.get_by_token_hash_for_update(token_hash)
        if challenge is None or not self._is_usable(challenge):
            return None
        user = challenge.user
        return ResolvedMfaChallenge(
            challenge_id=challenge.id,
            principal=AuthenticatedPrincipal(
                user_id=user.id,
                username=user.username,
                display_name=user.display_name,
            ),
            _challenge=challenge,
        )

    def consume(self, resolved: ResolvedMfaChallenge) -> None:
        """Consume a challenge already locked and validated in this transaction."""

        challenge = resolved._challenge
        if not self._is_usable(challenge):
            raise MfaChallengeServiceError("MFA challenge is no longer usable")
        challenge.consumed_at = max(
            self._current_time(), self._as_utc(challenge.created_at)
        )
        self._challenges.flush()

    def record_factor_failure(
        self, resolved: ResolvedMfaChallenge, *, maximum_failures: int
    ) -> int:
        """Persist one factor failure and revoke this challenge at its bound."""

        if type(maximum_failures) is not int or maximum_failures != 5:
            raise ValueError("the MFA challenge failure bound must be five")
        challenge = resolved._challenge
        if not self._is_usable(challenge):
            raise MfaChallengeServiceError("MFA challenge is no longer usable")
        if challenge.failed_factor_attempts >= maximum_failures:
            raise MfaChallengeServiceError("MFA challenge failure bound exceeded")
        challenge.failed_factor_attempts += 1
        if challenge.failed_factor_attempts == maximum_failures:
            challenge.revoked_at = max(
                self._current_time(), self._as_utc(challenge.created_at)
            )
        self._challenges.flush()
        return challenge.failed_factor_attempts

    def revoke(self, raw_token: str | None) -> bool:
        """Revoke a known unconsumed challenge; invalid input is harmless."""

        token_hash = hash_mfa_challenge_token(raw_token)
        if token_hash is None:
            return False
        challenge = self._challenges.get_by_token_hash_for_update(token_hash)
        if challenge is None or challenge.consumed_at is not None or challenge.revoked_at:
            return False
        challenge.revoked_at = max(
            self._current_time(), self._as_utc(challenge.created_at)
        )
        self._challenges.flush()
        return True

    def _is_usable(self, challenge: MfaChallenge) -> bool:
        try:
            now = self._current_time()
            created_at = self._as_utc(challenge.created_at)
            expires_at = self._as_utc(challenge.expires_at)
            consumed_at = (
                self._as_utc(challenge.consumed_at)
                if challenge.consumed_at is not None
                else None
            )
            revoked_at = (
                self._as_utc(challenge.revoked_at)
                if challenge.revoked_at is not None
                else None
            )
        except (TypeError, ValueError, OverflowError):
            return False
        return (
            challenge.user is not None
            and challenge.user.is_usable_for_authentication
            and created_at <= now < expires_at
            and consumed_at is None
            and revoked_at is None
        )

    def _current_time(self) -> datetime:
        return self._as_utc(self._clock())

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError("MFA challenge timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)
