"""Password-authentication service without HTTP or authorization behavior."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum

from aegis.db.repositories import UserRepository
from aegis.security.authentication_events import (
    AuthenticationAuditEvent,
    AuthenticationAuditSink,
    AuthenticationEventType,
    AuthenticationOutcome,
    AuthenticationReasonCode,
    AuthenticationRequestContext,
)
from aegis.security.identity import InvalidIdentity, normalize_username
from aegis.security.passwords import PasswordService


# Generated once from random discarded input using the current Argon2id
# parameters. It is not attached to any account and grants no access.
_DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$PJF4P3hVuMYrIpwaPF6Adg$"
    "C9881rA5sLOqDuped4B2zNh9ICSO+U8sQgpgJ69AM6k"
)


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Verified identity only; this object grants no authorization."""

    user_id: uuid.UUID
    username: str
    display_name: str


class LoginAttemptStatus(str, Enum):
    """Publicly consumable login-attempt status."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


@dataclass(frozen=True, slots=True)
class LoginAttemptResult:
    """Generic login result containing identity only after success."""

    status: LoginAttemptStatus
    principal: AuthenticatedPrincipal | None = None
    audit_user_id: uuid.UUID | None = field(default=None, compare=False, repr=False)
    audit_reason_code: AuthenticationReasonCode | None = field(
        default=None, compare=False, repr=False
    )

    def __post_init__(self) -> None:
        if (self.status is LoginAttemptStatus.SUCCESS) != (self.principal is not None):
            raise ValueError("only a successful login result may contain a principal")
        if self.status is LoginAttemptStatus.SUCCESS:
            if self.audit_reason_code is not None:
                raise ValueError("successful login result cannot contain a failure reason")
        elif not isinstance(self.audit_reason_code, AuthenticationReasonCode):
            # Compatibility construction remains useful in older service tests;
            # real service failures always supply their controlled reason below.
            if self.audit_reason_code is not None:
                raise TypeError("login audit reason must be controlled")

    @classmethod
    def success(cls, principal: AuthenticatedPrincipal) -> LoginAttemptResult:
        return cls(status=LoginAttemptStatus.SUCCESS, principal=principal)

    @classmethod
    def failure(
        cls,
        *,
        user_id: uuid.UUID | None = None,
        reason_code: AuthenticationReasonCode | None = None,
    ) -> LoginAttemptResult:
        return cls(
            status=LoginAttemptStatus.FAILURE,
            audit_user_id=user_id,
            audit_reason_code=reason_code,
        )


class AuthenticationService:
    """Orchestrate a password login attempt without HTTP or session state."""

    def __init__(
        self,
        users: UserRepository,
        passwords: PasswordService,
        audit_sink: AuthenticationAuditSink,
    ) -> None:
        self._users = users
        self._passwords = passwords
        self._audit_sink = audit_sink

    def attempt_login(
        self,
        username: str,
        password: str,
        context: AuthenticationRequestContext,
    ) -> LoginAttemptResult:
        """Verify one login attempt and emit its required controlled audit event."""

        user = self._users.get_by_username(username)
        if user is None:
            self._perform_dummy_verification(password)
            reason = (
                AuthenticationReasonCode.IDENTIFIER_REJECTED
                if self._is_malformed_identifier(username)
                else AuthenticationReasonCode.CREDENTIALS_REJECTED
            )
            self._record_credential_failure(context=context, reason_code=reason)
            return LoginAttemptResult.failure(reason_code=reason)

        if not user.is_usable_for_authentication:
            self._perform_dummy_verification(password)
            self._record_credential_failure(
                context=context,
                reason_code=AuthenticationReasonCode.ACCOUNT_UNUSABLE,
                user_id=user.id,
                username=user.username,
            )
            return LoginAttemptResult.failure(
                user_id=user.id,
                reason_code=AuthenticationReasonCode.ACCOUNT_UNUSABLE,
            )

        verification = self._passwords.verify_and_update(password, user.password_hash)
        if not verification.valid:
            self._record_credential_failure(
                context=context,
                reason_code=AuthenticationReasonCode.CREDENTIALS_REJECTED,
                user_id=user.id,
                username=user.username,
            )
            return LoginAttemptResult.failure(
                user_id=user.id,
                reason_code=AuthenticationReasonCode.CREDENTIALS_REJECTED,
            )

        principal = AuthenticatedPrincipal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
        )
        self._record_credential_success(context=context, principal=principal)

        if verification.replacement_hash is not None:
            user.password_hash = verification.replacement_hash
            self._users.flush()

        return LoginAttemptResult.success(principal)

    def _perform_dummy_verification(self, password: str) -> None:
        # This mitigates a practical CPU-cost enumeration signal; database and
        # runtime behavior are not claimed to be mathematically constant-time.
        self._passwords.verify(password, _DUMMY_PASSWORD_HASH)

    def _record_credential_success(
        self,
        *,
        context: AuthenticationRequestContext,
        principal: AuthenticatedPrincipal,
    ) -> None:
        self._record(
            AuthenticationAuditEvent(
                event_type=AuthenticationEventType.PASSWORD_AUTH_SUCCESS,
                outcome=AuthenticationOutcome.SUCCESS,
                reason_code=None,
                request_id=context.request_id,
                user_id=principal.user_id,
                username=principal.username,
                source_ip=context.source_ip,
                user_agent=context.user_agent,
            )
        )

    def _record_credential_failure(
        self,
        *,
        context: AuthenticationRequestContext,
        reason_code: AuthenticationReasonCode,
        user_id: uuid.UUID | None = None,
        username: str | None = None,
    ) -> None:
        self._record(
            AuthenticationAuditEvent(
                event_type=AuthenticationEventType.PASSWORD_AUTH_FAILURE,
                outcome=AuthenticationOutcome.FAILURE,
                reason_code=reason_code,
                request_id=context.request_id,
                user_id=user_id,
                username=username,
                source_ip=context.source_ip,
                user_agent=context.user_agent,
            )
        )

    def _record(self, event: AuthenticationAuditEvent) -> None:
        """Retain secret-free operational diagnostics without audit semantics."""

        try:
            self._audit_sink.record(event)
        except Exception:
            # Durable evidence is staged separately in the caller-owned database
            # transaction. A secondary logger failure cannot contradict it.
            return

    @staticmethod
    def _is_malformed_identifier(username: str) -> bool:
        # Repository lookup deliberately returns None for both malformed and
        # missing identifiers. This internal categorization never enters the
        # public LoginAttemptResult or retains attacker-supplied identifier text.
        try:
            normalize_username(username)
        except (InvalidIdentity, TypeError):
            return True
        return False
