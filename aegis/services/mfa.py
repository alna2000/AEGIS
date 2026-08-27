"""TOTP enrollment, confirmation, verification, replay, and disable lifecycle."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from aegis.db.models import MfaCredential
from aegis.db.repositories import MfaCredentialRepository
from aegis.security.authentication_events import (
    AuthenticationAuditEvent,
    AuthenticationAuditSink,
    AuthenticationEventType,
    AuthenticationOutcome,
    AuthenticationReasonCode,
    AuthenticationRequestContext,
)
from aegis.security.mfa_encryption import MfaSecretCipher, MfaSecretDecryptionError
from aegis.security.totp import TotpService
from aegis.services.authentication import AuthenticatedPrincipal


class MfaEnrollmentConflict(RuntimeError):
    """Raised when a user already has a pending or enabled TOTP credential."""


class MfaVerificationStatus(str, Enum):
    """Internal factor outcome used to classify challenge failure accounting."""

    SUCCESS = "SUCCESS"
    FACTOR_FAILURE = "FACTOR_FAILURE"
    CREDENTIAL_UNUSABLE = "CREDENTIAL_UNUSABLE"


@dataclass(frozen=True, slots=True)
class MfaVerificationResult:
    """Controlled factor result with its durable internal reason when rejected."""

    status: MfaVerificationStatus
    reason_code: AuthenticationReasonCode | None

    def __post_init__(self) -> None:
        if self.status is MfaVerificationStatus.SUCCESS:
            if self.reason_code is not None:
                raise ValueError("successful MFA result cannot contain a reason")
        elif not isinstance(self.reason_code, AuthenticationReasonCode):
            raise ValueError("rejected MFA result requires a controlled reason")


@dataclass(frozen=True, slots=True)
class TotpEnrollmentMaterial:
    """One-time enrollment output; its secret-bearing fields never enter repr."""

    credential_id: uuid.UUID
    secret: str = field(repr=False)
    provisioning_uri: str = field(repr=False)


class MfaService:
    """Centralize the complete service-layer TOTP credential lifecycle."""

    def __init__(
        self,
        credentials: MfaCredentialRepository,
        cipher: MfaSecretCipher,
        totp: TotpService,
        audit_sink: AuthenticationAuditSink,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._credentials = credentials
        self._cipher = cipher
        self._totp = totp
        self._audit_sink = audit_sink
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def begin_enrollment(
        self,
        principal: AuthenticatedPrincipal,
    ) -> TotpEnrollmentMaterial:
        """Persist a fresh encrypted pending secret and return it exactly once."""

        if self._credentials.get_current_totp(principal.user_id, for_update=True):
            raise MfaEnrollmentConflict(
                "a pending or enabled TOTP credential already exists"
            )
        now = self._current_time()
        secret = self._totp.generate_secret()
        credential = MfaCredential(
            user_id=principal.user_id,
            method_type="TOTP",
            encrypted_secret=self._cipher.encrypt(secret),
            encryption_key_id=self._cipher.key_id,
            enabled=False,
            created_at=now,
        )
        self._credentials.add(credential)
        self._credentials.flush()
        return TotpEnrollmentMaterial(
            credential_id=credential.id,
            secret=secret,
            provisioning_uri=self._totp.provisioning_uri(secret, principal.username),
        )

    def confirm_enrollment(
        self,
        principal: AuthenticatedPrincipal,
        code: object,
        context: AuthenticationRequestContext,
    ) -> bool:
        """Enable a pending credential only after a fresh valid proof."""

        credential = self._credentials.get_current_totp(
            principal.user_id, for_update=True
        )
        if credential is None or credential.enabled:
            self._record_failure(
                principal, context, AuthenticationReasonCode.MFA_CREDENTIAL_UNUSABLE
            )
            return False
        return self._accept_code(credential, principal, code, context, enable=True)

    def verify(
        self,
        principal: AuthenticatedPrincipal,
        code: object,
        context: AuthenticationRequestContext,
    ) -> bool:
        """Verify an enabled credential and consume its matching TOTP counter."""

        return (
            self.verify_result(principal, code, context)
            is MfaVerificationStatus.SUCCESS
        )

    def verify_result(
        self,
        principal: AuthenticatedPrincipal,
        code: object,
        context: AuthenticationRequestContext,
    ) -> MfaVerificationStatus:
        """Verify TOTP while distinguishing factor failures from unusable state."""

        return self.verify_detailed_result(principal, code, context).status

    def verify_detailed_result(
        self,
        principal: AuthenticatedPrincipal,
        code: object,
        context: AuthenticationRequestContext,
    ) -> MfaVerificationResult:
        """Return the controlled internal reason needed for durable evidence."""

        credential = self._credentials.get_current_totp(
            principal.user_id, for_update=True
        )
        if credential is None or not credential.enabled:
            self._record_failure(
                principal, context, AuthenticationReasonCode.MFA_CREDENTIAL_UNUSABLE
            )
            return MfaVerificationResult(
                MfaVerificationStatus.CREDENTIAL_UNUSABLE,
                AuthenticationReasonCode.MFA_CREDENTIAL_UNUSABLE,
            )
        return self._verify_code_result(credential, principal, code, context)

    def _verify_code_result(
        self,
        credential: MfaCredential,
        principal: AuthenticatedPrincipal,
        code: object,
        context: AuthenticationRequestContext,
    ) -> MfaVerificationResult:
        try:
            secret = self._cipher.decrypt(
                credential.encrypted_secret, credential.encryption_key_id
            )
        except MfaSecretDecryptionError:
            self._record_failure(
                principal, context, AuthenticationReasonCode.MFA_CREDENTIAL_UNUSABLE
            )
            return MfaVerificationResult(
                MfaVerificationStatus.CREDENTIAL_UNUSABLE,
                AuthenticationReasonCode.MFA_CREDENTIAL_UNUSABLE,
            )

        now = self._current_time()
        try:
            counter = self._totp.matching_counter(secret, code, now)
        except (TypeError, ValueError, OverflowError):
            counter = None
        if counter is None:
            self._record_failure(
                principal, context, AuthenticationReasonCode.TOTP_REJECTED
            )
            return MfaVerificationResult(
                MfaVerificationStatus.FACTOR_FAILURE,
                AuthenticationReasonCode.TOTP_REJECTED,
            )
        if (
            credential.last_accepted_counter is not None
            and counter <= credential.last_accepted_counter
        ):
            self._record_failure(
                principal, context, AuthenticationReasonCode.TOTP_REPLAYED
            )
            return MfaVerificationResult(
                MfaVerificationStatus.FACTOR_FAILURE,
                AuthenticationReasonCode.TOTP_REPLAYED,
            )

        self._record_success(principal, context)
        credential.last_accepted_counter = counter
        credential.last_used_at = max(now, self._as_utc(credential.created_at))
        self._credentials.flush()
        return MfaVerificationResult(MfaVerificationStatus.SUCCESS, None)

    def disable(self, principal: AuthenticatedPrincipal) -> bool:
        """Disable, but do not delete, the current TOTP credential."""

        credential = self._credentials.get_current_totp(
            principal.user_id, for_update=True
        )
        if credential is None:
            return False
        credential.enabled = False
        credential.disabled_at = max(
            self._current_time(), self._as_utc(credential.created_at)
        )
        self._credentials.flush()
        return True

    def _accept_code(
        self,
        credential: MfaCredential,
        principal: AuthenticatedPrincipal,
        code: object,
        context: AuthenticationRequestContext,
        *,
        enable: bool,
    ) -> bool:
        try:
            secret = self._cipher.decrypt(
                credential.encrypted_secret, credential.encryption_key_id
            )
        except MfaSecretDecryptionError:
            self._record_failure(
                principal, context, AuthenticationReasonCode.MFA_CREDENTIAL_UNUSABLE
            )
            return False

        now = self._current_time()
        try:
            counter = self._totp.matching_counter(secret, code, now)
        except (TypeError, ValueError, OverflowError):
            counter = None
        if counter is None:
            self._record_failure(
                principal, context, AuthenticationReasonCode.TOTP_REJECTED
            )
            return False
        if (
            credential.last_accepted_counter is not None
            and counter <= credential.last_accepted_counter
        ):
            self._record_failure(
                principal, context, AuthenticationReasonCode.TOTP_REPLAYED
            )
            return False

        self._record_success(principal, context)
        credential.last_accepted_counter = counter
        credential.last_used_at = max(now, self._as_utc(credential.created_at))
        if enable:
            credential.enabled = True
        self._credentials.flush()
        return True

    def _record_success(
        self,
        principal: AuthenticatedPrincipal,
        context: AuthenticationRequestContext,
    ) -> None:
        self._record(
            AuthenticationAuditEvent(
                event_type=AuthenticationEventType.TOTP_VERIFICATION_SUCCESS,
                outcome=AuthenticationOutcome.SUCCESS,
                reason_code=None,
                request_id=context.request_id,
                user_id=principal.user_id,
                username=principal.username,
                source_ip=context.source_ip,
                user_agent=context.user_agent,
            )
        )

    def _record_failure(
        self,
        principal: AuthenticatedPrincipal,
        context: AuthenticationRequestContext,
        reason: AuthenticationReasonCode,
    ) -> None:
        self._record(
            AuthenticationAuditEvent(
                event_type=AuthenticationEventType.TOTP_VERIFICATION_FAILURE,
                outcome=AuthenticationOutcome.FAILURE,
                reason_code=reason,
                request_id=context.request_id,
                user_id=principal.user_id,
                username=principal.username,
                source_ip=context.source_ip,
                user_agent=context.user_agent,
            )
        )

    def _record(self, event: AuthenticationAuditEvent) -> None:
        """Retain best-effort operational logging separate from durable audit."""

        try:
            self._audit_sink.record(event)
        except Exception:
            return

    def _current_time(self) -> datetime:
        return self._as_utc(self._clock())

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError("MFA timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)
