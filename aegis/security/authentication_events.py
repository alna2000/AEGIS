"""Controlled credential-audit events and bounded request metadata."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_address
from typing import Protocol


MAX_USER_AGENT_CHARACTERS = 256


class InvalidAuthenticationContext(ValueError):
    """Raised when required authentication context is invalid."""


class AuthenticationEventType(str, Enum):
    """Credential-verification events owned by Phase 2."""

    PASSWORD_AUTH_SUCCESS = "PASSWORD_AUTH_SUCCESS"
    PASSWORD_AUTH_FAILURE = "PASSWORD_AUTH_FAILURE"
    TOTP_VERIFICATION_SUCCESS = "TOTP_VERIFICATION_SUCCESS"
    TOTP_VERIFICATION_FAILURE = "TOTP_VERIFICATION_FAILURE"


class AuthenticationOutcome(str, Enum):
    """Controlled authentication outcomes."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class AuthenticationReasonCode(str, Enum):
    """Internal failure categories that must not enter public results."""

    CREDENTIALS_REJECTED = "CREDENTIALS_REJECTED"
    ACCOUNT_UNUSABLE = "ACCOUNT_UNUSABLE"
    IDENTIFIER_REJECTED = "IDENTIFIER_REJECTED"
    TOTP_REJECTED = "TOTP_REJECTED"
    MFA_CREDENTIAL_UNUSABLE = "MFA_CREDENTIAL_UNUSABLE"
    TOTP_REPLAYED = "TOTP_REPLAYED"


@dataclass(frozen=True, slots=True)
class AuthenticationRequestContext:
    """Allowlisted and minimized metadata for one login attempt."""

    request_id: uuid.UUID
    source_ip: str | None = None
    user_agent: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, uuid.UUID):
            raise InvalidAuthenticationContext("request_id must be a UUID")

        object.__setattr__(self, "source_ip", self._normalize_source_ip(self.source_ip))
        object.__setattr__(
            self,
            "user_agent",
            self._normalize_user_agent(self.user_agent),
        )

    @staticmethod
    def _normalize_source_ip(value: str | None) -> str | None:
        if not isinstance(value, str):
            return None
        try:
            return ip_address(value.strip()).compressed
        except ValueError:
            return None

    @staticmethod
    def _normalize_user_agent(value: str | None) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = value.strip()
        if not normalized:
            return None
        if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
            return None
        return normalized[:MAX_USER_AGENT_CHARACTERS]


@dataclass(frozen=True, slots=True)
class AuthenticationAuditEvent:
    """Allowlisted authentication event with no arbitrary metadata container."""

    event_type: AuthenticationEventType
    outcome: AuthenticationOutcome
    reason_code: AuthenticationReasonCode | None
    request_id: uuid.UUID
    user_id: uuid.UUID | None = None
    username: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None

    def __post_init__(self) -> None:
        successful_types = {
            AuthenticationEventType.PASSWORD_AUTH_SUCCESS,
            AuthenticationEventType.TOTP_VERIFICATION_SUCCESS,
        }
        failed_types = {
            AuthenticationEventType.PASSWORD_AUTH_FAILURE,
            AuthenticationEventType.TOTP_VERIFICATION_FAILURE,
        }
        if self.outcome is AuthenticationOutcome.SUCCESS:
            if self.event_type not in successful_types:
                raise ValueError("successful credential outcome requires a success event")
            if self.reason_code is not None or self.user_id is None or self.username is None:
                raise ValueError("successful audit event requires an identified user")
        elif self.event_type not in failed_types:
            raise ValueError("failed credential outcome requires a failure event")
        elif self.reason_code is None:
            raise ValueError("failed audit event requires a controlled reason code")
        elif self.event_type is AuthenticationEventType.PASSWORD_AUTH_FAILURE and (
            self.reason_code
            not in {
                AuthenticationReasonCode.CREDENTIALS_REJECTED,
                AuthenticationReasonCode.ACCOUNT_UNUSABLE,
                AuthenticationReasonCode.IDENTIFIER_REJECTED,
            }
        ):
            raise ValueError("password failure requires a password reason code")
        elif self.event_type is AuthenticationEventType.TOTP_VERIFICATION_FAILURE:
            if self.reason_code not in {
                AuthenticationReasonCode.TOTP_REJECTED,
                AuthenticationReasonCode.MFA_CREDENTIAL_UNUSABLE,
                AuthenticationReasonCode.TOTP_REPLAYED,
            }:
                raise ValueError("TOTP failure requires a TOTP reason code")
            if self.user_id is None or self.username is None:
                raise ValueError("TOTP audit event requires an identified user")


class AuthenticationAuditSink(Protocol):
    """Application-side boundary for required authentication audit emission."""

    def record(self, event: AuthenticationAuditEvent) -> None:
        """Record one controlled authentication event or raise on failure."""


class AuthenticationAuditError(RuntimeError):
    """Raised when required authentication audit emission does not complete."""
