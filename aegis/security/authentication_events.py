"""Controlled login-audit events and bounded request metadata."""

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
    """Authentication events owned by Phase 2."""

    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"


class AuthenticationOutcome(str, Enum):
    """Controlled authentication outcomes."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class AuthenticationReasonCode(str, Enum):
    """Internal failure categories that must not enter public results."""

    CREDENTIALS_REJECTED = "CREDENTIALS_REJECTED"
    ACCOUNT_UNUSABLE = "ACCOUNT_UNUSABLE"
    IDENTIFIER_REJECTED = "IDENTIFIER_REJECTED"


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
        if self.outcome is AuthenticationOutcome.SUCCESS:
            if self.event_type is not AuthenticationEventType.LOGIN_SUCCESS:
                raise ValueError("successful audit outcome requires LOGIN_SUCCESS")
            if self.reason_code is not None or self.user_id is None or self.username is None:
                raise ValueError("successful audit event requires an identified user")
        elif self.event_type is not AuthenticationEventType.LOGIN_FAILURE:
            raise ValueError("failed audit outcome requires LOGIN_FAILURE")
        elif self.reason_code is None:
            raise ValueError("failed audit event requires a controlled reason code")


class AuthenticationAuditSink(Protocol):
    """Application-side boundary for required authentication audit emission."""

    def record(self, event: AuthenticationAuditEvent) -> None:
        """Record one controlled authentication event or raise on failure."""


class AuthenticationAuditError(RuntimeError):
    """Raised when required authentication audit emission does not complete."""
