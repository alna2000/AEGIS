"""Typed, minimized security-event vocabulary for persistent audit evidence."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Mapping


class SecurityEventFamily(str, Enum):
    """Derived event grouping; it is not independently persisted."""

    AUTHENTICATION = "AUTHENTICATION"
    MFA = "MFA"
    SESSION = "SESSION"
    AUTHORIZATION = "AUTHORIZATION"
    RESOURCE_ACCESS = "RESOURCE_ACCESS"
    ABUSE_CONTROL = "ABUSE_CONTROL"
    OPERATIONAL_SECURITY = "OPERATIONAL_SECURITY"


class SecurityEventCode(str, Enum):
    PASSWORD_AUTH_SUCCEEDED = "PASSWORD_AUTH_SUCCEEDED"
    PASSWORD_AUTH_FAILED = "PASSWORD_AUTH_FAILED"
    MFA_FACTOR_SUCCEEDED = "MFA_FACTOR_SUCCEEDED"
    MFA_FACTOR_FAILED = "MFA_FACTOR_FAILED"
    MFA_CHALLENGE_EXHAUSTED = "MFA_CHALLENGE_EXHAUSTED"
    MFA_CHALLENGE_ISSUED = "MFA_CHALLENGE_ISSUED"
    SESSION_ESTABLISHED = "SESSION_ESTABLISHED"
    SESSION_REVOKED = "SESSION_REVOKED"
    LOGOUT_SUCCEEDED = "LOGOUT_SUCCEEDED"
    AUTHORIZATION_ALLOWED = "AUTHORIZATION_ALLOWED"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
    RESOURCE_READ_SUCCEEDED = "RESOURCE_READ_SUCCEEDED"
    RESOURCE_COLLECTION_READ = "RESOURCE_COLLECTION_READ"
    RESOURCE_READ_INACCESSIBLE = "RESOURCE_READ_INACCESSIBLE"
    ABUSE_ADMISSION_DENIED = "ABUSE_ADMISSION_DENIED"
    ABUSE_STORE_UNAVAILABLE = "ABUSE_STORE_UNAVAILABLE"
    CONCURRENCY_SATURATED = "CONCURRENCY_SATURATED"
    AUDIT_PERSISTENCE_FAILED = "AUDIT_PERSISTENCE_FAILED"


class SecurityEventOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    ALLOW = "ALLOW"
    DENY = "DENY"
    LIMITED = "LIMITED"
    ERROR = "ERROR"


class SecurityEventSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class SecurityActorType(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    USER = "USER"
    SYSTEM = "SYSTEM"


class SecurityTargetType(str, Enum):
    USER = "USER"
    MFA_CHALLENGE = "MFA_CHALLENGE"
    SESSION = "SESSION"
    INTELLIGENCE_RECORD = "INTELLIGENCE_RECORD"
    ENDPOINT = "ENDPOINT"
    AUDIT_EVENT = "AUDIT_EVENT"
    SECURITY_SUBSYSTEM = "SECURITY_SUBSYSTEM"


class SecurityEventAction(str, Enum):
    AUTHENTICATE = "AUTHENTICATE"
    VERIFY_MFA = "VERIFY_MFA"
    ESTABLISH_SESSION = "ESTABLISH_SESSION"
    REVOKE_SESSION = "REVOKE_SESSION"
    AUTHORIZE = "AUTHORIZE"
    READ_RESOURCE = "READ_RESOURCE"
    APPLY_ABUSE_CONTROL = "APPLY_ABUSE_CONTROL"
    PERSIST_AUDIT = "PERSIST_AUDIT"


class SecurityEventReason(str, Enum):
    CREDENTIALS_REJECTED = "CREDENTIALS_REJECTED"
    ACCOUNT_UNUSABLE = "ACCOUNT_UNUSABLE"
    IDENTIFIER_REJECTED = "IDENTIFIER_REJECTED"
    TOTP_REJECTED = "TOTP_REJECTED"
    TOTP_REPLAYED = "TOTP_REPLAYED"
    MFA_CREDENTIAL_UNUSABLE = "MFA_CREDENTIAL_UNUSABLE"
    CHALLENGE_FAILURE_LIMIT = "CHALLENGE_FAILURE_LIMIT"
    POLICY_DENIED = "POLICY_DENIED"
    POLICY_EVALUATION_ERROR = "POLICY_EVALUATION_ERROR"
    RESOURCE_INACCESSIBLE = "RESOURCE_INACCESSIBLE"
    RATE_LIMIT = "RATE_LIMIT"
    COOLDOWN = "COOLDOWN"
    CONCURRENCY = "CONCURRENCY"
    STORE_CAPACITY = "STORE_CAPACITY"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
    DATABASE_ERROR = "DATABASE_ERROR"
    AUDIT_ERROR = "AUDIT_ERROR"


@dataclass(frozen=True, slots=True)
class _EventDefinition:
    family: SecurityEventFamily
    outcome: SecurityEventOutcome
    severity: SecurityEventSeverity
    action: SecurityEventAction
    reason_required: bool


_EVENT_DEFINITIONS: Mapping[SecurityEventCode, _EventDefinition] = MappingProxyType(
    {
        SecurityEventCode.PASSWORD_AUTH_SUCCEEDED: _EventDefinition(SecurityEventFamily.AUTHENTICATION, SecurityEventOutcome.SUCCESS, SecurityEventSeverity.INFORMATIONAL, SecurityEventAction.AUTHENTICATE, False),
        SecurityEventCode.PASSWORD_AUTH_FAILED: _EventDefinition(SecurityEventFamily.AUTHENTICATION, SecurityEventOutcome.FAILURE, SecurityEventSeverity.LOW, SecurityEventAction.AUTHENTICATE, True),
        SecurityEventCode.MFA_FACTOR_SUCCEEDED: _EventDefinition(SecurityEventFamily.MFA, SecurityEventOutcome.SUCCESS, SecurityEventSeverity.INFORMATIONAL, SecurityEventAction.VERIFY_MFA, False),
        SecurityEventCode.MFA_FACTOR_FAILED: _EventDefinition(SecurityEventFamily.MFA, SecurityEventOutcome.FAILURE, SecurityEventSeverity.MEDIUM, SecurityEventAction.VERIFY_MFA, True),
        SecurityEventCode.MFA_CHALLENGE_EXHAUSTED: _EventDefinition(SecurityEventFamily.MFA, SecurityEventOutcome.DENY, SecurityEventSeverity.HIGH, SecurityEventAction.VERIFY_MFA, True),
        SecurityEventCode.MFA_CHALLENGE_ISSUED: _EventDefinition(SecurityEventFamily.MFA, SecurityEventOutcome.SUCCESS, SecurityEventSeverity.INFORMATIONAL, SecurityEventAction.VERIFY_MFA, False),
        SecurityEventCode.SESSION_ESTABLISHED: _EventDefinition(SecurityEventFamily.SESSION, SecurityEventOutcome.SUCCESS, SecurityEventSeverity.INFORMATIONAL, SecurityEventAction.ESTABLISH_SESSION, False),
        SecurityEventCode.SESSION_REVOKED: _EventDefinition(SecurityEventFamily.SESSION, SecurityEventOutcome.SUCCESS, SecurityEventSeverity.INFORMATIONAL, SecurityEventAction.REVOKE_SESSION, False),
        SecurityEventCode.LOGOUT_SUCCEEDED: _EventDefinition(SecurityEventFamily.SESSION, SecurityEventOutcome.SUCCESS, SecurityEventSeverity.INFORMATIONAL, SecurityEventAction.REVOKE_SESSION, False),
        SecurityEventCode.AUTHORIZATION_ALLOWED: _EventDefinition(SecurityEventFamily.AUTHORIZATION, SecurityEventOutcome.ALLOW, SecurityEventSeverity.INFORMATIONAL, SecurityEventAction.AUTHORIZE, False),
        SecurityEventCode.AUTHORIZATION_DENIED: _EventDefinition(SecurityEventFamily.AUTHORIZATION, SecurityEventOutcome.DENY, SecurityEventSeverity.LOW, SecurityEventAction.AUTHORIZE, True),
        SecurityEventCode.AUTHORIZATION_ERROR: _EventDefinition(SecurityEventFamily.AUTHORIZATION, SecurityEventOutcome.ERROR, SecurityEventSeverity.HIGH, SecurityEventAction.AUTHORIZE, True),
        SecurityEventCode.RESOURCE_READ_SUCCEEDED: _EventDefinition(SecurityEventFamily.RESOURCE_ACCESS, SecurityEventOutcome.SUCCESS, SecurityEventSeverity.INFORMATIONAL, SecurityEventAction.READ_RESOURCE, False),
        SecurityEventCode.RESOURCE_COLLECTION_READ: _EventDefinition(SecurityEventFamily.RESOURCE_ACCESS, SecurityEventOutcome.SUCCESS, SecurityEventSeverity.INFORMATIONAL, SecurityEventAction.READ_RESOURCE, False),
        SecurityEventCode.RESOURCE_READ_INACCESSIBLE: _EventDefinition(SecurityEventFamily.RESOURCE_ACCESS, SecurityEventOutcome.DENY, SecurityEventSeverity.LOW, SecurityEventAction.READ_RESOURCE, True),
        SecurityEventCode.ABUSE_ADMISSION_DENIED: _EventDefinition(SecurityEventFamily.ABUSE_CONTROL, SecurityEventOutcome.LIMITED, SecurityEventSeverity.MEDIUM, SecurityEventAction.APPLY_ABUSE_CONTROL, True),
        SecurityEventCode.ABUSE_STORE_UNAVAILABLE: _EventDefinition(SecurityEventFamily.OPERATIONAL_SECURITY, SecurityEventOutcome.ERROR, SecurityEventSeverity.HIGH, SecurityEventAction.APPLY_ABUSE_CONTROL, True),
        SecurityEventCode.CONCURRENCY_SATURATED: _EventDefinition(SecurityEventFamily.ABUSE_CONTROL, SecurityEventOutcome.LIMITED, SecurityEventSeverity.MEDIUM, SecurityEventAction.APPLY_ABUSE_CONTROL, True),
        SecurityEventCode.AUDIT_PERSISTENCE_FAILED: _EventDefinition(SecurityEventFamily.OPERATIONAL_SECURITY, SecurityEventOutcome.ERROR, SecurityEventSeverity.HIGH, SecurityEventAction.PERSIST_AUDIT, True),
    }
)

_SOURCE_KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")


@dataclass(frozen=True, slots=True)
class AuditSourceCorrelation:
    """A pre-derived opaque audit correlation; Part 1 does not generate it."""

    digest: bytes = field(repr=False)
    key_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.digest, bytes) or len(self.digest) != 32:
            raise ValueError("audit source correlation must be a 32-byte digest")
        if not isinstance(self.key_id, str) or _SOURCE_KEY_ID_PATTERN.fullmatch(self.key_id) is None:
            raise ValueError("audit source correlation key ID is invalid")

    def __repr__(self) -> str:
        return f"AuditSourceCorrelation(key_id={self.key_id!r}, digest=<redacted>)"


@dataclass(frozen=True, slots=True)
class SecurityEventDraft:
    """Immutable allowlisted input for one future durable security event."""

    event_code: SecurityEventCode
    actor_type: SecurityActorType
    request_id: uuid.UUID | None
    actor_user_id: uuid.UUID | None = None
    subject_user_id: uuid.UUID | None = None
    target_type: SecurityTargetType | None = None
    target_id: uuid.UUID | None = None
    reason_code: SecurityEventReason | None = None
    source: AuditSourceCorrelation | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _validate_event_fields(
            self.event_code,
            self.actor_type,
            self.request_id,
            self.actor_user_id,
            self.subject_user_id,
            self.target_type,
            self.target_id,
            self.reason_code,
            self.source,
        )


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Complete immutable event generated by the audit service."""

    id: uuid.UUID
    occurred_at: datetime
    event_code: SecurityEventCode
    outcome: SecurityEventOutcome
    severity: SecurityEventSeverity
    actor_type: SecurityActorType
    action: SecurityEventAction
    request_id: uuid.UUID | None
    actor_user_id: uuid.UUID | None = None
    subject_user_id: uuid.UUID | None = None
    target_type: SecurityTargetType | None = None
    target_id: uuid.UUID | None = None
    reason_code: SecurityEventReason | None = None
    source: AuditSourceCorrelation | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.id, uuid.UUID):
            raise TypeError("security event ID must be a UUID")
        if not isinstance(self.occurred_at, datetime) or self.occurred_at.tzinfo is None:
            raise ValueError("security event timestamp must be timezone-aware")
        object.__setattr__(self, "occurred_at", self.occurred_at.astimezone(timezone.utc))
        definition = event_definition(self.event_code)
        if self.outcome is not definition.outcome or self.severity is not definition.severity or self.action is not definition.action:
            raise ValueError("security event derived fields contradict its event code")
        _validate_event_fields(
            self.event_code,
            self.actor_type,
            self.request_id,
            self.actor_user_id,
            self.subject_user_id,
            self.target_type,
            self.target_id,
            self.reason_code,
            self.source,
        )

    @property
    def family(self) -> SecurityEventFamily:
        return event_definition(self.event_code).family


def event_definition(event_code: SecurityEventCode) -> _EventDefinition:
    if not isinstance(event_code, SecurityEventCode):
        raise TypeError("event code must be controlled")
    return _EVENT_DEFINITIONS[event_code]


def _validate_event_fields(
    event_code: object,
    actor_type: object,
    request_id: object,
    actor_user_id: object,
    subject_user_id: object,
    target_type: object,
    target_id: object,
    reason_code: object,
    source: object,
) -> None:
    definition = event_definition(event_code)  # type: ignore[arg-type]
    if not isinstance(actor_type, SecurityActorType):
        raise TypeError("actor type must be controlled")
    if actor_type is SecurityActorType.USER:
        if not isinstance(actor_user_id, uuid.UUID):
            raise ValueError("user actor requires an internal user UUID")
    elif actor_user_id is not None:
        raise ValueError("anonymous/system actor cannot contain a user ID")
    if subject_user_id is not None and not isinstance(subject_user_id, uuid.UUID):
        raise TypeError("subject user ID must be a UUID")
    if actor_user_id is not None and subject_user_id == actor_user_id:
        raise ValueError("subject user ID is only for a different user")
    if request_id is not None and not isinstance(request_id, uuid.UUID):
        raise TypeError("request ID must be a UUID")
    if actor_type is not SecurityActorType.SYSTEM and request_id is None:
        raise ValueError("request-owned event requires a server request UUID")
    if target_type is not None and not isinstance(target_type, SecurityTargetType):
        raise TypeError("target type must be controlled")
    if target_id is not None and not isinstance(target_id, uuid.UUID):
        raise TypeError("target ID must be a UUID")
    if target_id is not None and target_type is None:
        raise ValueError("target ID requires a controlled target type")
    if reason_code is not None and not isinstance(reason_code, SecurityEventReason):
        raise TypeError("reason code must be controlled")
    if definition.reason_required != (reason_code is not None):
        raise ValueError("event reason presence contradicts its event code")
    if source is not None and not isinstance(source, AuditSourceCorrelation):
        raise TypeError("source must be a pre-derived audit correlation")
