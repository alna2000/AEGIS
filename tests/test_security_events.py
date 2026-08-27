"""Typed security-event vocabulary, validation, and privacy tests."""

from dataclasses import fields
from datetime import datetime, timedelta, timezone
import uuid

import pytest

from aegis.security.security_events import (
    AuditSourceCorrelation,
    SecurityActorType,
    SecurityEvent,
    SecurityEventAction,
    SecurityEventCode,
    SecurityEventDraft,
    SecurityEventFamily,
    SecurityEventOutcome,
    SecurityEventReason,
    SecurityEventSeverity,
    SecurityTargetType,
    event_definition,
)


REQUEST_ID = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
USER_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
OTHER_USER_ID = uuid.UUID("66666666-7777-8888-9999-aaaaaaaaaaaa")


def test_valid_minimal_event_derives_family_and_controlled_fields() -> None:
    definition = event_definition(SecurityEventCode.PASSWORD_AUTH_FAILED)
    draft = SecurityEventDraft(
        event_code=SecurityEventCode.PASSWORD_AUTH_FAILED,
        actor_type=SecurityActorType.ANONYMOUS,
        request_id=REQUEST_ID,
        reason_code=SecurityEventReason.CREDENTIALS_REJECTED,
    )
    event = SecurityEvent(
        id=uuid.UUID("12345678-1234-5678-1234-567812345678"),
        occurred_at=datetime(2026, 8, 27, 10, 0, tzinfo=timezone(timedelta(hours=3))),
        event_code=draft.event_code,
        outcome=definition.outcome,
        severity=definition.severity,
        actor_type=draft.actor_type,
        action=definition.action,
        request_id=draft.request_id,
        reason_code=draft.reason_code,
    )

    assert event.family is SecurityEventFamily.AUTHENTICATION
    assert event.outcome is SecurityEventOutcome.FAILURE
    assert event.severity is SecurityEventSeverity.LOW
    assert event.action is SecurityEventAction.AUTHENTICATE
    assert event.occurred_at == datetime(2026, 8, 27, 7, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("event_code", "PASSWORD_AUTH_FAILED"),
        ("actor_type", "ANONYMOUS"),
        ("request_id", "not-a-uuid"),
        ("subject_user_id", "not-a-uuid"),
        ("target_type", "USER"),
        ("target_id", "not-a-uuid"),
        ("reason_code", "CREDENTIALS_REJECTED"),
    ],
)
def test_uncontrolled_or_invalid_fields_are_rejected(field_name: str, value: object) -> None:
    values: dict[str, object] = {
        "event_code": SecurityEventCode.PASSWORD_AUTH_FAILED,
        "actor_type": SecurityActorType.ANONYMOUS,
        "request_id": REQUEST_ID,
        "reason_code": SecurityEventReason.CREDENTIALS_REJECTED,
    }
    values[field_name] = value
    with pytest.raises((TypeError, ValueError)):
        SecurityEventDraft(**values)  # type: ignore[arg-type]


def test_actor_subject_target_and_request_invariants() -> None:
    with pytest.raises(ValueError, match="user actor"):
        SecurityEventDraft(
            SecurityEventCode.SESSION_ESTABLISHED,
            SecurityActorType.USER,
            REQUEST_ID,
        )
    with pytest.raises(ValueError, match="anonymous/system"):
        SecurityEventDraft(
            SecurityEventCode.SESSION_ESTABLISHED,
            SecurityActorType.SYSTEM,
            None,
            actor_user_id=USER_ID,
        )
    with pytest.raises(ValueError, match="different user"):
        SecurityEventDraft(
            SecurityEventCode.SESSION_ESTABLISHED,
            SecurityActorType.USER,
            REQUEST_ID,
            actor_user_id=USER_ID,
            subject_user_id=USER_ID,
        )
    with pytest.raises(ValueError, match="target type"):
        SecurityEventDraft(
            SecurityEventCode.SESSION_ESTABLISHED,
            SecurityActorType.USER,
            REQUEST_ID,
            actor_user_id=USER_ID,
            target_id=uuid.uuid4(),
        )
    with pytest.raises(ValueError, match="request UUID"):
        SecurityEventDraft(
            SecurityEventCode.PASSWORD_AUTH_FAILED,
            SecurityActorType.ANONYMOUS,
            None,
            reason_code=SecurityEventReason.CREDENTIALS_REJECTED,
        )

    valid = SecurityEventDraft(
        SecurityEventCode.SESSION_REVOKED,
        SecurityActorType.USER,
        REQUEST_ID,
        actor_user_id=USER_ID,
        subject_user_id=OTHER_USER_ID,
        target_type=SecurityTargetType.SESSION,
        target_id=uuid.uuid4(),
    )
    assert valid.subject_user_id == OTHER_USER_ID


def test_event_code_controls_reason_presence_and_derived_values() -> None:
    with pytest.raises(ValueError, match="reason presence"):
        SecurityEventDraft(
            SecurityEventCode.PASSWORD_AUTH_FAILED,
            SecurityActorType.ANONYMOUS,
            REQUEST_ID,
        )
    with pytest.raises(ValueError, match="reason presence"):
        SecurityEventDraft(
            SecurityEventCode.PASSWORD_AUTH_SUCCEEDED,
            SecurityActorType.USER,
            REQUEST_ID,
            actor_user_id=USER_ID,
            reason_code=SecurityEventReason.CREDENTIALS_REJECTED,
        )

    definition = event_definition(SecurityEventCode.PASSWORD_AUTH_SUCCEEDED)
    with pytest.raises(ValueError, match="derived fields"):
        SecurityEvent(
            id=uuid.uuid4(),
            occurred_at=datetime.now(timezone.utc),
            event_code=SecurityEventCode.PASSWORD_AUTH_SUCCEEDED,
            outcome=SecurityEventOutcome.FAILURE,
            severity=definition.severity,
            actor_type=SecurityActorType.USER,
            action=definition.action,
            request_id=REQUEST_ID,
            actor_user_id=USER_ID,
        )


def test_source_correlation_is_opaque_bounded_and_redacted() -> None:
    correlation = AuditSourceCorrelation(b"x" * 32, "audit-v1")
    assert "x" * 32 not in repr(correlation)
    with pytest.raises(ValueError):
        AuditSourceCorrelation(b"127.0.0.1", "audit-v1")
    with pytest.raises(ValueError):
        AuditSourceCorrelation(b"x" * 32, "invalid key id")
    with pytest.raises(TypeError, match="pre-derived"):
        SecurityEventDraft(
            SecurityEventCode.PASSWORD_AUTH_FAILED,
            SecurityActorType.ANONYMOUS,
            REQUEST_ID,
            reason_code=SecurityEventReason.CREDENTIALS_REJECTED,
            source="127.0.0.1",  # type: ignore[arg-type]
        )


def test_event_api_has_no_arbitrary_or_sensitive_data_surface() -> None:
    field_names = {item.name for item in fields(SecurityEventDraft)}
    assert field_names.isdisjoint(
        {
            "password",
            "password_hash",
            "totp_code",
            "totp_secret",
            "session_token",
            "challenge_token",
            "cookie",
            "request_body",
            "classified_content",
            "raw_metadata",
            "metadata",
            "headers",
            "exception",
        }
    )
    for forbidden in (
        "password",
        "totp_code",
        "session_token",
        "challenge_token",
        "cookie",
        "request_body",
        "classified_content",
        "raw_metadata",
    ):
        with pytest.raises(TypeError):
            SecurityEventDraft(
                event_code=SecurityEventCode.PASSWORD_AUTH_FAILED,
                actor_type=SecurityActorType.ANONYMOUS,
                request_id=REQUEST_ID,
                reason_code=SecurityEventReason.CREDENTIALS_REJECTED,
                **{forbidden: "synthetic-secret"},
            )
