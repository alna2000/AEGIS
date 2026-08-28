"""Deterministic bounded detection-engine tests."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from aegis.db.detection_repositories import DetectionEvent, DetectionEventQueryRepository
from aegis.db.models import AuditEvent
from aegis.security.detections import DetectionFindingCode, DetectionSeverity
from aegis.security.security_events import SecurityEventCode
from aegis.services.detections import (
    MAX_DETECTION_SOURCE_ROWS,
    DetectionService,
    DetectionSourceLimitExceeded,
)


NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
ACTOR_A = uuid.UUID("10000000-0000-4000-8000-000000000001")
ACTOR_B = uuid.UUID("10000000-0000-4000-8000-000000000002")


class Repository:
    def __init__(self, events: tuple[DetectionEvent, ...]) -> None:
        self.events = events
        self.calls = []

    def list_relevant_events(self, **kwargs):
        self.calls.append(kwargs)
        return self.events[: kwargs["limit"]]


def event(
    code: SecurityEventCode,
    offset: timedelta,
    *,
    actor: uuid.UUID | None = ACTOR_A,
    subject: uuid.UUID | None = None,
    identifier: int | None = None,
) -> DetectionEvent:
    return DetectionEvent(
        id=uuid.UUID(int=identifier or int(offset.total_seconds()) + 10000),
        occurred_at=NOW + offset,
        event_code=code.value,
        actor_user_id=actor,
        subject_user_id=subject,
        target_id=None,
    )


@pytest.mark.parametrize(
    ("code", "threshold", "minutes", "finding", "severity", "group_field"),
    [
        (SecurityEventCode.PASSWORD_AUTH_FAILED, 5, 10, DetectionFindingCode.REPEATED_PASSWORD_FAILURE, DetectionSeverity.MEDIUM, "subject"),
        (SecurityEventCode.MFA_FACTOR_FAILED, 3, 5, DetectionFindingCode.MFA_FAILURE_PATTERN, DetectionSeverity.MEDIUM, "actor"),
        (SecurityEventCode.AUTHORIZATION_DENIED, 25, 5, DetectionFindingCode.AUTHORIZATION_DENIAL_SPIKE, DetectionSeverity.LOW, "actor"),
        (SecurityEventCode.RESOURCE_READ_INACCESSIBLE, 10, 10, DetectionFindingCode.RESOURCE_ACCESS_PROBING, DetectionSeverity.MEDIUM, "actor"),
        (SecurityEventCode.ABUSE_ADMISSION_DENIED, 5, 5, DetectionFindingCode.ABUSE_PRESSURE, DetectionSeverity.MEDIUM, "actor"),
    ],
)
def test_threshold_detectors_are_exact_and_window_bounded(
    code, threshold, minutes, finding, severity, group_field
) -> None:
    identity = {"subject": ACTOR_A} if group_field == "subject" else {"actor": ACTOR_A}
    exact = tuple(
        event(
            code,
            timedelta(seconds=index - threshold + 1),
            identifier=index + 1,
            **identity,
        )
        for index in range(threshold)
    )
    assert DetectionService(Repository(exact[:-1])).detect(now=NOW) == ()
    result = DetectionService(Repository(exact)).detect(now=NOW)
    assert len(result) == 1
    assert result[0].finding_code is finding
    assert result[0].severity is severity
    assert result[0].event_count == threshold

    outside = exact[1:] + (
        event(
            code,
            timedelta(minutes=minutes, microseconds=1),
            identifier=threshold + 10,
            **identity,
        ),
    )
    assert DetectionService(Repository(outside)).detect(
        now=NOW + timedelta(minutes=minutes, microseconds=1)
    ) == ()


@pytest.mark.parametrize(
    ("code", "finding"),
    [
        (SecurityEventCode.MFA_CHALLENGE_EXHAUSTED, DetectionFindingCode.MFA_CHALLENGE_EXHAUSTION),
        (SecurityEventCode.AUTHORIZATION_ERROR, DetectionFindingCode.AUTHORIZATION_SYSTEM_ERROR),
        (SecurityEventCode.ABUSE_STORE_UNAVAILABLE, DetectionFindingCode.ABUSE_STORE_FAILURE),
        (SecurityEventCode.AUDIT_PERSISTENCE_FAILED, DetectionFindingCode.AUDIT_SYSTEM_FAILURE),
    ],
)
def test_single_occurrence_detectors(code, finding) -> None:
    result = DetectionService(Repository((event(code, timedelta(0), identifier=1),))).detect(now=NOW)
    assert len(result) == 1
    assert result[0].finding_code is finding
    assert result[0].severity is DetectionSeverity.HIGH


def test_unrelated_separate_and_anonymous_identity_events_do_not_combine() -> None:
    events = tuple(
        event(SecurityEventCode.PASSWORD_AUTH_FAILED, timedelta(seconds=index), actor=None, subject=None, identifier=index + 1)
        for index in range(10)
    ) + tuple(
        event(SecurityEventCode.AUTHORIZATION_DENIED, timedelta(seconds=index), actor=ACTOR_A if index % 2 else ACTOR_B, identifier=100 + index)
        for index in range(25)
    ) + (event(SecurityEventCode.LOGOUT_SUCCEEDED, timedelta(0), identifier=999),)
    assert DetectionService(Repository(events)).detect(now=NOW) == ()


def test_abuse_pressure_can_be_actorless_without_inventing_identity() -> None:
    events = tuple(
        event(SecurityEventCode.CONCURRENCY_SATURATED, timedelta(seconds=index), actor=None, identifier=index + 1)
        for index in range(5)
    )
    finding = DetectionService(Repository(events)).detect(now=NOW)[0]
    assert finding.finding_code is DetectionFindingCode.ABUSE_PRESSURE
    assert finding.subject_user_id is None


def test_supporting_ids_source_rows_lookback_and_output_are_bounded() -> None:
    events = tuple(
        event(SecurityEventCode.AUTHORIZATION_DENIED, timedelta(seconds=index), identifier=index + 1)
        for index in range(30)
    )
    repository = Repository(events)
    finding = DetectionService(repository).detect(now=NOW + timedelta(seconds=30))[0]
    assert finding.event_count == 30
    assert len(finding.supporting_event_ids) == 25
    assert repository.calls[0]["limit"] == MAX_DETECTION_SOURCE_ROWS + 1
    assert repository.calls[0]["end"] - repository.calls[0]["start"] == timedelta(hours=24)
    assert set(finding.__slots__) == {
        "finding_code", "severity", "window_start", "window_end",
        "subject_user_id", "event_count", "supporting_event_ids",
    }


def test_source_overflow_and_excessive_lookback_fail_closed() -> None:
    repeated = tuple(
        event(SecurityEventCode.AUTHORIZATION_ERROR, timedelta(0), identifier=index + 1)
        for index in range(MAX_DETECTION_SOURCE_ROWS + 1)
    )
    with pytest.raises(DetectionSourceLimitExceeded):
        DetectionService(Repository(repeated)).detect(now=NOW)
    with pytest.raises(ValueError):
        DetectionService(Repository(())).detect(now=NOW, lookback=timedelta(hours=25))


def test_finding_order_is_deterministic_and_service_has_no_enforcement_surface() -> None:
    events = (
        event(SecurityEventCode.AUTHORIZATION_DENIED, timedelta(0), identifier=1),
        event(SecurityEventCode.AUTHORIZATION_ERROR, timedelta(0), identifier=2),
        event(SecurityEventCode.ABUSE_STORE_UNAVAILABLE, timedelta(seconds=-1), identifier=3),
    )
    service = DetectionService(Repository(events))
    findings = service.detect(now=NOW)
    assert [finding.finding_code for finding in findings] == [
        DetectionFindingCode.AUTHORIZATION_SYSTEM_ERROR,
        DetectionFindingCode.ABUSE_STORE_FAILURE,
    ]
    assert not any(hasattr(service, name) for name in ("commit", "update", "delete", "revoke", "disable"))


def test_detection_repository_reads_only_relevant_bounded_ordered_fields(
    db_session: Session,
) -> None:
    later = AuditEvent(
        id=uuid.UUID(int=2), occurred_at=NOW,
        event_code="AUTHORIZATION_ERROR", outcome="ERROR", severity="HIGH",
        actor_type="SYSTEM", action="AUTHORIZE", reason_code="DATABASE_ERROR",
    )
    earlier = AuditEvent(
        id=uuid.UUID(int=1), occurred_at=NOW - timedelta(seconds=1),
        event_code="AUTHORIZATION_ERROR", outcome="ERROR", severity="HIGH",
        actor_type="SYSTEM", action="AUTHORIZE", reason_code="DATABASE_ERROR",
    )
    unrelated = AuditEvent(
        id=uuid.UUID(int=3), occurred_at=NOW,
        event_code="LOGOUT_SUCCEEDED", outcome="SUCCESS", severity="INFORMATIONAL",
        actor_type="SYSTEM", action="REVOKE_SESSION",
    )
    db_session.add_all((later, earlier, unrelated))
    db_session.flush()

    rows = DetectionEventQueryRepository(db_session).list_relevant_events(
        event_codes=frozenset({"AUTHORIZATION_ERROR"}),
        start=NOW - timedelta(hours=1),
        end=NOW,
        limit=2,
    )

    assert [row.id for row in rows] == [earlier.id, later.id]
    assert set(rows[0].__slots__) == {
        "id", "occurred_at", "event_code", "actor_user_id",
        "subject_user_id", "target_id",
    }
