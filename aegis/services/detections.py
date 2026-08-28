"""Deterministic, bounded detection over existing durable audit evidence."""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from aegis.db.detection_repositories import DetectionEvent, DetectionEventQueryRepository
from aegis.security.detections import (
    DetectionFinding,
    DetectionFindingCode,
    DetectionSeverity,
)
from aegis.security.security_events import SecurityEventCode


MAX_DETECTION_LOOKBACK = timedelta(hours=24)
MAX_DETECTION_SOURCE_ROWS = 5000
MAX_DETECTION_FINDINGS = 500
MAX_SUPPORTING_EVENT_IDS = 25


class DetectionSourceLimitExceeded(RuntimeError):
    """The bounded source query cannot produce a complete detection result."""


@dataclass(frozen=True, slots=True)
class _Rule:
    finding_code: DetectionFindingCode
    event_codes: frozenset[SecurityEventCode]
    threshold: int
    window: timedelta
    severity: DetectionSeverity
    grouping: str


_RULES = (
    _Rule(DetectionFindingCode.REPEATED_PASSWORD_FAILURE, frozenset({SecurityEventCode.PASSWORD_AUTH_FAILED}), 5, timedelta(minutes=10), DetectionSeverity.MEDIUM, "subject"),
    _Rule(DetectionFindingCode.MFA_FAILURE_PATTERN, frozenset({SecurityEventCode.MFA_FACTOR_FAILED}), 3, timedelta(minutes=5), DetectionSeverity.MEDIUM, "actor"),
    _Rule(DetectionFindingCode.MFA_CHALLENGE_EXHAUSTION, frozenset({SecurityEventCode.MFA_CHALLENGE_EXHAUSTED}), 1, timedelta(0), DetectionSeverity.HIGH, "occurrence"),
    _Rule(DetectionFindingCode.AUTHORIZATION_DENIAL_SPIKE, frozenset({SecurityEventCode.AUTHORIZATION_DENIED}), 25, timedelta(minutes=5), DetectionSeverity.LOW, "actor"),
    _Rule(DetectionFindingCode.AUTHORIZATION_SYSTEM_ERROR, frozenset({SecurityEventCode.AUTHORIZATION_ERROR}), 1, timedelta(0), DetectionSeverity.HIGH, "occurrence"),
    _Rule(DetectionFindingCode.RESOURCE_ACCESS_PROBING, frozenset({SecurityEventCode.RESOURCE_READ_INACCESSIBLE}), 10, timedelta(minutes=10), DetectionSeverity.MEDIUM, "actor"),
    _Rule(DetectionFindingCode.ABUSE_PRESSURE, frozenset({SecurityEventCode.ABUSE_ADMISSION_DENIED, SecurityEventCode.CONCURRENCY_SATURATED}), 5, timedelta(minutes=5), DetectionSeverity.MEDIUM, "actor-or-global"),
    _Rule(DetectionFindingCode.ABUSE_STORE_FAILURE, frozenset({SecurityEventCode.ABUSE_STORE_UNAVAILABLE}), 1, timedelta(0), DetectionSeverity.HIGH, "occurrence"),
    _Rule(DetectionFindingCode.AUDIT_SYSTEM_FAILURE, frozenset({SecurityEventCode.AUDIT_PERSISTENCE_FAILED}), 1, timedelta(0), DetectionSeverity.HIGH, "occurrence"),
)

DETECTION_FALSE_POSITIVE_NOTES = {
    DetectionFindingCode.REPEATED_PASSWORD_FAILURE: "Legitimate user entering an incorrect password repeatedly.",
    DetectionFindingCode.MFA_FAILURE_PATTERN: "Legitimate authenticator mistakes or clock confusion.",
    DetectionFindingCode.MFA_CHALLENGE_EXHAUSTION: "A legitimate user exhausted a short-lived challenge.",
    DetectionFindingCode.AUTHORIZATION_DENIAL_SPIKE: "Repeated navigation or stale access expectations; not proof of malicious activity.",
    DetectionFindingCode.AUTHORIZATION_SYSTEM_ERROR: "Transient infrastructure or invalid server-side policy state.",
    DetectionFindingCode.RESOURCE_ACCESS_PROBING: "Repeated stale or mistyped record references.",
    DetectionFindingCode.ABUSE_PRESSURE: "A burst of legitimate demand can saturate local controls.",
    DetectionFindingCode.ABUSE_STORE_FAILURE: "Local capacity or transient abuse-store unavailability.",
    DetectionFindingCode.AUDIT_SYSTEM_FAILURE: "A durable event can exist only when its persistence path remained available.",
}


class DetectionService:
    def __init__(self, repository: DetectionEventQueryRepository) -> None:
        self._repository = repository

    def detect(
        self,
        *,
        now: datetime,
        lookback: timedelta = MAX_DETECTION_LOOKBACK,
    ) -> tuple[DetectionFinding, ...]:
        now = _utc(now)
        if not isinstance(lookback, timedelta) or not timedelta(0) < lookback <= MAX_DETECTION_LOOKBACK:
            raise ValueError("detection lookback is outside the safe bound")
        codes = frozenset(code.value for rule in _RULES for code in rule.event_codes)
        events = self._repository.list_relevant_events(
            event_codes=codes,
            start=now - lookback,
            end=now,
            limit=MAX_DETECTION_SOURCE_ROWS + 1,
        )
        if len(events) > MAX_DETECTION_SOURCE_ROWS:
            raise DetectionSourceLimitExceeded("detection source row bound exceeded")
        findings = [finding for rule in _RULES for finding in _evaluate(rule, events)]
        findings.sort(
            key=lambda finding: (
                -_severity_rank(finding.severity),
                -finding.window_end.timestamp(),
                finding.finding_code.value,
                str(finding.subject_user_id or ""),
            )
        )
        return tuple(findings[:MAX_DETECTION_FINDINGS])


def _evaluate(rule: _Rule, events: tuple[DetectionEvent, ...]) -> tuple[DetectionFinding, ...]:
    selected = tuple(event for event in events if event.event_code in {code.value for code in rule.event_codes})
    if rule.grouping == "occurrence":
        return tuple(_occurrence(rule, event) for event in selected)
    grouped: dict[uuid.UUID | None, list[DetectionEvent]] = defaultdict(list)
    for event in selected:
        key = event.subject_user_id if rule.grouping == "subject" else event.actor_user_id
        if key is None and rule.grouping != "actor-or-global":
            continue
        grouped[key].append(event)
    findings = []
    for key, group in grouped.items():
        finding = _latest_threshold_window(rule, key, group)
        if finding is not None:
            findings.append(finding)
    return tuple(findings)


def _latest_threshold_window(
    rule: _Rule,
    subject_user_id: uuid.UUID | None,
    events: list[DetectionEvent],
) -> DetectionFinding | None:
    left = 0
    selected: tuple[DetectionEvent, ...] | None = None
    for right, event in enumerate(events):
        while event.occurred_at - events[left].occurred_at > rule.window:
            left += 1
        window = tuple(events[left : right + 1])
        if len(window) >= rule.threshold:
            selected = window
    if selected is None:
        return None
    return DetectionFinding(
        finding_code=rule.finding_code,
        severity=rule.severity,
        window_start=selected[0].occurred_at,
        window_end=selected[-1].occurred_at,
        subject_user_id=subject_user_id,
        event_count=len(selected),
        supporting_event_ids=tuple(event.id for event in selected[-MAX_SUPPORTING_EVENT_IDS:]),
    )


def _occurrence(rule: _Rule, event: DetectionEvent) -> DetectionFinding:
    return DetectionFinding(
        finding_code=rule.finding_code,
        severity=rule.severity,
        window_start=event.occurred_at,
        window_end=event.occurred_at,
        subject_user_id=event.actor_user_id or event.subject_user_id,
        event_count=1,
        supporting_event_ids=(event.id,),
    )


def _severity_rank(severity: DetectionSeverity) -> int:
    return {DetectionSeverity.LOW: 1, DetectionSeverity.MEDIUM: 2, DetectionSeverity.HIGH: 3}[severity]


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("detection clock must be timezone-aware")
    return value.astimezone(timezone.utc)
