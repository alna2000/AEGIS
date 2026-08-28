"""Validate bounded audit queries and produce privacy-reviewed projections."""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from aegis.db.audit_query_repositories import (
    AuditEventQueryRepository,
    AuditQueryFilters,
)
from aegis.db.models import AuditEvent
from aegis.security.security_events import (
    SecurityEventCode,
    SecurityEventOutcome,
    SecurityEventSeverity,
    SecurityTargetType,
)


MAX_AUDIT_QUERY_RANGE = timedelta(days=31)
DEFAULT_AUDIT_QUERY_RANGE = timedelta(hours=24)


class InvalidAuditQuery(ValueError):
    """A query or cursor fell outside the controlled read boundary."""


@dataclass(frozen=True, slots=True)
class AuditEventProjection:
    id: uuid.UUID
    occurred_at: datetime
    event_code: str
    outcome: str
    severity: str
    actor_type: str
    actor_user_id: uuid.UUID | None
    subject_user_id: uuid.UUID | None
    target_type: str | None
    target_id: uuid.UUID | None
    action: str
    reason_code: str | None
    request_id: uuid.UUID | None


@dataclass(frozen=True, slots=True)
class AuditQueryPage:
    events: tuple[AuditEventProjection, ...]
    next_cursor: str | None


class AuditQueryService:
    def __init__(self, repository: AuditEventQueryRepository) -> None:
        self._repository = repository

    def query(
        self,
        *,
        now: datetime,
        start: datetime | None,
        end: datetime | None,
        limit: int,
        cursor: str | None,
        event_code: SecurityEventCode | None,
        outcome: SecurityEventOutcome | None,
        severity: SecurityEventSeverity | None,
        actor_user_id: uuid.UUID | None,
        target_type: SecurityTargetType | None,
        target_id: uuid.UUID | None,
        request_id: uuid.UUID | None,
    ) -> AuditQueryPage:
        now = _utc(now)
        selected_end = _utc(end) if end is not None else now
        selected_start = _utc(start) if start is not None else selected_end - DEFAULT_AUDIT_QUERY_RANGE
        if selected_start > selected_end or selected_end - selected_start > MAX_AUDIT_QUERY_RANGE:
            raise InvalidAuditQuery("audit time range is invalid")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise InvalidAuditQuery("audit page size is invalid")
        if target_id is not None and target_type is None:
            raise InvalidAuditQuery("audit target ID requires a controlled target type")
        cursor_time, cursor_id = _decode_cursor(cursor) if cursor else (None, None)
        rows = self._repository.list_events(
            AuditQueryFilters(
                start=selected_start,
                end=selected_end,
                limit=limit,
                event_code=event_code.value if event_code else None,
                outcome=outcome.value if outcome else None,
                severity=severity.value if severity else None,
                actor_user_id=actor_user_id,
                target_type=target_type.value if target_type else None,
                target_id=target_id,
                request_id=request_id,
                cursor_time=cursor_time,
                cursor_id=cursor_id,
            )
        )
        page_rows = rows[:limit]
        next_cursor = _encode_cursor(page_rows[-1]) if len(rows) > limit else None
        return AuditQueryPage(tuple(_project(row) for row in page_rows), next_cursor)


def _project(row: AuditEvent) -> AuditEventProjection:
    return AuditEventProjection(
        id=row.id,
        occurred_at=row.occurred_at,
        event_code=row.event_code,
        outcome=row.outcome,
        severity=row.severity,
        actor_type=row.actor_type,
        actor_user_id=row.actor_user_id,
        subject_user_id=row.subject_user_id,
        target_type=row.target_type,
        target_id=row.target_id,
        action=row.action,
        reason_code=row.reason_code,
        request_id=row.request_id,
    )


def _encode_cursor(row: AuditEvent) -> str:
    payload = json.dumps(
        [row.occurred_at.astimezone(timezone.utc).isoformat(), str(row.id)],
        separators=(",", ":"),
    ).encode("ascii")
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _decode_cursor(value: str) -> tuple[datetime, uuid.UUID]:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise InvalidAuditQuery("audit cursor is invalid")
    try:
        padded = value + "=" * (-len(value) % 4)
        data = json.loads(base64.b64decode(padded, altchars=b"-_", validate=True))
        if not isinstance(data, list) or len(data) != 2:
            raise ValueError
        return _utc(datetime.fromisoformat(data[0])), uuid.UUID(data[1])
    except (ValueError, TypeError, json.JSONDecodeError):
        raise InvalidAuditQuery("audit cursor is invalid") from None


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise InvalidAuditQuery("audit timestamps must include a timezone")
    return value.astimezone(timezone.utc)
