"""Bounded read-only persistence boundary for security audit events."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Select, and_, or_, select
from sqlalchemy.orm import Session

from aegis.db.models import AuditEvent


@dataclass(frozen=True, slots=True)
class AuditQueryFilters:
    start: datetime
    end: datetime
    limit: int
    event_code: str | None = None
    outcome: str | None = None
    severity: str | None = None
    actor_user_id: uuid.UUID | None = None
    target_type: str | None = None
    target_id: uuid.UUID | None = None
    request_id: uuid.UUID | None = None
    cursor_time: datetime | None = None
    cursor_id: uuid.UUID | None = None


class AuditEventQueryRepository:
    """Expose one bounded query and no mutation operations."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_events(self, filters: AuditQueryFilters) -> tuple[AuditEvent, ...]:
        if not isinstance(filters, AuditQueryFilters) or not 1 <= filters.limit <= 100:
            raise ValueError("audit query requires controlled bounds")
        statement: Select[tuple[AuditEvent]] = select(AuditEvent).where(
            AuditEvent.occurred_at >= filters.start,
            AuditEvent.occurred_at <= filters.end,
        )
        for column, value in (
            (AuditEvent.event_code, filters.event_code),
            (AuditEvent.outcome, filters.outcome),
            (AuditEvent.severity, filters.severity),
            (AuditEvent.actor_user_id, filters.actor_user_id),
            (AuditEvent.target_type, filters.target_type),
            (AuditEvent.target_id, filters.target_id),
            (AuditEvent.request_id, filters.request_id),
        ):
            if value is not None:
                statement = statement.where(column == value)
        if filters.cursor_time is not None and filters.cursor_id is not None:
            statement = statement.where(
                or_(
                    AuditEvent.occurred_at < filters.cursor_time,
                    and_(
                        AuditEvent.occurred_at == filters.cursor_time,
                        AuditEvent.id < filters.cursor_id,
                    ),
                )
            )
        statement = statement.order_by(
            AuditEvent.occurred_at.desc(), AuditEvent.id.desc()
        ).limit(filters.limit + 1)
        return tuple(self._session.scalars(statement))
