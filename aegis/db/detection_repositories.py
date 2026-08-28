"""Read-only bounded audit-event input for deterministic detections."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.db.models import AuditEvent


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    id: uuid.UUID
    occurred_at: datetime
    event_code: str
    actor_user_id: uuid.UUID | None
    subject_user_id: uuid.UUID | None
    target_id: uuid.UUID | None


class DetectionEventQueryRepository:
    """Load only controlled detection inputs; expose no mutation or commit API."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_relevant_events(
        self,
        *,
        event_codes: frozenset[str],
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[DetectionEvent, ...]:
        if not event_codes or not 1 <= limit <= 5001:
            raise ValueError("detection query bounds are invalid")
        rows = self._session.execute(
            select(
                AuditEvent.id,
                AuditEvent.occurred_at,
                AuditEvent.event_code,
                AuditEvent.actor_user_id,
                AuditEvent.subject_user_id,
                AuditEvent.target_id,
            )
            .where(
                AuditEvent.occurred_at >= start,
                AuditEvent.occurred_at <= end,
                AuditEvent.event_code.in_(event_codes),
            )
            .order_by(AuditEvent.occurred_at.asc(), AuditEvent.id.asc())
            .limit(limit)
        )
        return tuple(DetectionEvent(*row) for row in rows)
