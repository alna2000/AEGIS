"""Generate and stage immutable security events in caller-owned transactions."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timezone

from aegis.db.audit_repositories import AuditEventWriterRepository
from aegis.db.models import AuditEvent
from aegis.security.security_events import (
    SecurityEvent,
    SecurityEventDraft,
    event_definition,
)


class AuditService:
    """Build controlled events and delegate append-only persistence."""

    def __init__(
        self,
        writer: AuditEventWriterRepository,
        *,
        id_generator: Callable[[], uuid.UUID] = uuid.uuid4,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._writer = writer
        self._id_generator = id_generator
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def stage(self, draft: SecurityEventDraft) -> AuditEvent:
        """Flush a new event without committing the caller's transaction."""

        if not isinstance(draft, SecurityEventDraft):
            raise TypeError("audit service requires a typed event draft")
        event_id = self._id_generator()
        if not isinstance(event_id, uuid.UUID):
            raise TypeError("audit event ID generator must return a UUID")
        occurred_at = self._clock()
        if not isinstance(occurred_at, datetime) or occurred_at.tzinfo is None:
            raise ValueError("audit clock must return a timezone-aware datetime")
        definition = event_definition(draft.event_code)
        event = SecurityEvent(
            id=event_id,
            occurred_at=occurred_at,
            event_code=draft.event_code,
            outcome=definition.outcome,
            severity=definition.severity,
            actor_type=draft.actor_type,
            action=definition.action,
            request_id=draft.request_id,
            actor_user_id=draft.actor_user_id,
            subject_user_id=draft.subject_user_id,
            target_type=draft.target_type,
            target_id=draft.target_id,
            reason_code=draft.reason_code,
            source=draft.source,
        )
        return self._writer.add_event(event)
