"""Append-only persistence boundary for durable security audit events."""

from sqlalchemy.orm import Session

from aegis.db.models import AuditEvent
from aegis.security.security_events import SecurityEvent


class AuditEventWriterRepository:
    """Stage new evidence without exposing update, delete, or commit operations."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add_event(self, event: SecurityEvent) -> AuditEvent:
        """Construct and flush one row inside the caller-owned transaction."""

        if not isinstance(event, SecurityEvent):
            raise TypeError("audit writer requires a typed security event")
        source = event.source
        model = AuditEvent(
            id=event.id,
            occurred_at=event.occurred_at,
            event_code=event.event_code.value,
            outcome=event.outcome.value,
            severity=event.severity.value,
            actor_type=event.actor_type.value,
            actor_user_id=event.actor_user_id,
            subject_user_id=event.subject_user_id,
            target_type=(event.target_type.value if event.target_type else None),
            target_id=event.target_id,
            action=event.action.value,
            reason_code=(event.reason_code.value if event.reason_code else None),
            request_id=event.request_id,
            source_correlation=(source.digest if source else None),
            source_key_id=(source.key_id if source else None),
        )
        self._session.add(model)
        self._session.flush()
        return model
