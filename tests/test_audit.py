"""Persistent append-only audit repository and service tests."""

from datetime import datetime, timezone
from unittest.mock import Mock
import uuid

import pytest
from sqlalchemy import create_engine, event as sqlalchemy_event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aegis.db.audit_repositories import AuditEventWriterRepository
from aegis.db.base import Base
from aegis.db.models import AuditEvent
from aegis.security.security_events import (
    SecurityActorType,
    SecurityEventCode,
    SecurityEventDraft,
    SecurityEventReason,
)
from aegis.services.audit import AuditService


EVENT_ID = uuid.UUID("01234567-89ab-cdef-0123-456789abcdef")
REQUEST_ID = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


def failed_password_draft() -> SecurityEventDraft:
    return SecurityEventDraft(
        event_code=SecurityEventCode.PASSWORD_AUTH_FAILED,
        actor_type=SecurityActorType.ANONYMOUS,
        request_id=REQUEST_ID,
        reason_code=SecurityEventReason.CREDENTIALS_REJECTED,
    )


def test_service_generates_deterministic_identity_time_and_stages_without_commit(
    db_session: Session,
) -> None:
    service = AuditService(
        AuditEventWriterRepository(db_session),
        id_generator=lambda: EVENT_ID,
        clock=lambda: NOW,
    )
    row = service.stage(failed_password_draft())

    assert row.id == EVENT_ID
    assert row.occurred_at == NOW
    assert row.event_code == "PASSWORD_AUTH_FAILED"
    assert row.outcome == "FAILURE"
    assert row.severity == "LOW"
    assert row.actor_type == "ANONYMOUS"
    assert row.reason_code == "CREDENTIALS_REJECTED"
    assert db_session.in_transaction()
    assert db_session.scalar(select(func.count()).select_from(AuditEvent)) == 1

    db_session.rollback()
    assert db_session.scalar(select(func.count()).select_from(AuditEvent)) == 0


def test_repository_only_adds_and_flushes_typed_events() -> None:
    session = Mock(spec=["add", "flush"])
    writer = AuditEventWriterRepository(session)  # type: ignore[arg-type]
    definition_draft = failed_password_draft()
    service = AuditService(
        writer,
        id_generator=lambda: EVENT_ID,
        clock=lambda: NOW,
    )

    service.stage(definition_draft)
    session.add.assert_called_once()
    session.flush.assert_called_once_with()
    assert not hasattr(writer, "commit")
    assert not hasattr(writer, "update")
    assert not hasattr(writer, "delete")
    assert not hasattr(service, "commit")


def test_flush_failure_surfaces_and_caller_rollback_removes_whole_transaction(
    db_session: Session,
) -> None:
    service = AuditService(
        AuditEventWriterRepository(db_session),
        id_generator=lambda: EVENT_ID,
        clock=lambda: NOW,
    )
    service.stage(failed_password_draft())
    with pytest.raises(IntegrityError):
        service.stage(failed_password_draft())
    db_session.rollback()
    assert db_session.scalar(select(func.count()).select_from(AuditEvent)) == 0


def test_database_constraints_reject_uncontrolled_persistent_values() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(
            AuditEvent(
                id=EVENT_ID,
                occurred_at=NOW,
                event_code="UNCONTROLLED_EVENT",
                outcome="FAILURE",
                severity="LOW",
                actor_type="ANONYMOUS",
                actor_user_id=None,
                subject_user_id=None,
                target_type=None,
                target_id=None,
                action="AUTHENTICATE",
                reason_code="CREDENTIALS_REJECTED",
                request_id=REQUEST_ID,
                source_correlation=None,
                source_key_id=None,
            )
        )
        with pytest.raises(IntegrityError):
            session.flush()
    Base.metadata.drop_all(engine)
    engine.dispose()


def test_database_restricts_unknown_actor_user_reference() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")

    @sqlalchemy_event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(
            AuditEvent(
                id=EVENT_ID,
                occurred_at=NOW,
                event_code="SESSION_ESTABLISHED",
                outcome="SUCCESS",
                severity="INFORMATIONAL",
                actor_type="USER",
                actor_user_id=uuid.uuid4(),
                subject_user_id=None,
                target_type="SESSION",
                target_id=uuid.uuid4(),
                action="ESTABLISH_SESSION",
                reason_code=None,
                request_id=REQUEST_ID,
                source_correlation=None,
                source_key_id=None,
            )
        )
        with pytest.raises(IntegrityError):
            session.flush()
    Base.metadata.drop_all(engine)
    engine.dispose()


def test_audit_model_has_no_mutable_lifecycle_or_secret_columns() -> None:
    columns = set(AuditEvent.__table__.columns.keys())
    assert columns.isdisjoint(
        {
            "updated_at",
            "deleted_at",
            "password",
            "totp_code",
            "session_token",
            "challenge_token",
            "request_body",
            "classified_content",
            "metadata",
        }
    )


@pytest.mark.parametrize(
    ("id_value", "clock_value", "error"),
    [
        ("not-a-uuid", NOW, TypeError),
        (EVENT_ID, datetime(2026, 8, 27, 12, 0), ValueError),
    ],
)
def test_service_rejects_invalid_generated_identity_or_time(
    db_session: Session,
    id_value: object,
    clock_value: datetime,
    error: type[Exception],
) -> None:
    service = AuditService(
        AuditEventWriterRepository(db_session),
        id_generator=lambda: id_value,  # type: ignore[arg-type,return-value]
        clock=lambda: clock_value,
    )
    with pytest.raises(error):
        service.stage(failed_password_draft())
