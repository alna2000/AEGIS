"""Bounded, centrally authorized, privacy-safe audit query tests."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session

from aegis.api.dependencies import (
    get_audit_query_service,
    get_authorization_subject_service,
    get_current_principal,
)
from aegis.db.audit_query_repositories import AuditEventQueryRepository
from aegis.db.models import AuditEvent
from aegis.main import create_app
from aegis.security.authorization import AuthorizationSubject, RoleName
from aegis.security.security_events import SecurityEventCode
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.audit_queries import AuditQueryService, InvalidAuditQuery
from aegis.services.authorization import AuthorizationSubjectLoadResult


NOW = datetime(2026, 8, 27, 18, 0, tzinfo=timezone.utc)
USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000001")


def _principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(USER_ID, "synthetic.auditor", "Synthetic Auditor")


class Subjects:
    def __init__(self, roles: frozenset[RoleName]) -> None:
        self.roles = roles

    def load(self, principal):
        return AuthorizationSubjectLoadResult.success(
            AuthorizationSubject(
                identity=principal,
                account_usable=True,
                active_roles=self.roles,
                department_id=None,
                department_active=False,
                clearance_rank=None,
                active_compartment_ids=frozenset(),
            )
        )


def _event(identifier: uuid.UUID, occurred_at: datetime) -> AuditEvent:
    return AuditEvent(
        id=identifier,
        occurred_at=occurred_at,
        event_code=SecurityEventCode.LOGOUT_SUCCEEDED.value,
        outcome="SUCCESS",
        severity="INFORMATIONAL",
        actor_type="SYSTEM",
        action="REVOKE_SESSION",
    )


def test_query_is_stably_descending_and_cursor_continues(db_session: Session) -> None:
    ids = [uuid.UUID(int=value) for value in (1, 2, 3)]
    for offset, identifier in enumerate(ids):
        db_session.add(_event(identifier, NOW - timedelta(minutes=offset)))
    db_session.flush()
    service = AuditQueryService(AuditEventQueryRepository(db_session))

    first = service.query(
        now=NOW,
        start=None,
        end=None,
        limit=2,
        cursor=None,
        event_code=None,
        outcome=None,
        severity=None,
        actor_user_id=None,
        target_type=None,
        target_id=None,
        request_id=None,
    )
    second = service.query(
        now=NOW,
        start=None,
        end=None,
        limit=2,
        cursor=first.next_cursor,
        event_code=None,
        outcome=None,
        severity=None,
        actor_user_id=None,
        target_type=None,
        target_id=None,
        request_id=None,
    )

    assert [event.id for event in first.events] == ids[:2]
    assert [event.id for event in second.events] == ids[2:]
    assert second.next_cursor is None


@pytest.mark.parametrize(
    "arguments",
    [
        {"start": NOW - timedelta(days=32), "end": NOW, "cursor": None},
        {"start": NOW, "end": NOW - timedelta(seconds=1), "cursor": None},
        {"start": None, "end": None, "cursor": "not-a-cursor"},
    ],
)
def test_query_rejects_unbounded_ranges_and_malformed_cursor(
    db_session: Session, arguments: dict
) -> None:
    service = AuditQueryService(AuditEventQueryRepository(db_session))
    with pytest.raises(InvalidAuditQuery):
        service.query(
            now=NOW,
            limit=50,
            event_code=None,
            outcome=None,
            severity=None,
            actor_user_id=None,
            target_type=None,
            target_id=None,
            request_id=None,
            **arguments,
        )


@pytest.mark.parametrize(
    ("roles", "expected"),
    [
        (frozenset({RoleName.SECURITY_AUDITOR}), 200),
        (frozenset({RoleName.SYSTEM_ADMINISTRATOR}), 403),
        (frozenset({RoleName.ANALYST}), 403),
        (frozenset(), 403),
    ],
)
def test_audit_api_uses_central_role_capability_and_safe_projection(
    db_session: Session, roles: frozenset[RoleName], expected: int
) -> None:
    db_session.add(_event(uuid.uuid4(), NOW))
    db_session.flush()
    application = create_app()
    application.dependency_overrides[get_current_principal] = _principal
    application.dependency_overrides[get_authorization_subject_service] = lambda: Subjects(roles)
    application.dependency_overrides[get_audit_query_service] = lambda: AuditQueryService(
        AuditEventQueryRepository(db_session)
    )

    with TestClient(application) as client:
        response = client.get("/audit/events", params={"end": NOW.isoformat()})

    assert response.status_code == expected
    if expected == 200:
        assert set(response.json()) == {"events", "next_cursor"}
        event = response.json()["events"][0]
        assert "source_correlation" not in event
        assert "source_key_id" not in event
        assert "username" not in event
        assert "metadata" not in event
        assert "classification" not in event


def test_audit_api_rejects_unbounded_or_uncontrolled_queries(db_session: Session) -> None:
    application = create_app()
    application.dependency_overrides[get_current_principal] = _principal
    application.dependency_overrides[get_authorization_subject_service] = lambda: Subjects(
        frozenset({RoleName.SECURITY_AUDITOR})
    )
    application.dependency_overrides[get_audit_query_service] = lambda: AuditQueryService(
        AuditEventQueryRepository(db_session)
    )
    with TestClient(application) as client:
        assert client.get("/audit/events?limit=101").status_code == 422
        assert client.get("/audit/events?event_code=UNCONTROLLED").status_code == 422
        assert client.get(
            "/audit/events", params={"target_id": str(uuid.uuid4())}
        ).status_code == 400
