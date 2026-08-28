"""Centrally authorized, bounded, privacy-safe detection API tests."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
import pytest

from aegis.api.dependencies import (
    get_authorization_subject_service,
    get_current_principal,
    get_detection_service,
)
from aegis.main import create_app
from aegis.security.authorization import AuthorizationSubject, RoleName
from aegis.security.detections import (
    DetectionFinding,
    DetectionFindingCode,
    DetectionSeverity,
)
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.authorization import (
    AuthorizationSubjectLoadResult,
)


USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000001")
EVENT_ID = uuid.UUID("20000000-0000-4000-8000-000000000001")
NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)


def _principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(USER_ID, "ignored.client.value", "Ignored")


class Subjects:
    def __init__(
        self,
        roles: frozenset[RoleName],
        *,
        usable: bool = True,
        state_valid: bool = True,
    ) -> None:
        self.roles = roles
        self.usable = usable
        self.state_valid = state_valid
        self.principals = []

    def load(self, principal):
        self.principals.append(principal)
        return AuthorizationSubjectLoadResult.success(
            AuthorizationSubject(
                identity=principal,
                account_usable=self.usable,
                active_roles=self.roles,
                department_id=None,
                department_active=False,
                clearance_rank=None,
                active_compartment_ids=frozenset(),
                state_valid=self.state_valid,
            )
        )


class Detections:
    def __init__(self, findings=(), error: Exception | None = None) -> None:
        self.findings = findings
        self.error = error
        self.calls = []

    def detect(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.findings


def _finding(*, code=DetectionFindingCode.AUTHORIZATION_SYSTEM_ERROR, offset=0):
    instant = NOW + timedelta(seconds=offset)
    return DetectionFinding(
        finding_code=code,
        severity=DetectionSeverity.HIGH,
        window_start=instant,
        window_end=instant,
        subject_user_id=USER_ID,
        event_count=1,
        supporting_event_ids=(uuid.UUID(int=EVENT_ID.int + offset),),
    )


def _client(roles, detections, *, usable=True, state_valid=True):
    application = create_app()
    subjects = Subjects(roles, usable=usable, state_valid=state_valid)
    application.dependency_overrides[get_current_principal] = _principal
    application.dependency_overrides[get_authorization_subject_service] = lambda: subjects
    application.dependency_overrides[get_detection_service] = lambda: detections
    return TestClient(application), subjects


@pytest.mark.parametrize(
    ("roles", "usable", "state_valid", "expected"),
    [
        (frozenset({RoleName.SECURITY_AUDITOR}), True, True, 200),
        (frozenset({RoleName.SYSTEM_ADMINISTRATOR}), True, True, 403),
        (frozenset({RoleName.ANALYST}), True, True, 403),
        (frozenset({RoleName.SECURITY_AUDITOR}), False, True, 403),
        (frozenset({RoleName.SECURITY_AUDITOR}), True, False, 403),
        (frozenset(), True, True, 403),
    ],
)
def test_detection_api_uses_central_authorization(roles, usable, state_valid, expected):
    service = Detections()
    client, _ = _client(roles, service, usable=usable, state_valid=state_valid)
    with client:
        response = client.get(
            "/audit/detections",
            headers={"x-role": "Security Auditor", "x-clearance": "TOP SECRET"},
        )
    assert response.status_code == expected
    assert len(service.calls) == (1 if expected == 200 else 0)


def test_detection_api_requires_a_server_resolved_session():
    application = create_app()
    service = Detections()
    application.dependency_overrides[get_detection_service] = lambda: service
    with TestClient(application) as client:
        response = client.get(
            "/audit/detections",
            headers={"x-role": "Security Auditor", "authorization": "Bearer invented"},
        )
    assert response.status_code == 401
    assert service.calls == []


def test_detection_api_returns_stable_safe_projection_and_default_bound():
    service = Detections((_finding(offset=1), _finding(offset=0)))
    client, subjects = _client(frozenset({RoleName.SECURITY_AUDITOR}), service)
    with client:
        response = client.get("/audit/detections")
    assert response.status_code == 200
    assert [item["supporting_event_ids"][0] for item in response.json()["findings"]] == [
        str(uuid.UUID(int=EVENT_ID.int + 1)), str(EVENT_ID)
    ]
    assert service.calls[0]["lookback"] == timedelta(hours=24)
    assert subjects.principals == [_principal()]
    allowed = {
        "finding_code", "severity", "window_start", "window_end",
        "subject_user_id", "event_count", "supporting_event_ids",
    }
    assert set(response.json()["findings"][0]) == allowed
    forbidden = {
        "username", "ip", "user_agent", "source_correlation", "source_key_id",
        "token", "cookie", "password", "totp", "limiter_key", "role",
        "clearance", "department", "compartment", "record_code",
        "classified_content", "exception_trace",
    }
    assert forbidden.isdisjoint(response.text.lower())


def test_detection_api_empty_result_and_lookback_bounds():
    service = Detections()
    client, _ = _client(frozenset({RoleName.SECURITY_AUDITOR}), service)
    with client:
        maximum = client.get("/audit/detections?lookback_hours=24")
        excessive = client.get("/audit/detections?lookback_hours=25")
        zero = client.get("/audit/detections?lookback_hours=0")
    assert maximum.json() == {"findings": []}
    assert service.calls == [{"now": service.calls[0]["now"], "lookback": timedelta(hours=24)}]
    assert excessive.status_code == 422
    assert zero.status_code == 422


def test_detection_failure_is_generic_and_has_no_partial_projection():
    service = Detections(error=RuntimeError("database internals and secret material"))
    client, _ = _client(frozenset({RoleName.SECURITY_AUDITOR}), service)
    with client:
        response = client.get("/audit/detections")
    assert response.status_code == 503
    assert response.json() == {"detail": "Detection service unavailable"}
    assert "database internals" not in response.text


def test_query_has_no_enforcement_or_persistence_surface():
    service = Detections((_finding(),))
    before = vars(service).copy()
    client, _ = _client(frozenset({RoleName.SECURITY_AUDITOR}), service)
    with client:
        assert client.get("/audit/detections").status_code == 200
    assert service.findings == before["findings"]
    assert service.error == before["error"]
    assert not any(
        hasattr(service, name)
        for name in ("commit", "update", "delete", "revoke", "disable", "lock")
    )
