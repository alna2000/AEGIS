"""Deterministic integration tests for Part 4 availability protection."""

from __future__ import annotations

from dataclasses import replace
import uuid

from fastapi.testclient import TestClient
import pytest

from aegis.api.dependencies import (
    get_audit_service,
    get_db_session,
    get_intelligence_record_collection_read_service,
    get_intelligence_record_read_service,
    get_mfa_challenge_service,
    get_session_service,
)
from aegis.core.config import Settings, get_settings
from aegis.main import create_app
from aegis.security.abuse import (
    AbuseControlEngine,
    AbuseDecisionStatus,
    AbuseStoreUnavailable,
    ConcurrencyPolicy,
    CorrelationKeyDeriver,
    CounterPolicy,
    InMemoryAbuseStateStore,
)
from aegis.security.authentication_events import AuthenticationRequestContext
from aegis.security.availability_abuse import (
    AvailabilityAbuseControl,
    AvailabilityAbusePolicy,
)
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.intelligence_records import (
    AuthorizedIntelligenceRecord,
    IntelligenceRecordCollectionReadOutcome,
    IntelligenceRecordCollectionReadResult,
    IntelligenceRecordReadResult,
)
from aegis.services.sessions import ResolvedSession, generate_session_token
from aegis.services.sessions import RevokedSession


LIMIT_BODY = {"detail": "Request temporarily unavailable"}
RECORD_LIMIT_BODY = {"detail": "Record request temporarily unavailable"}


class Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class UnavailableStore:
    def admit(self, _rules):
        raise AbuseStoreUnavailable("synthetic unavailable store")

    def check_cooldowns(self, _scopes):
        raise AbuseStoreUnavailable("synthetic unavailable store")

    def activate_cooldown(self, _scope, _delay):
        raise AbuseStoreUnavailable("synthetic unavailable store")

    def acquire_lease(self, _scope, _policy):
        raise AbuseStoreUnavailable("synthetic unavailable store")

    def release_lease(self, _scope, _token):
        raise AbuseStoreUnavailable("synthetic unavailable store")


class ProgrammingErrorStore(UnavailableStore):
    def admit(self, _rules):
        raise RuntimeError("synthetic programming error")


class InvalidResultStore(UnavailableStore):
    def admit(self, _rules):
        return object()


class Sessions:
    def __init__(self, resolved_by_token: dict[str, ResolvedSession]) -> None:
        self.resolved_by_token = resolved_by_token
        self.resolve_calls = 0
        self.revoked: list[str | None] = []

    def resolve_session(self, raw_token: str | None):
        self.resolve_calls += 1
        return self.resolved_by_token.get(raw_token or "")

    def revoke_session(self, raw_token: str | None) -> bool:
        self.revoked.append(raw_token)
        return raw_token in self.resolved_by_token

    def revoke_session_with_identity(self, raw_token: str | None):
        self.revoked.append(raw_token)
        resolved = self.resolved_by_token.get(raw_token or "")
        if resolved is None:
            return None
        return RevokedSession(resolved.session_id, resolved.principal.user_id)


class DatabaseTransaction:
    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


class Challenges:
    def revoke(self, _raw_token: str | None) -> bool:
        return False


class Audit:
    def stage(self, _draft):
        return None


class CollectionService:
    def __init__(self) -> None:
        self.calls = 0

    def read(self, _principal):
        self.calls += 1
        return IntelligenceRecordCollectionReadResult(
            IntelligenceRecordCollectionReadOutcome.AUTHORIZED, ()
        )


class UnexpectedRecordService:
    def read(self, *_args):
        raise AssertionError("limited request reached record service")


class ResultService:
    def __init__(self, result=None, *, raises: bool = False) -> None:
        self.result = result
        self.raises = raises

    def read(self, *_args):
        if self.raises:
            raise RuntimeError("synthetic record service failure")
        return self.result


def make_settings() -> Settings:
    return Settings(
        environment="test",
        database_url="sqlite+pysqlite:///:memory:",
        session_cookie_secure=False,
        _env_file=None,
    )


def resolved_session() -> ResolvedSession:
    return ResolvedSession(
        session_id=uuid.uuid4(),
        principal=AuthenticatedPrincipal(
            user_id=uuid.uuid4(),
            username="synthetic.operator",
            display_name="Synthetic Operator",
        ),
    )


def control(
    *, policy: AvailabilityAbusePolicy | None = None, maximum_entries: int = 128
) -> tuple[AvailabilityAbuseControl, InMemoryAbuseStateStore]:
    clock = Clock()
    store = InMemoryAbuseStateStore(
        maximum_entries=maximum_entries, reserved_entries=2, clock=clock
    )
    return (
        AvailabilityAbuseControl(
            AbuseControlEngine(store),
            CorrelationKeyDeriver(b"synthetic-part4-test-secret-32-bytes!!"),
            policy=policy,
        ),
        store,
    )


def application_with(
    availability: AvailabilityAbuseControl,
    sessions: Sessions | None = None,
):
    application = create_app()
    configured = make_settings()
    application.state.availability_abuse_control = availability
    application.dependency_overrides[get_settings] = lambda: configured
    application.dependency_overrides[get_audit_service] = lambda: Audit()
    if sessions is not None:
        application.dependency_overrides[get_session_service] = lambda: sessions
    return application, configured


def test_auth_me_limits_before_resolution_and_does_not_mutate_cookie() -> None:
    selected = replace(
        AvailabilityAbusePolicy(), auth_me_global=CounterPolicy(1, 60)
    )
    availability, _store = control(policy=selected)
    sessions = Sessions({})
    application, configured = application_with(availability, sessions)
    token = generate_session_token()
    with TestClient(application) as client:
        client.cookies.set(configured.session_cookie_name, token)
        assert client.get("/auth/me").status_code == 401
        limited = client.get("/auth/me")

    assert sessions.resolve_calls == 1
    assert limited.status_code == 429
    assert limited.json() == LIMIT_BODY
    assert limited.headers["cache-control"] == "no-store"
    assert limited.headers["retry-after"] == "60"
    assert "set-cookie" not in limited.headers
    assert client.cookies.get(configured.session_cookie_name) == token


def test_random_session_tokens_allocate_no_semantic_state_before_resolution() -> None:
    availability, store = control(maximum_entries=8)
    context = AuthenticationRequestContext(request_id=uuid.uuid4())
    for _ in range(100):
        assert availability.admit_auth_me_outer(context).status in {
            AbuseDecisionStatus.ALLOW,
            AbuseDecisionStatus.LIMITED,
        }
    assert store.entry_count() == 2


def test_logout_limit_is_cookie_neutral_but_store_outage_preserves_recovery() -> None:
    selected = replace(
        AvailabilityAbusePolicy(), logout_global=CounterPolicy(1, 60)
    )
    availability, _store = control(policy=selected)
    token = generate_session_token()
    sessions = Sessions({token: resolved_session()})
    application, configured = application_with(availability, sessions)
    transaction = DatabaseTransaction()
    application.dependency_overrides[get_db_session] = lambda: transaction
    application.dependency_overrides[get_mfa_challenge_service] = lambda: Challenges()
    with TestClient(application) as client:
        client.cookies.set(configured.session_cookie_name, token)
        assert client.post("/auth/logout").status_code == 204
        client.cookies.set(configured.session_cookie_name, token)
        limited = client.post("/auth/logout")
    assert limited.status_code == 429
    assert "set-cookie" not in limited.headers
    assert sessions.revoked == [token]

    unavailable = AvailabilityAbuseControl(
        AbuseControlEngine(UnavailableStore()),
        CorrelationKeyDeriver(b"synthetic-part4-test-secret-32-bytes!!"),
    )
    recovery_sessions = Sessions({token: resolved_session()})
    recovery_app, recovery_settings = application_with(unavailable, recovery_sessions)
    recovery_db = DatabaseTransaction()
    recovery_app.dependency_overrides[get_db_session] = lambda: recovery_db
    recovery_app.dependency_overrides[get_mfa_challenge_service] = lambda: Challenges()
    with TestClient(recovery_app) as client:
        client.cookies.set(recovery_settings.session_cookie_name, token)
        recovered = client.post("/auth/logout")
    assert recovered.status_code == 204
    assert recovery_sessions.revoked == [token]
    assert recovery_db.commits == 1


def test_collection_session_budget_is_independent_and_rejects_before_service() -> None:
    selected = replace(
        AvailabilityAbusePolicy(), collection_session=CounterPolicy(1, 60)
    )
    availability, _store = control(policy=selected)
    first_token, second_token = generate_session_token(), generate_session_token()
    sessions = Sessions(
        {first_token: resolved_session(), second_token: resolved_session()}
    )
    application, configured = application_with(availability, sessions)
    service = CollectionService()
    application.dependency_overrides[get_intelligence_record_collection_read_service] = (
        lambda: service
    )
    with TestClient(application) as client:
        client.cookies.set(configured.session_cookie_name, first_token)
        assert client.get("/records").status_code == 200
        limited = client.get("/records")
        client.cookies.set(configured.session_cookie_name, second_token)
        independent = client.get("/records")

    assert limited.status_code == 429
    assert limited.json() == RECORD_LIMIT_BODY
    assert independent.status_code == 200
    assert service.calls == 2


def test_detail_limit_is_independent_of_record_code_and_prevents_content_work() -> None:
    selected = replace(
        AvailabilityAbusePolicy(), detail_session=CounterPolicy(1, 60)
    )
    availability, _store = control(policy=selected)
    token = generate_session_token()
    sessions = Sessions({token: resolved_session()})
    application, configured = application_with(availability, sessions)
    application.dependency_overrides[get_intelligence_record_read_service] = (
        lambda: UnexpectedRecordService()
    )
    with TestClient(application) as client:
        client.cookies.set(configured.session_cookie_name, token)
        first = client.get("/records/FAKE-0001")
        second = client.get("/records/DIFFERENT-9999")

    assert first.status_code == 503
    assert second.status_code == 429
    assert second.json() == RECORD_LIMIT_BODY
    assert "DIFFERENT-9999" not in second.text


def test_record_concurrency_is_global_session_scoped_and_released() -> None:
    selected = replace(
        AvailabilityAbusePolicy(),
        expensive_global_concurrency=ConcurrencyPolicy(2, 30),
        collection_session_concurrency=ConcurrencyPolicy(1, 30),
    )
    availability, _store = control(policy=selected)
    first_id, second_id = uuid.uuid4(), uuid.uuid4()
    decision, first = availability.acquire_record_work(first_id, collection=True)
    assert decision.status is AbuseDecisionStatus.ALLOW and first is not None
    same_decision, same = availability.acquire_record_work(first_id, collection=True)
    assert same_decision.status is AbuseDecisionStatus.LIMITED and same is None
    other_decision, other = availability.acquire_record_work(second_id, collection=True)
    assert other_decision.status is AbuseDecisionStatus.ALLOW and other is not None
    global_decision, global_blocked = availability.acquire_record_work(
        uuid.uuid4(), collection=False
    )
    assert global_decision.status is AbuseDecisionStatus.LIMITED
    assert global_blocked is None
    first.release()
    other.release()
    released_decision, released = availability.acquire_record_work(
        first_id, collection=True
    )
    assert released_decision.status is AbuseDecisionStatus.ALLOW
    assert released is not None
    released.release()


def test_public_limit_covers_framework_and_static_routes_but_health_is_independent() -> None:
    selected = replace(
        AvailabilityAbusePolicy(), public_source=CounterPolicy(1, 60)
    )
    availability, _store = control(policy=selected)
    application, _configured = application_with(availability)
    with TestClient(application) as client:
        assert client.get("/").status_code == 200
        for path in ("/ui", "/static/css/aegis.css", "/docs", "/redoc", "/openapi.json"):
            limited = client.get(path)
            assert limited.status_code == 429
            assert limited.json() == LIMIT_BODY
        assert client.get("/health").json() == {"status": "ok"}

    unavailable = AvailabilityAbuseControl(
        AbuseControlEngine(UnavailableStore()),
        CorrelationKeyDeriver(b"synthetic-part4-test-secret-32-bytes!!"),
    )
    unavailable_app, _ = application_with(unavailable)
    with TestClient(unavailable_app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/").status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/ui",
        "/ui/",
        "/static/css/aegis.css",
        "/docs",
        "/docs/",
        "/docs/oauth2-redirect",
        "/docs/oauth2-redirect/",
        "/redoc",
        "/redoc/",
        "/openapi.json?synthetic=query",
    ],
)
def test_public_head_and_equivalent_paths_share_the_guard(path: str) -> None:
    selected = replace(
        AvailabilityAbusePolicy(), public_source=CounterPolicy(1, 60)
    )
    availability, _store = control(policy=selected)
    application, _configured = application_with(availability)
    with TestClient(application) as client:
        client.head(path, follow_redirects=False)
        limited = client.head(path, follow_redirects=False)
    assert limited.status_code == 429
    assert limited.headers["cache-control"] == "no-store"
    assert limited.headers["retry-after"] == "60"


def test_health_does_not_call_even_a_programming_error_store() -> None:
    availability = AvailabilityAbuseControl(
        AbuseControlEngine(ProgrammingErrorStore()),
        CorrelationKeyDeriver(b"synthetic-part4-test-secret-32-bytes!!"),
    )
    application, _configured = application_with(availability)
    with TestClient(application) as client:
        health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}


@pytest.mark.parametrize("store", [ProgrammingErrorStore(), InvalidResultStore()])
def test_logout_does_not_fail_open_for_programming_or_invalid_store_results(store) -> None:
    availability = AvailabilityAbuseControl(
        AbuseControlEngine(store),
        CorrelationKeyDeriver(b"synthetic-part4-test-secret-32-bytes!!"),
    )
    token = generate_session_token()
    sessions = Sessions({token: resolved_session()})
    application, configured = application_with(availability, sessions)
    transaction = DatabaseTransaction()
    application.dependency_overrides[get_db_session] = lambda: transaction
    application.dependency_overrides[get_mfa_challenge_service] = lambda: Challenges()
    with TestClient(application, raise_server_exceptions=False) as client:
        client.cookies.set(configured.session_cookie_name, token)
        response = client.post("/auth/logout")
    assert response.status_code == 500
    assert sessions.revoked == []
    assert transaction.commits == 0
    assert "set-cookie" not in response.headers
    assert client.cookies.get(configured.session_cookie_name) == token


@pytest.mark.parametrize(
    ("path", "collection", "service", "expected_status"),
    [
        (
            "/records",
            True,
            ResultService(
                IntelligenceRecordCollectionReadResult(
                    IntelligenceRecordCollectionReadOutcome.AUTHORIZED, ()
                )
            ),
            200,
        ),
        (
            "/records",
            True,
            ResultService(
                IntelligenceRecordCollectionReadResult(
                    IntelligenceRecordCollectionReadOutcome.UNAVAILABLE
                )
            ),
            503,
        ),
        ("/records", True, ResultService(raises=True), 503),
        (
            "/records/INT-99999",
            False,
            ResultService(IntelligenceRecordReadResult.inaccessible()),
            404,
        ),
        (
            "/records/INT-99999",
            False,
            ResultService(IntelligenceRecordReadResult.unavailable()),
            503,
        ),
        ("/records/INT-99999", False, ResultService(raises=True), 503),
        (
            "/records/INT-99999",
            False,
            ResultService(
                IntelligenceRecordReadResult.authorized(
                    AuthorizedIntelligenceRecord(
                        record_code="INT-99999",
                        title="Synthetic Record",
                        summary=None,
                        content="Synthetic content",
                        classification="CONFIDENTIAL",
                    )
                )
            ),
            200,
        ),
    ],
)
def test_record_routes_release_both_leases_for_every_outcome(
    path: str, collection: bool, service: ResultService, expected_status: int
) -> None:
    selected = replace(
        AvailabilityAbusePolicy(),
        expensive_global_concurrency=ConcurrencyPolicy(1, 30),
        collection_session_concurrency=ConcurrencyPolicy(1, 30),
        detail_session_concurrency=ConcurrencyPolicy(1, 30),
    )
    availability, _store = control(policy=selected)
    token = generate_session_token()
    resolved = resolved_session()
    sessions = Sessions({token: resolved})
    application, configured = application_with(availability, sessions)
    dependency = (
        get_intelligence_record_collection_read_service
        if collection
        else get_intelligence_record_read_service
    )
    application.dependency_overrides[dependency] = lambda: service
    with TestClient(application) as client:
        client.cookies.set(configured.session_cookie_name, token)
        response = client.get(path)
    assert response.status_code == expected_status
    decision, leases = availability.acquire_record_work(
        resolved.session_id, collection=collection
    )
    assert decision.status is AbuseDecisionStatus.ALLOW
    assert leases is not None
    leases.release()


def test_expensive_store_outage_fails_closed_before_session_or_record_work() -> None:
    unavailable = AvailabilityAbuseControl(
        AbuseControlEngine(UnavailableStore()),
        CorrelationKeyDeriver(b"synthetic-part4-test-secret-32-bytes!!"),
    )
    sessions = Sessions({})
    application, _configured = application_with(unavailable, sessions)
    application.dependency_overrides[get_intelligence_record_collection_read_service] = (
        lambda: UnexpectedRecordService()
    )
    with TestClient(application) as client:
        identity = client.get("/auth/me")
        collection = client.get("/records")

    assert identity.status_code == 503
    assert identity.json() == {"detail": "Authentication service unavailable"}
    assert collection.status_code == 503
    assert collection.json() == {"detail": "Classified record service unavailable"}
    assert sessions.resolve_calls == 0
