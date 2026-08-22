"""HTTP login, cookie, current-session, logout, and transaction tests."""

from datetime import datetime, timedelta, timezone
import uuid

from argon2 import PasswordHasher
from argon2.low_level import Type
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.api.dependencies import (
    get_authentication_audit_sink,
    get_db_session,
    get_session_service,
)
from aegis.core.config import Settings, get_settings
from aegis.db.models import User, UserSession
from aegis.db.repositories import SessionRepository
from aegis.main import create_app
from aegis.security.authentication_events import (
    AuthenticationAuditEvent,
    AuthenticationEventType,
    AuthenticationRequestContext,
)
from aegis.security.passwords import PasswordService
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.sessions import (
    SessionService,
    generate_session_token,
    hash_session_token,
)


SYNTHETIC_PASSWORD = "Synthetic-HTTP-Login-73!"
WRONG_PASSWORD = "Synthetic-Wrong-Password!"
GENERIC_FAILURE = {"detail": "Invalid username or password"}


class RecordingAuditSink:
    def __init__(self) -> None:
        self.events: list[AuthenticationAuditEvent] = []

    def record(self, event: AuthenticationAuditEvent) -> None:
        self.events.append(event)


class FailingAuditSink:
    def record(self, event: AuthenticationAuditEvent) -> None:
        raise RuntimeError("synthetic audit unavailable")


class FailingSessionService:
    def __init__(self, delegate: SessionService) -> None:
        self._delegate = delegate

    def revoke_session(self, raw_token: str | None) -> bool:
        return self._delegate.revoke_session(raw_token)

    def create_session(self, principal, context):
        raise RuntimeError("synthetic session persistence unavailable")


class FailingResolutionService:
    def resolve_session(self, raw_token: str | None):
        raise RuntimeError("synthetic sensitive database detail")


def persist_user(
    db_session: Session,
    *,
    username: str = "synthetic.operator",
    password_hash: str | None = None,
    is_active: bool = True,
    disabled_at: datetime | None = None,
) -> User:
    user = User(
        username=username,
        display_name="Synthetic Operator",
        email=f"{username}@example.test",
        password_hash=password_hash or PasswordService().hash(SYNTHETIC_PASSWORD),
        is_active=is_active,
        disabled_at=disabled_at,
    )
    db_session.add(user)
    db_session.flush()
    return user


def configure_app(
    db_session: Session,
    *,
    settings: Settings | None = None,
    audit_sink=None,
) -> tuple[FastAPI, Settings, RecordingAuditSink | FailingAuditSink]:
    application = create_app()
    test_settings = settings or Settings(
        environment="test",
        database_url="sqlite+pysqlite:///:memory:",
        session_cookie_secure=False,
        _env_file=None,
    )
    sink = audit_sink or RecordingAuditSink()
    application.dependency_overrides[get_settings] = lambda: test_settings
    application.dependency_overrides[get_db_session] = lambda: db_session
    application.dependency_overrides[get_authentication_audit_sink] = lambda: sink
    return application, test_settings, sink


def login(client: TestClient, username: str = "synthetic.operator"):
    return client.post(
        "/auth/login",
        json={"username": username, "password": SYNTHETIC_PASSWORD},
        headers={"user-agent": "AEGIS-HTTP-Test/1.0"},
    )


def test_login_sets_hash_only_strict_httponly_cookie_and_safe_json(
    db_session: Session,
) -> None:
    persist_user(db_session)
    application, settings, sink = configure_app(db_session)

    with TestClient(application) as client:
        response = login(client)

    assert response.status_code == 200
    assert response.json() == {"authenticated": True}
    raw_token = response.cookies.get(settings.session_cookie_name)
    assert raw_token is not None
    assert len(raw_token) == 43
    assert raw_token not in response.text
    set_cookie = response.headers["set-cookie"]
    assert "HttpOnly" in set_cookie
    assert "SameSite=strict" in set_cookie
    assert "Path=/" in set_cookie
    assert "Secure" not in set_cookie

    stored = db_session.scalar(select(UserSession))
    assert stored is not None
    assert stored.token_hash == hash_session_token(raw_token)
    assert stored.token_hash != raw_token
    # TestClient's synthetic host is not an IP address, so minimized context drops it.
    assert stored.source_ip is None
    assert stored.user_agent == "AEGIS-HTTP-Test/1.0"
    assert len(sink.events) == 1
    assert (
        sink.events[0].event_type
        is AuthenticationEventType.PASSWORD_AUTH_SUCCESS
    )


def test_production_configuration_requires_and_emits_secure_cookie(
    db_session: Session,
) -> None:
    with pytest.raises(ValidationError):
        Settings(environment="production", session_cookie_secure=False, _env_file=None)

    persist_user(db_session)
    production = Settings(
        environment="production",
        debug=False,
        database_url="sqlite+pysqlite:///:memory:",
        session_cookie_secure=True,
        _env_file=None,
    )
    application, _, _ = configure_app(db_session, settings=production)

    with TestClient(application, base_url="https://testserver") as client:
        response = login(client)

    assert response.status_code == 200
    assert "Secure" in response.headers["set-cookie"]


def test_all_ordinary_login_rejections_share_one_public_response(
    db_session: Session,
) -> None:
    persist_user(db_session)
    persist_user(
        db_session,
        username="synthetic.disabled",
        is_active=False,
        disabled_at=datetime.now(timezone.utc),
    )
    persist_user(
        db_session,
        username="synthetic.invalidhash",
        password_hash="malformed-stored-verifier",
    )
    db_session.commit()
    application, _, _ = configure_app(db_session)

    attempts = [
        {"username": "synthetic.operator", "password": WRONG_PASSWORD},
        {"username": "synthetic.missing", "password": SYNTHETIC_PASSWORD},
        {"username": "invalid username", "password": SYNTHETIC_PASSWORD},
        {"username": "synthetic.disabled", "password": SYNTHETIC_PASSWORD},
        {"username": "synthetic.invalidhash", "password": SYNTHETIC_PASSWORD},
    ]
    with TestClient(application) as client:
        responses = [client.post("/auth/login", json=attempt) for attempt in attempts]

    assert [response.status_code for response in responses] == [401] * len(attempts)
    assert [response.json() for response in responses] == [GENERIC_FAILURE] * len(attempts)
    combined_output = " ".join(response.text for response in responses)
    assert WRONG_PASSWORD not in combined_output
    assert SYNTHETIC_PASSWORD not in combined_output
    assert "malformed-stored-verifier" not in combined_output
    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 0


def test_invalid_login_body_does_not_echo_password_or_extra_input(
    db_session: Session,
) -> None:
    application, _, _ = configure_app(db_session)
    supplied_secret = "synthetic-plaintext-must-not-echo"

    with TestClient(application) as client:
        response = client.post(
            "/auth/login",
            json={"username": 123, "password": supplied_secret, "is_active": True},
        )

    assert response.status_code == 401
    assert response.json() == GENERIC_FAILURE
    assert supplied_secret not in response.text


def test_current_session_returns_safe_identity_and_missing_cookie_fails(
    db_session: Session,
) -> None:
    persist_user(db_session)
    application, _, _ = configure_app(db_session)

    with TestClient(application) as client:
        assert client.get("/auth/me").status_code == 401
        assert login(client).status_code == 200
        response = client.get("/auth/me")

    assert response.status_code == 200
    assert response.json() == {
        "username": "synthetic.operator",
        "display_name": "Synthetic Operator",
    }
    assert set(response.json()) == {"username", "display_name"}


def test_current_session_internal_failure_is_sanitized(db_session: Session) -> None:
    application, _, _ = configure_app(db_session)
    application.dependency_overrides[get_session_service] = (
        lambda: FailingResolutionService()
    )

    with TestClient(application) as client:
        response = client.get("/auth/me")

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service unavailable"}
    assert "synthetic sensitive database detail" not in response.text


def test_unknown_malformed_expired_revoked_and_disabled_sessions_fail_http(
    db_session: Session,
) -> None:
    user = persist_user(db_session)
    application, settings, _ = configure_app(db_session)

    with TestClient(application) as client:
        client.cookies.set(settings.session_cookie_name, "malformed")
        assert client.get("/auth/me").status_code == 401
        client.cookies.set(settings.session_cookie_name, generate_session_token())
        assert client.get("/auth/me").status_code == 401

        success = login(client)
        raw_token = success.cookies.get(settings.session_cookie_name)
        assert raw_token is not None
        stored = db_session.scalar(
            select(UserSession).where(
                UserSession.token_hash == hash_session_token(raw_token)
            )
        )
        assert stored is not None

        stored.expires_at = stored.created_at + timedelta(microseconds=1)
        db_session.flush()
        assert client.get("/auth/me").status_code == 401
        stored.expires_at = stored.created_at.replace(year=stored.created_at.year + 1)
        stored.revoked_at = stored.created_at
        db_session.flush()
        assert client.get("/auth/me").status_code == 401
        stored.revoked_at = None
        user.is_active = False
        user.disabled_at = datetime.now(timezone.utc)
        db_session.flush()
        assert client.get("/auth/me").status_code == 401


def test_logout_revokes_server_state_clears_cookie_and_is_idempotent(
    db_session: Session,
) -> None:
    persist_user(db_session)
    application, settings, _ = configure_app(db_session)

    with TestClient(application) as client:
        success = login(client)
        old_token = success.cookies.get(settings.session_cookie_name)
        assert old_token is not None
        response = client.post("/auth/logout")
        assert response.status_code == 204
        assert "Max-Age=0" in response.headers["set-cookie"]

        stored = db_session.scalar(
            select(UserSession).where(
                UserSession.token_hash == hash_session_token(old_token)
            )
        )
        assert stored is not None
        assert stored.revoked_at is not None

        client.cookies.set(settings.session_cookie_name, old_token)
        assert client.get("/auth/me").status_code == 401
        assert client.post("/auth/logout").status_code == 204


def test_login_does_not_promote_fixated_token_and_rotates_existing_session(
    db_session: Session,
) -> None:
    persist_user(db_session)
    application, settings, _ = configure_app(db_session)
    attacker_token = generate_session_token()

    with TestClient(application) as client:
        client.cookies.set(settings.session_cookie_name, attacker_token)
        first = login(client)
        first_token = first.cookies.get(settings.session_cookie_name)
        assert first_token is not None and first_token != attacker_token
        second = login(client)
        second_token = second.cookies.get(settings.session_cookie_name)

    assert second_token is not None and second_token != first_token
    assert db_session.scalar(
        select(UserSession).where(
            UserSession.token_hash == hash_session_token(attacker_token)
        )
    ) is None
    first_session = db_session.scalar(
        select(UserSession).where(UserSession.token_hash == hash_session_token(first_token))
    )
    assert first_session is not None and first_session.revoked_at is not None
    second_session = db_session.scalar(
        select(UserSession).where(
            UserSession.token_hash == hash_session_token(second_token)
        )
    )
    assert second_session is not None and second_session.revoked_at is None


def test_session_persistence_failure_rolls_back_password_rehash_and_returns_no_cookie(
    db_session: Session,
) -> None:
    legacy_hasher = PasswordHasher(
        time_cost=1,
        memory_cost=1024,
        parallelism=1,
        hash_len=16,
        salt_len=8,
        type=Type.ID,
    )
    original_hash = legacy_hasher.hash(SYNTHETIC_PASSWORD)
    user = persist_user(db_session, password_hash=original_hash)
    user_id = user.id
    db_session.commit()
    application, settings, sink = configure_app(db_session)
    real_sessions = SessionService(
        SessionRepository(db_session),
        lifetime=timedelta(hours=8),
    )
    prior_session = real_sessions.create_session(
        AuthenticatedPrincipal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
        ),
        AuthenticationRequestContext(request_id=uuid.uuid4()),
    )
    db_session.commit()
    application.dependency_overrides[get_session_service] = lambda: FailingSessionService(
        real_sessions
    )

    with TestClient(application) as client:
        client.cookies.set(settings.session_cookie_name, prior_session.raw_token)
        response = login(client)

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service unavailable"}
    assert settings.session_cookie_name not in response.cookies
    db_session.expire_all()
    persisted_user = db_session.get(User, user_id)
    assert persisted_user is not None
    assert persisted_user.password_hash == original_hash
    persisted_prior_session = db_session.scalar(
        select(UserSession).where(
            UserSession.token_hash == hash_session_token(prior_session.raw_token)
        )
    )
    assert persisted_prior_session is not None
    assert persisted_prior_session.revoked_at is None
    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 1
    assert len(sink.events) == 1
    assert (
        sink.events[0].event_type
        is AuthenticationEventType.PASSWORD_AUTH_SUCCESS
    )


def test_required_audit_failure_blocks_http_login_and_session_creation(
    db_session: Session,
) -> None:
    persist_user(db_session)
    db_session.commit()
    application, settings, _ = configure_app(db_session, audit_sink=FailingAuditSink())

    with TestClient(application) as client:
        response = login(client)

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service unavailable"}
    assert settings.session_cookie_name not in response.cookies
    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 0
