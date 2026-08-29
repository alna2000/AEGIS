"""HTTP login, cookie, current-session, logout, and transaction tests."""

from datetime import datetime, timedelta, timezone
import uuid

from argon2 import PasswordHasher
from argon2.low_level import Type
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pyotp
from pydantic import ValidationError
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.api.dependencies import (
    get_audit_service,
    get_authentication_audit_sink,
    get_db_session,
    get_mfa_challenge_service,
    get_mfa_service,
    get_session_service,
)
from aegis.core.config import Settings, get_settings
from aegis.db.models import AuditEvent, MfaChallenge, MfaCredential, User, UserSession
from aegis.db.repositories import (
    MfaChallengeRepository,
    MfaCredentialRepository,
    SessionRepository,
)
from aegis.main import create_app
from aegis.security.authentication_events import (
    AuthenticationAuditEvent,
    AuthenticationEventType,
    AuthenticationRequestContext,
)
from aegis.security.passwords import PasswordService
from aegis.security.security_events import SecurityEventCode
from aegis.security.mfa_encryption import MfaSecretCipher
from aegis.security.totp import TotpService
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.mfa import MfaService
from aegis.services.mfa_challenges import (
    MfaChallengeService,
    generate_mfa_challenge_token,
    hash_mfa_challenge_token,
)
from aegis.services.sessions import (
    SessionService,
    generate_session_token,
    hash_session_token,
)


SYNTHETIC_PASSWORD = "Synthetic-HTTP-Login-73!"
WRONG_PASSWORD = "Synthetic-Wrong-Password!"
GENERIC_FAILURE = {"detail": "Invalid username or password"}
GENERIC_MFA_FAILURE = {"detail": "MFA verification failed"}
FIXED_NOW = datetime(2026, 8, 22, 12, 0, 5, tzinfo=timezone.utc)


def durable_codes(db_session: Session) -> list[str]:
    return list(db_session.scalars(select(AuditEvent.event_code).order_by(AuditEvent.occurred_at, AuditEvent.id)))


class RecordingAuditSink:
    def __init__(self) -> None:
        self.events: list[AuthenticationAuditEvent] = []

    def record(self, event: AuthenticationAuditEvent) -> None:
        self.events.append(event)


class FailingAuditSink:
    def record(self, event: AuthenticationAuditEvent) -> None:
        raise RuntimeError("synthetic audit unavailable")


class FailingDurableAudit:
    def stage(self, _draft):
        raise RuntimeError("synthetic durable audit unavailable")


class FailingSessionService:
    def __init__(self, delegate: SessionService) -> None:
        self._delegate = delegate

    def revoke_session(self, raw_token: str | None) -> bool:
        return self._delegate.revoke_session(raw_token)

    def revoke_session_with_identity(self, raw_token: str | None):
        return self._delegate.revoke_session_with_identity(raw_token)

    def create_session(self, principal, context):
        raise RuntimeError("synthetic session persistence unavailable")


class FailingResolutionService:
    def resolve_session(self, raw_token: str | None):
        raise RuntimeError("synthetic sensitive database detail")


class FailingChallengeCreationService:
    def __init__(self, delegate: MfaChallengeService) -> None:
        self._delegate = delegate

    def requires_totp(self, principal: AuthenticatedPrincipal) -> bool:
        return self._delegate.requires_totp(principal)

    def create_challenge(self, principal, context):
        raise RuntimeError("synthetic challenge persistence unavailable")


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


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
        mfa_encryption_key=None,
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


def configure_mfa_services(
    application: FastAPI,
    db_session: Session,
    settings: Settings,
    sink,
    clock: MutableClock,
) -> None:
    application.dependency_overrides[get_mfa_challenge_service] = lambda: (
        MfaChallengeService(
            MfaChallengeRepository(db_session),
            MfaCredentialRepository(db_session),
            lifetime=timedelta(seconds=settings.mfa_challenge_lifetime_seconds),
            clock=clock,
        )
    )
    application.dependency_overrides[get_mfa_service] = lambda: MfaService(
        MfaCredentialRepository(db_session),
        MfaSecretCipher(
            settings.mfa_encryption_key,
            settings.mfa_encryption_key_id,
        ),
        TotpService(),
        sink,
        clock=clock,
    )


def enable_totp(
    db_session: Session,
    user: User,
    settings: Settings,
    *,
    secret: str | None = None,
) -> str:
    secret = secret or pyotp.random_base32()
    cipher = MfaSecretCipher(
        settings.mfa_encryption_key,
        settings.mfa_encryption_key_id,
    )
    db_session.add(
        MfaCredential(
            user_id=user.id,
            encrypted_secret=cipher.encrypt(secret),
            encryption_key_id=cipher.key_id,
            enabled=True,
            created_at=FIXED_NOW - timedelta(minutes=1),
        )
    )
    db_session.flush()
    return secret


def totp_code(secret: str, at: datetime) -> str:
    return pyotp.TOTP(secret, digits=6, interval=30).at(at)


def verify_totp(client: TestClient, code: str):
    return client.post("/auth/mfa/totp/verify", json={"code": code})


def mfa_settings(*, secure: bool = False, environment: str = "test") -> Settings:
    return Settings(
        environment=environment,
        debug=environment != "production",
        database_url="sqlite+pysqlite:///:memory:",
        session_cookie_secure=secure,
        mfa_encryption_key=Fernet.generate_key().decode("ascii"),
        _env_file=None,
    )


def test_login_sets_hash_only_strict_httponly_cookie_and_safe_json(
    db_session: Session,
) -> None:
    persist_user(db_session)
    application, settings, sink = configure_app(db_session)

    with TestClient(application) as client:
        response = login(client)

    assert response.status_code == 200
    assert response.json() == {"authenticated": True, "mfa_required": False}
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
    assert durable_codes(db_session) == [
        SecurityEventCode.PASSWORD_AUTH_SUCCEEDED.value,
        SecurityEventCode.SESSION_ESTABLISHED.value,
    ]
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

    assert durable_codes(db_session) == [
        SecurityEventCode.PASSWORD_AUTH_SUCCEEDED.value,
        SecurityEventCode.SESSION_ESTABLISHED.value,
        SecurityEventCode.SESSION_REVOKED.value,
        SecurityEventCode.LOGOUT_SUCCEEDED.value,
        SecurityEventCode.LOGOUT_SUCCEEDED.value,
    ]


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


def test_legacy_audit_failure_does_not_block_http_login(
    db_session: Session,
) -> None:
    persist_user(db_session)
    db_session.commit()
    application, settings, _ = configure_app(db_session, audit_sink=FailingAuditSink())

    with TestClient(application) as client:
        response = login(client)

    assert response.status_code == 200
    assert settings.session_cookie_name in response.cookies
    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 1


def test_durable_audit_failure_rolls_back_login_and_returns_no_cookie(
    db_session: Session,
) -> None:
    persist_user(db_session)
    db_session.commit()
    application, settings, _ = configure_app(db_session)
    application.dependency_overrides[get_audit_service] = lambda: FailingDurableAudit()

    with TestClient(application) as client:
        response = login(client)

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service unavailable"}
    assert settings.session_cookie_name not in response.cookies
    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 0
    assert db_session.scalar(select(func.count()).select_from(AuditEvent)) == 0


def test_mfa_password_success_creates_hash_only_challenge_but_no_session(
    db_session: Session,
) -> None:
    user = persist_user(db_session)
    settings = mfa_settings()
    application, _, sink = configure_app(db_session, settings=settings)
    clock = MutableClock(FIXED_NOW)
    secret = enable_totp(db_session, user, settings)
    configure_mfa_services(application, db_session, settings, sink, clock)

    with TestClient(application) as client:
        response = login(client)
        assert client.get("/auth/me").status_code == 401

    assert response.status_code == 200
    assert response.json() == {"authenticated": False, "mfa_required": True}
    raw_challenge = response.cookies.get(settings.mfa_challenge_cookie_name)
    assert raw_challenge is not None
    assert settings.session_cookie_name not in response.cookies
    assert raw_challenge not in response.text
    assert secret not in response.text
    set_cookie = response.headers["set-cookie"]
    assert "HttpOnly" in set_cookie
    assert "SameSite=strict" in set_cookie
    assert "Path=/auth" in set_cookie
    assert "Max-Age=300" in set_cookie
    stored = db_session.scalar(select(MfaChallenge))
    assert stored is not None
    assert stored.token_hash == hash_mfa_challenge_token(raw_challenge)
    assert stored.token_hash != raw_challenge
    assert raw_challenge not in tuple(str(value) for value in vars(stored).values())
    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 0
    assert durable_codes(db_session) == [
        SecurityEventCode.PASSWORD_AUTH_SUCCEEDED.value,
        SecurityEventCode.MFA_CHALLENGE_ISSUED.value,
    ]


def test_valid_challenge_and_totp_consume_challenge_and_issue_fresh_session(
    db_session: Session,
) -> None:
    user = persist_user(db_session)
    settings = mfa_settings()
    application, _, sink = configure_app(db_session, settings=settings)
    clock = MutableClock(FIXED_NOW)
    secret = enable_totp(db_session, user, settings)
    configure_mfa_services(application, db_session, settings, sink, clock)

    with TestClient(application) as client:
        challenge_response = login(client)
        raw_challenge = challenge_response.cookies.get(
            settings.mfa_challenge_cookie_name
        )
        response = verify_totp(client, totp_code(secret, clock.value))
        identity = client.get("/auth/me")

    assert response.status_code == 200
    assert response.json() == {"authenticated": True, "mfa_required": False}
    raw_session = response.cookies.get(settings.session_cookie_name)
    assert raw_challenge is not None
    assert raw_session is not None and raw_session != raw_challenge
    assert raw_session not in response.text
    assert "Max-Age=0" in response.headers["set-cookie"]
    challenge = db_session.scalar(select(MfaChallenge))
    assert challenge is not None and challenge.consumed_at == clock.value
    stored_session = db_session.scalar(select(UserSession))
    assert stored_session is not None
    assert stored_session.token_hash == hash_session_token(raw_session)
    assert identity.status_code == 200
    assert identity.json()["username"] == user.username
    assert durable_codes(db_session) == [
        SecurityEventCode.PASSWORD_AUTH_SUCCEEDED.value,
        SecurityEventCode.MFA_CHALLENGE_ISSUED.value,
        SecurityEventCode.MFA_FACTOR_SUCCEEDED.value,
        SecurityEventCode.SESSION_ESTABLISHED.value,
    ]
    assert [event.event_type for event in sink.events] == [
        AuthenticationEventType.PASSWORD_AUTH_SUCCESS,
        AuthenticationEventType.TOTP_VERIFICATION_SUCCESS,
    ]


def test_totp_without_valid_challenge_never_creates_session(
    db_session: Session,
) -> None:
    user = persist_user(db_session)
    settings = mfa_settings()
    application, _, sink = configure_app(db_session, settings=settings)
    clock = MutableClock(FIXED_NOW)
    secret = enable_totp(db_session, user, settings)
    configure_mfa_services(application, db_session, settings, sink, clock)

    with TestClient(application) as client:
        missing = verify_totp(client, totp_code(secret, clock.value))
        client.cookies.set(
            settings.mfa_challenge_cookie_name,
            generate_mfa_challenge_token(),
            path="/auth",
        )
        random = verify_totp(client, totp_code(secret, clock.value))

    assert missing.status_code == 401 and missing.json() == GENERIC_MFA_FAILURE
    assert random.status_code == 401 and random.json() == GENERIC_MFA_FAILURE
    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 0


def test_expired_and_consumed_challenges_fail_closed(db_session: Session) -> None:
    user = persist_user(db_session)
    settings = mfa_settings()
    application, _, sink = configure_app(db_session, settings=settings)
    clock = MutableClock(FIXED_NOW)
    secret = enable_totp(db_session, user, settings)
    configure_mfa_services(application, db_session, settings, sink, clock)

    with TestClient(application) as client:
        first = login(client)
        expired_token = first.cookies.get(settings.mfa_challenge_cookie_name)
        assert expired_token is not None
        clock.value += timedelta(seconds=settings.mfa_challenge_lifetime_seconds)
        expired = verify_totp(client, totp_code(secret, clock.value))

        clock.value += timedelta(seconds=30)
        second = login(client)
        consumed_token = second.cookies.get(settings.mfa_challenge_cookie_name)
        assert consumed_token is not None
        assert verify_totp(client, totp_code(secret, clock.value)).status_code == 200
        client.cookies.set(
            settings.mfa_challenge_cookie_name,
            consumed_token,
            path="/auth",
        )
        clock.value += timedelta(seconds=30)
        consumed = verify_totp(client, totp_code(secret, clock.value))

    assert expired.status_code == 401 and expired.json() == GENERIC_MFA_FAILURE
    assert consumed.status_code == 401 and consumed.json() == GENERIC_MFA_FAILURE
    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 1


def test_challenge_is_bound_to_its_user_and_failed_code_does_not_consume_it(
    db_session: Session,
) -> None:
    first_user = persist_user(db_session)
    second_user = persist_user(db_session, username="synthetic.second")
    settings = mfa_settings()
    application, _, sink = configure_app(db_session, settings=settings)
    clock = MutableClock(FIXED_NOW)
    first_secret = enable_totp(db_session, first_user, settings)
    second_secret = pyotp.random_base32()
    while totp_code(second_secret, clock.value) == totp_code(
        first_secret, clock.value
    ):
        second_secret = pyotp.random_base32()
    enable_totp(db_session, second_user, settings, secret=second_secret)
    configure_mfa_services(application, db_session, settings, sink, clock)

    with TestClient(application) as client:
        assert login(client).json()["mfa_required"] is True
        wrong_user = verify_totp(client, totp_code(second_secret, clock.value))
        challenge = db_session.scalar(select(MfaChallenge))
        assert challenge is not None and challenge.consumed_at is None
        correct_user = verify_totp(client, totp_code(first_secret, clock.value))

    assert wrong_user.status_code == 401
    assert wrong_user.json() == GENERIC_MFA_FAILURE
    assert correct_user.status_code == 200


@pytest.mark.parametrize("disable_account", [True, False])
def test_disabled_account_or_mfa_credential_cannot_complete_challenge(
    db_session: Session,
    disable_account: bool,
) -> None:
    user = persist_user(db_session)
    settings = mfa_settings()
    application, _, sink = configure_app(db_session, settings=settings)
    clock = MutableClock(FIXED_NOW)
    secret = enable_totp(db_session, user, settings)
    configure_mfa_services(application, db_session, settings, sink, clock)

    with TestClient(application) as client:
        assert login(client).status_code == 200
        if disable_account:
            user.is_active = False
            user.disabled_at = clock.value
        else:
            credential = db_session.scalar(select(MfaCredential))
            assert credential is not None
            credential.enabled = False
            credential.disabled_at = clock.value
        db_session.commit()
        response = verify_totp(client, totp_code(secret, clock.value))

    assert response.status_code == 401
    assert response.json() == GENERIC_MFA_FAILURE
    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 0


def test_totp_replay_fails_but_later_step_can_complete_same_challenge(
    db_session: Session,
) -> None:
    user = persist_user(db_session)
    settings = mfa_settings()
    application, _, sink = configure_app(db_session, settings=settings)
    clock = MutableClock(FIXED_NOW)
    secret = enable_totp(db_session, user, settings)
    configure_mfa_services(application, db_session, settings, sink, clock)

    with TestClient(application) as client:
        assert login(client).status_code == 200
        first_code = totp_code(secret, clock.value)
        assert verify_totp(client, first_code).status_code == 200
        assert login(client).status_code == 200
        replay = verify_totp(client, first_code)
        clock.value += timedelta(seconds=30)
        later = verify_totp(client, totp_code(secret, clock.value))

    assert replay.status_code == 401 and replay.json() == GENERIC_MFA_FAILURE
    assert later.status_code == 200


def test_final_mfa_session_replaces_old_session_without_promoting_challenge(
    db_session: Session,
) -> None:
    user = persist_user(db_session)
    settings = mfa_settings()
    application, _, sink = configure_app(db_session, settings=settings)
    clock = MutableClock(FIXED_NOW)
    configure_mfa_services(application, db_session, settings, sink, clock)

    with TestClient(application) as client:
        direct = login(client)
        old_token = direct.cookies.get(settings.session_cookie_name)
        assert old_token is not None
        secret = enable_totp(db_session, user, settings)
        db_session.commit()
        challenge_response = login(client)
        challenge_token = challenge_response.cookies.get(
            settings.mfa_challenge_cookie_name
        )
        final = verify_totp(client, totp_code(secret, clock.value))
        new_token = final.cookies.get(settings.session_cookie_name)

    assert challenge_token is not None
    assert new_token is not None
    assert new_token not in {old_token, challenge_token}
    old_session = db_session.scalar(
        select(UserSession).where(
            UserSession.token_hash == hash_session_token(old_token)
        )
    )
    assert old_session is not None and old_session.revoked_at is not None


def test_mfa_session_failure_rolls_back_counter_and_challenge_consumption(
    db_session: Session,
) -> None:
    user = persist_user(db_session)
    settings = mfa_settings()
    application, _, sink = configure_app(db_session, settings=settings)
    clock = MutableClock(FIXED_NOW)
    secret = enable_totp(db_session, user, settings)
    db_session.commit()
    configure_mfa_services(application, db_session, settings, sink, clock)
    real_sessions = SessionService(
        SessionRepository(db_session), lifetime=timedelta(hours=8)
    )
    application.dependency_overrides[get_session_service] = lambda: (
        FailingSessionService(real_sessions)
    )

    with TestClient(application) as client:
        assert login(client).status_code == 200
        response = verify_totp(client, totp_code(secret, clock.value))

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service unavailable"}
    assert settings.session_cookie_name not in response.cookies
    db_session.expire_all()
    challenge = db_session.scalar(select(MfaChallenge))
    credential = db_session.scalar(select(MfaCredential))
    assert challenge is not None and challenge.consumed_at is None
    assert credential is not None and credential.last_accepted_counter is None
    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 0
    assert [event.event_type for event in sink.events] == [
        AuthenticationEventType.PASSWORD_AUTH_SUCCESS,
        AuthenticationEventType.TOTP_VERIFICATION_SUCCESS,
    ]


def test_challenge_creation_failure_rolls_back_password_rehash_and_no_cookies(
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
    settings = mfa_settings()
    enable_totp(db_session, user, settings)
    db_session.commit()
    application, _, sink = configure_app(db_session, settings=settings)
    real_challenges = MfaChallengeService(
        MfaChallengeRepository(db_session),
        MfaCredentialRepository(db_session),
        lifetime=timedelta(minutes=5),
    )
    application.dependency_overrides[get_mfa_challenge_service] = lambda: (
        FailingChallengeCreationService(real_challenges)
    )

    with TestClient(application) as client:
        response = login(client)

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service unavailable"}
    assert settings.session_cookie_name not in response.cookies
    assert settings.mfa_challenge_cookie_name not in response.cookies
    db_session.expire_all()
    persisted_user = db_session.get(User, user_id)
    assert persisted_user is not None and persisted_user.password_hash == original_hash
    assert db_session.scalar(select(func.count()).select_from(MfaChallenge)) == 0
    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 0
    assert [event.event_type for event in sink.events] == [
        AuthenticationEventType.PASSWORD_AUTH_SUCCESS
    ]


def test_mfa_validation_and_failures_do_not_echo_code_or_internal_state(
    db_session: Session,
) -> None:
    settings = mfa_settings()
    application, _, _ = configure_app(db_session, settings=settings)
    supplied_code = "654321"

    with TestClient(application) as client:
        malformed = client.post(
            "/auth/mfa/totp/verify",
            json={"code": supplied_code, "username": "synthetic.operator"},
        )

    assert malformed.status_code == 401
    assert malformed.json() == GENERIC_MFA_FAILURE
    assert supplied_code not in malformed.text


def test_enabled_mfa_with_missing_key_fails_before_challenge_issuance(
    db_session: Session,
) -> None:
    user = persist_user(db_session)
    key = Fernet.generate_key().decode("ascii")
    storage_settings = mfa_settings()
    storage_settings.mfa_encryption_key = key
    enable_totp(db_session, user, storage_settings)
    application, settings, _ = configure_app(db_session)

    with TestClient(application) as client:
        response = login(client)

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service unavailable"}
    assert settings.mfa_challenge_cookie_name not in response.cookies
    assert db_session.scalar(select(func.count()).select_from(MfaChallenge)) == 0


def test_production_mfa_challenge_cookie_is_secure(db_session: Session) -> None:
    user = persist_user(db_session)
    settings = mfa_settings(secure=True, environment="production")
    application, _, sink = configure_app(db_session, settings=settings)
    clock = MutableClock(FIXED_NOW)
    enable_totp(db_session, user, settings)
    configure_mfa_services(application, db_session, settings, sink, clock)

    with TestClient(application, base_url="https://testserver") as client:
        response = login(client)

    assert response.status_code == 200
    assert "Secure" in response.headers["set-cookie"]


def test_logout_revokes_and_clears_an_in_progress_mfa_challenge(
    db_session: Session,
) -> None:
    user = persist_user(db_session)
    settings = mfa_settings()
    application, _, sink = configure_app(db_session, settings=settings)
    clock = MutableClock(FIXED_NOW)
    secret = enable_totp(db_session, user, settings)
    configure_mfa_services(application, db_session, settings, sink, clock)

    with TestClient(application) as client:
        challenge_response = login(client)
        raw_challenge = challenge_response.cookies.get(
            settings.mfa_challenge_cookie_name
        )
        assert raw_challenge is not None
        logout_response = client.post("/auth/logout")
        client.cookies.set(
            settings.mfa_challenge_cookie_name,
            raw_challenge,
            path="/auth",
        )
        denied = verify_totp(client, totp_code(secret, clock.value))

    challenge = db_session.scalar(select(MfaChallenge))
    assert logout_response.status_code == 204
    assert "Max-Age=0" in logout_response.headers["set-cookie"]
    assert challenge is not None and challenge.revoked_at == clock.value
    assert denied.status_code == 401
