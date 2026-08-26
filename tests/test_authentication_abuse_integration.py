"""Deterministic HTTP integration tests for login and MFA abuse protection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import pyotp
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.api.dependencies import (
    get_authentication_abuse_control,
    get_authentication_audit_sink,
    get_authentication_service,
    get_db_session,
    get_mfa_challenge_service,
    get_mfa_service,
)
from aegis.core.config import Settings, get_settings
from aegis.db.models import MfaChallenge, MfaCredential, User
from aegis.db.repositories import MfaChallengeRepository, MfaCredentialRepository
from aegis.main import create_app
from aegis.security.abuse import (
    AbuseControlEngine,
    AbuseDecisionStatus,
    AbuseScope,
    AbuseScopeKind,
    AbuseStoreUnavailable,
    ConcurrencyPolicy,
    CorrelationKeyDeriver,
    CooldownPolicy,
    CounterPolicy,
    InMemoryAbuseStateStore,
)
from aegis.security.authentication_abuse import (
    AuthenticationAbuseControl,
    AuthenticationAbusePolicy,
)
from aegis.security.authentication_events import AuthenticationRequestContext
from aegis.security.mfa_encryption import MfaSecretCipher
from aegis.security.passwords import PasswordService
from aegis.security.totp import TotpService
from aegis.services.mfa import MfaService
from aegis.services.mfa_challenges import MfaChallengeService


PASSWORD = "Synthetic-Abuse-Password-41!"
NOW = datetime(2026, 8, 26, 12, 0, 5, tzinfo=timezone.utc)
LIMIT_BODY = {"detail": "Authentication temporarily unavailable"}
SERVICE_BODY = {"detail": "Authentication service unavailable"}


class MonotonicClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class DateTimeClock:
    def __call__(self) -> datetime:
        return NOW


class AuditSink:
    def record(self, _event) -> None:
        return None


class UnexpectedAuthentication:
    def attempt_login(self, *_args, **_kwargs):
        raise AssertionError("limited login reached Argon2 authentication")


class FailingMfaService:
    def verify_result(self, *_args, **_kwargs):
        raise RuntimeError("synthetic MFA infrastructure failure")


class UnavailableStore:
    def admit(self, _rules):
        raise AbuseStoreUnavailable("synthetic store unavailable")

    def check_cooldowns(self, _scopes):
        raise AbuseStoreUnavailable("synthetic store unavailable")

    def activate_cooldown(self, _scope, _delay):
        raise AbuseStoreUnavailable("synthetic store unavailable")

    def acquire_lease(self, _scope, _policy):
        raise AbuseStoreUnavailable("synthetic store unavailable")

    def release_lease(self, _scope, _token):
        raise AbuseStoreUnavailable("synthetic store unavailable")


def policy(**changes) -> AuthenticationAbusePolicy:
    values = {
        "login_global": CounterPolicy(100, 60),
        "login_source": CounterPolicy(100, 60),
        "login_identity": CounterPolicy(2, 60),
        "login_concurrency": ConcurrencyPolicy(2, 30),
        "mfa_global": CounterPolicy(100, 60),
        "mfa_source": CounterPolicy(100, 60),
        "mfa_token": CounterPolicy(20, 300),
        "mfa_concurrency": ConcurrencyPolicy(1, 30),
        "mfa_cooldown": CooldownPolicy(1, 4),
        "mfa_max_factor_failures": 5,
    }
    values.update(changes)
    return AuthenticationAbusePolicy(**values)


def abuse_control(
    *,
    selected_policy: AuthenticationAbusePolicy | None = None,
    maximum_entries: int = 128,
) -> tuple[AuthenticationAbuseControl, InMemoryAbuseStateStore, MonotonicClock]:
    clock = MonotonicClock()
    store = InMemoryAbuseStateStore(
        maximum_entries=maximum_entries, reserved_entries=2, clock=clock
    )
    control = AuthenticationAbuseControl(
        AbuseControlEngine(store),
        CorrelationKeyDeriver(b"synthetic-abuse-test-secret-32-bytes!!"),
        policy=selected_policy or policy(),
    )
    return control, store, clock


def settings() -> Settings:
    return Settings(
        environment="test",
        database_url="sqlite+pysqlite:///:memory:",
        session_cookie_secure=False,
        mfa_encryption_key=Fernet.generate_key().decode("ascii"),
        _env_file=None,
    )


def persist_user(
    db_session: Session,
    *,
    username: str = "synthetic.operator",
    is_active: bool = True,
    disabled_at: datetime | None = None,
) -> User:
    user = User(
        username=username,
        display_name="Synthetic Operator",
        email=f"{username}@example.test",
        password_hash=PasswordService().hash(PASSWORD),
        is_active=is_active,
        disabled_at=disabled_at,
    )
    db_session.add(user)
    db_session.flush()
    return user


def configure(
    db_session: Session,
    control: AuthenticationAbuseControl,
    *,
    test_settings: Settings | None = None,
):
    application = create_app()
    selected_settings = test_settings or settings()
    sink = AuditSink()
    application.dependency_overrides[get_settings] = lambda: selected_settings
    application.dependency_overrides[get_db_session] = lambda: db_session
    application.dependency_overrides[get_authentication_audit_sink] = lambda: sink
    application.dependency_overrides[get_authentication_abuse_control] = lambda: control
    application.dependency_overrides[get_mfa_challenge_service] = lambda: MfaChallengeService(
        MfaChallengeRepository(db_session),
        MfaCredentialRepository(db_session),
        lifetime=timedelta(seconds=selected_settings.mfa_challenge_lifetime_seconds),
        clock=DateTimeClock(),
    )
    application.dependency_overrides[get_mfa_service] = lambda: MfaService(
        MfaCredentialRepository(db_session),
        MfaSecretCipher(
            selected_settings.mfa_encryption_key,
            selected_settings.mfa_encryption_key_id,
        ),
        TotpService(),
        sink,
        clock=DateTimeClock(),
    )
    return application, selected_settings


def post_login(client: TestClient, username: str, password: str = "wrong"):
    return client.post(
        "/auth/login", json={"username": username, "password": password}
    )


def test_login_limit_is_generic_cookie_neutral_and_prevents_argon2(
    db_session: Session,
) -> None:
    persist_user(db_session)
    control, _store, _clock = abuse_control(
        selected_policy=policy(login_identity=CounterPolicy(1, 60))
    )
    application, _ = configure(db_session, control)
    with TestClient(application) as client:
        client.cookies.set("existing", "synthetic-cookie")
        assert post_login(client, "synthetic.operator").status_code == 401
        application.dependency_overrides[get_authentication_service] = (
            lambda: UnexpectedAuthentication()
        )
        limited = post_login(client, "SYNTHETIC.OPERATOR")

    assert limited.status_code == 429
    assert limited.json() == LIMIT_BODY
    assert limited.headers["cache-control"] == "no-store"
    assert limited.headers["retry-after"] == "60"
    assert "set-cookie" not in limited.headers
    assert client.cookies.get("existing") == "synthetic-cookie"


def test_known_unknown_and_malformed_login_scopes_have_equivalent_contract(
    db_session: Session,
) -> None:
    persist_user(db_session)
    persist_user(db_session, username="inactive.operator", is_active=False)
    persist_user(
        db_session,
        username="disabled.operator",
        is_active=False,
        disabled_at=NOW - timedelta(minutes=1),
    )
    control, store, _clock = abuse_control(
        selected_policy=policy(login_identity=CounterPolicy(1, 60))
    )
    application, _ = configure(db_session, control)
    with TestClient(application) as client:
        outcomes = []
        for username in (
            "synthetic.operator",
            "unknown.operator",
            "inactive.operator",
            "disabled.operator",
            "!",
        ):
            first = post_login(client, username)
            second = post_login(client, username)
            outcomes.append((first.status_code, second.status_code, second.json()))
        malformed_flood = [post_login(client, "@" * length) for length in range(2, 42)]

    assert outcomes == [(401, 429, LIMIT_BODY)] * 5
    assert all(response.status_code == 429 for response in malformed_flood)
    # Global, source, four normalized identities, and one fixed malformed class.
    assert store.entry_count() == 7


def test_login_store_unavailable_fails_closed_before_authentication(
    db_session: Session,
) -> None:
    control = AuthenticationAbuseControl(
        AbuseControlEngine(UnavailableStore()),
        CorrelationKeyDeriver(b"synthetic-abuse-test-secret-32-bytes!!"),
        policy=policy(),
    )
    application, _ = configure(db_session, control)
    application.dependency_overrides[get_authentication_service] = (
        lambda: UnexpectedAuthentication()
    )
    with TestClient(application) as client:
        response = post_login(client, "unknown.operator")
    assert response.status_code == 503
    assert response.json() == SERVICE_BODY
    assert response.headers["cache-control"] == "no-store"


def test_valid_identity_cardinality_is_bounded_and_global_protection_remains() -> None:
    control, store, _clock = abuse_control(maximum_entries=8)
    context = AuthenticationRequestContext(request_id=__import__("uuid").uuid4())
    decisions = [control.admit_login(f"user-{index}", context) for index in range(20)]
    assert store.entry_count() <= 8
    assert any(decision.status is AbuseDecisionStatus.UNAVAILABLE for decision in decisions)
    assert control.admit_login("user-0", context).status in {
        AbuseDecisionStatus.ALLOW,
        AbuseDecisionStatus.LIMITED,
    }


def test_login_concurrency_slots_cannot_be_oversubscribed() -> None:
    control, _store, _clock = abuse_control(
        selected_policy=policy(login_concurrency=ConcurrencyPolicy(1, 30))
    )
    first = control.acquire_login_work()
    second = control.acquire_login_work()
    assert first.decision.status is AbuseDecisionStatus.ALLOW
    assert second.decision.status is AbuseDecisionStatus.LIMITED
    assert first.lease is not None
    first.lease.release()


def test_mfa_token_concurrency_slots_cannot_be_oversubscribed() -> None:
    control, _store, _clock = abuse_control()
    token = "A" * 43
    first = control.acquire_mfa_work(token)
    second = control.acquire_mfa_work(token)
    assert first.decision.status is AbuseDecisionStatus.ALLOW
    assert second.decision.status is AbuseDecisionStatus.LIMITED
    assert first.lease is not None
    first.lease.release()


def _enable_totp(db_session: Session, user: User, selected_settings: Settings) -> str:
    secret = pyotp.random_base32()
    cipher = MfaSecretCipher(
        selected_settings.mfa_encryption_key,
        selected_settings.mfa_encryption_key_id,
    )
    db_session.add(
        MfaCredential(
            user_id=user.id,
            encrypted_secret=cipher.encrypt(secret),
            encryption_key_id=cipher.key_id,
            enabled=True,
            created_at=NOW - timedelta(minutes=1),
        )
    )
    db_session.flush()
    return secret


def test_fifth_factor_failure_revokes_only_challenge_and_new_login_can_retry(
    db_session: Session,
) -> None:
    user = persist_user(db_session)
    control, _store, clock = abuse_control()
    application, selected_settings = configure(db_session, control)
    secret = _enable_totp(db_session, user, selected_settings)
    valid_code = pyotp.TOTP(secret).at(NOW)
    wrong_code = "000000" if valid_code != "000000" else "111111"

    with TestClient(application) as client:
        login_response = post_login(client, user.username, PASSWORD)
        assert login_response.status_code == 200
        for failure_number in range(1, 6):
            response = client.post("/auth/mfa/totp/verify", json={"code": wrong_code})
            assert response.status_code == 401
            persisted = db_session.scalar(select(MfaChallenge))
            assert persisted is not None
            assert persisted.failed_factor_attempts == failure_number
            assert (persisted.revoked_at is not None) is (failure_number == 5)
            if failure_number in (2, 3, 4):
                retry = 2 ** (failure_number - 2)
                limited = client.post(
                    "/auth/mfa/totp/verify", json={"code": wrong_code}
                )
                assert limited.status_code == 429
                assert limited.json() == LIMIT_BODY
                assert limited.headers["retry-after"] == str(retry)
                assert "set-cookie" not in limited.headers
                clock.value += retry

        sixth = client.post("/auth/mfa/totp/verify", json={"code": valid_code})
        assert sixth.status_code == 401
        replacement = post_login(client, user.username, PASSWORD)
        assert replacement.status_code == 200
        assert replacement.json() == {"authenticated": False, "mfa_required": True}

    challenges = list(db_session.scalars(select(MfaChallenge).order_by(MfaChallenge.created_at)))
    assert challenges[0].failed_factor_attempts == 5
    assert challenges[0].revoked_at is not None
    credential = db_session.scalar(select(MfaCredential).where(MfaCredential.user_id == user.id))
    assert user.is_active is True
    assert credential is not None and credential.enabled is True
    assert challenges[-1].revoked_at is None
    assert challenges[-1].failed_factor_attempts == 0


def test_non_digit_factor_failure_counts_but_infrastructure_failure_does_not(
    db_session: Session,
) -> None:
    user = persist_user(db_session)
    control, _store, _clock = abuse_control()
    application, selected_settings = configure(db_session, control)
    _enable_totp(db_session, user, selected_settings)
    with TestClient(application) as client:
        assert post_login(client, user.username, PASSWORD).status_code == 200
        assert client.post("/auth/mfa/totp/verify", json={"code": "abcdef"}).status_code == 401
        challenge = db_session.scalar(select(MfaChallenge))
        assert challenge is not None and challenge.failed_factor_attempts == 1

        credential = db_session.scalar(
            select(MfaCredential).where(MfaCredential.user_id == user.id)
        )
        assert credential is not None
        credential.encrypted_secret = "synthetic-invalid-ciphertext"
        db_session.flush()
        unusable = client.post("/auth/mfa/totp/verify", json={"code": "123456"})
        assert unusable.status_code == 401
        db_session.refresh(challenge)
        assert challenge.failed_factor_attempts == 1

        application.dependency_overrides[get_mfa_service] = lambda: FailingMfaService()
        failed = client.post("/auth/mfa/totp/verify", json={"code": "123456"})
        assert failed.status_code == 503
        db_session.refresh(challenge)
        assert challenge.failed_factor_attempts == 1


def test_random_malformed_and_missing_mfa_tokens_are_generic_and_bounded(
    db_session: Session,
) -> None:
    control, store, _clock = abuse_control(
        selected_policy=policy(mfa_token=CounterPolicy(1, 60))
    )
    application, selected_settings = configure(db_session, control)
    with TestClient(application) as client:
        first_missing = client.post("/auth/mfa/totp/verify", json={"code": "123456"})
        limited_missing = client.post("/auth/mfa/totp/verify", json={"code": "123456"})
        client.cookies.set(selected_settings.mfa_challenge_cookie_name, "malformed")
        limited_malformed = client.post("/auth/mfa/totp/verify", json={"code": "123456"})
        client.cookies.set(selected_settings.mfa_challenge_cookie_name, "A" * 43)
        random_first = client.post("/auth/mfa/totp/verify", json={"code": "123456"})
        random_limited = client.post("/auth/mfa/totp/verify", json={"code": "123456"})

    assert first_missing.status_code == 401
    assert limited_missing.status_code == 429
    assert limited_malformed.status_code == 429
    assert limited_missing.json() == limited_malformed.json() == LIMIT_BODY
    assert random_first.status_code == 401
    assert random_limited.status_code == 429
    assert random_limited.json() == LIMIT_BODY
    # Endpoint, source, controlled missing/malformed, and one random token scope.
    assert store.entry_count() == 4
