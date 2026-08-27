"""Login-attempt enumeration mitigation, audit, and context tests."""

from dataclasses import asdict
from datetime import datetime, timezone
import uuid
from unittest.mock import Mock

from argon2 import PasswordHasher
from argon2.low_level import Type
import pytest
from sqlalchemy.orm import Session

from aegis.db.models import User
from aegis.db.repositories import UserRepository
from aegis.security.audit_sinks import LoggingAuthenticationAuditSink
from aegis.security.authentication_events import (
    MAX_USER_AGENT_CHARACTERS,
    AuthenticationAuditEvent,
    AuthenticationEventType,
    AuthenticationOutcome,
    AuthenticationReasonCode,
    AuthenticationRequestContext,
    InvalidAuthenticationContext,
)
from aegis.security.passwords import PasswordService
from aegis.services.authentication import (
    AuthenticationService,
    LoginAttemptResult,
    LoginAttemptStatus,
)


SYNTHETIC_PASSWORD = "Synthetic-Nightfall-73!"
WRONG_PASSWORD = "Synthetic-Wrong-Password!"


class RecordingAuditSink:
    """Collect controlled events for service-boundary assertions."""

    def __init__(self) -> None:
        self.events: list[AuthenticationAuditEvent] = []

    def record(self, event: AuthenticationAuditEvent) -> None:
        self.events.append(event)


class FailingAuditSink:
    """Represent an unavailable required audit boundary."""

    def record(self, event: AuthenticationAuditEvent) -> None:
        raise RuntimeError("synthetic audit sink failure")


def make_context(**overrides: object) -> AuthenticationRequestContext:
    values: dict[str, object] = {
        "request_id": uuid.uuid4(),
        "source_ip": "192.0.2.25",
        "user_agent": "AEGIS-Synthetic-Test/1.0",
    }
    values.update(overrides)
    return AuthenticationRequestContext(**values)  # type: ignore[arg-type]


def build_service(
    db_session: Session,
    *,
    passwords: PasswordService | Mock | None = None,
    audit_sink: RecordingAuditSink | FailingAuditSink | None = None,
) -> tuple[UserRepository, AuthenticationService, RecordingAuditSink | FailingAuditSink]:
    users = UserRepository(db_session)
    sink = audit_sink or RecordingAuditSink()
    service = AuthenticationService(users, passwords or PasswordService(), sink)
    return users, service, sink


def persist_user(
    users: UserRepository,
    password_hash: str,
    *,
    username: str = "Synthetic.Operator",
    email: str = "operator@example.test",
    is_active: bool = True,
    disabled_at: datetime | None = None,
) -> User:
    user = User(
        username=username,
        display_name="Synthetic Operator",
        email=email,
        password_hash=password_hash,
        is_active=is_active,
        disabled_at=disabled_at,
    )
    users.add(user)
    users.flush()
    return user


def test_success_returns_identity_only_and_emits_exact_success_event(
    db_session: Session,
) -> None:
    users, service, sink = build_service(db_session)
    user = persist_user(users, PasswordService().hash(SYNTHETIC_PASSWORD))
    context = make_context()

    result = service.attempt_login(
        "SYNTHETIC.OPERATOR", SYNTHETIC_PASSWORD, context
    )

    assert result.status is LoginAttemptStatus.SUCCESS
    assert result.principal is not None
    assert result.principal.user_id == user.id
    assert result.principal.username == "synthetic.operator"
    assert sink.events == [
        AuthenticationAuditEvent(
            event_type=AuthenticationEventType.PASSWORD_AUTH_SUCCESS,
            outcome=AuthenticationOutcome.SUCCESS,
            reason_code=None,
            request_id=context.request_id,
            user_id=user.id,
            username="synthetic.operator",
            source_ip="192.0.2.25",
            user_agent="AEGIS-Synthetic-Test/1.0",
        )
    ]


def test_nonexistent_account_executes_dummy_verification(db_session: Session) -> None:
    passwords = Mock(spec=PasswordService)
    passwords.verify.return_value = False
    _, service, sink = build_service(db_session, passwords=passwords)

    result = service.attempt_login(
        "synthetic.missing", SYNTHETIC_PASSWORD, make_context()
    )

    assert result == LoginAttemptResult.failure()
    passwords.verify.assert_called_once()
    supplied_password, dummy_hash = passwords.verify.call_args.args
    assert supplied_password == SYNTHETIC_PASSWORD
    assert dummy_hash.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    passwords.hash.assert_not_called()
    passwords.verify_and_update.assert_not_called()
    assert sink.events[0].user_id is None
    assert sink.events[0].username is None


def test_disabled_account_executes_dummy_verification(db_session: Session) -> None:
    passwords = Mock(spec=PasswordService)
    passwords.verify.return_value = False
    users, service, sink = build_service(db_session, passwords=passwords)
    user = persist_user(
        users,
        PasswordService().hash(SYNTHETIC_PASSWORD),
        is_active=False,
        disabled_at=datetime.now(timezone.utc),
    )

    result = service.attempt_login(
        "synthetic.operator", SYNTHETIC_PASSWORD, make_context()
    )

    assert result == LoginAttemptResult.failure()
    passwords.verify.assert_called_once()
    passwords.verify_and_update.assert_not_called()
    assert sink.events[0].reason_code is AuthenticationReasonCode.ACCOUNT_UNUSABLE
    assert sink.events[0].user_id == user.id


def test_malformed_username_executes_dummy_verification(db_session: Session) -> None:
    passwords = Mock(spec=PasswordService)
    passwords.verify.return_value = False
    _, service, sink = build_service(db_session, passwords=passwords)

    result = service.attempt_login(
        "invalid username", SYNTHETIC_PASSWORD, make_context()
    )

    assert result == LoginAttemptResult.failure()
    passwords.verify.assert_called_once()
    passwords.hash.assert_not_called()
    passwords.verify_and_update.assert_not_called()
    assert sink.events[0].reason_code is AuthenticationReasonCode.IDENTIFIER_REJECTED
    assert sink.events[0].username is None


def test_dummy_verifier_can_never_authenticate_nonexistent_account(
    db_session: Session,
) -> None:
    passwords = Mock(spec=PasswordService)
    passwords.verify.return_value = True
    _, service, sink = build_service(db_session, passwords=passwords)

    result = service.attempt_login(
        "synthetic.missing", "any-synthetic-password", make_context()
    )

    assert result == LoginAttemptResult.failure()
    assert (
        sink.events[0].event_type
        is AuthenticationEventType.PASSWORD_AUTH_FAILURE
    )


def test_all_credential_rejections_have_same_service_result(
    db_session: Session,
) -> None:
    users, service, sink = build_service(db_session)
    persist_user(users, PasswordService().hash(SYNTHETIC_PASSWORD))
    persist_user(
        users,
        PasswordService().hash(SYNTHETIC_PASSWORD),
        username="synthetic.disabled",
        email="disabled@example.test",
        is_active=False,
        disabled_at=datetime.now(timezone.utc),
    )
    context = make_context()

    results = [
        service.attempt_login("synthetic.operator", WRONG_PASSWORD, context),
        service.attempt_login("synthetic.missing", SYNTHETIC_PASSWORD, context),
        service.attempt_login("synthetic.disabled", SYNTHETIC_PASSWORD, context),
        service.attempt_login("invalid username", SYNTHETIC_PASSWORD, context),
    ]

    assert results == [LoginAttemptResult.failure()] * 4
    assert [event.event_type for event in sink.events] == [
        AuthenticationEventType.PASSWORD_AUTH_FAILURE
    ] * 4
    assert sink.events[-1].reason_code is AuthenticationReasonCode.IDENTIFIER_REJECTED
    assert sink.events[-1].username is None


def test_failure_events_are_controlled_and_contain_no_credentials(
    db_session: Session,
) -> None:
    users, service, sink = build_service(db_session)
    stored_hash = PasswordService().hash(SYNTHETIC_PASSWORD)
    persist_user(users, stored_hash)

    result = service.attempt_login(
        "synthetic.operator", WRONG_PASSWORD, make_context()
    )

    assert result == LoginAttemptResult.failure()
    assert len(sink.events) == 1
    event_values = tuple(str(value) for value in asdict(sink.events[0]).values())
    assert WRONG_PASSWORD not in event_values
    assert SYNTHETIC_PASSWORD not in event_values
    assert stored_hash not in event_values
    assert (
        sink.events[0].event_type
        is AuthenticationEventType.PASSWORD_AUTH_FAILURE
    )
    assert sink.events[0].reason_code is AuthenticationReasonCode.CREDENTIALS_REJECTED


def test_logging_sink_never_receives_credentials_or_session_tokens(
    db_session: Session,
) -> None:
    users, service, sink = build_service(db_session)
    stored_hash = PasswordService().hash(SYNTHETIC_PASSWORD)
    persist_user(users, stored_hash)
    context = make_context()

    result = service.attempt_login(
        "synthetic.operator",
        SYNTHETIC_PASSWORD,
        context,
    )
    assert result.status is LoginAttemptStatus.SUCCESS
    assert len(sink.events) == 1

    logger = Mock()
    LoggingAuthenticationAuditSink(logger).record(sink.events[0])
    rendered_log_call = repr(logger.info.call_args)
    synthetic_raw_token = "T" * 43

    assert "PASSWORD_AUTH_SUCCESS" in rendered_log_call
    assert SYNTHETIC_PASSWORD not in rendered_log_call
    assert stored_hash not in rendered_log_call
    assert synthetic_raw_token not in rendered_log_call


def test_malformed_stored_verifier_fails_closed_and_is_audited(
    db_session: Session,
) -> None:
    users, service, sink = build_service(db_session)
    persist_user(users, "malformed-stored-verifier")

    result = service.attempt_login(
        "synthetic.operator", SYNTHETIC_PASSWORD, make_context()
    )

    assert result == LoginAttemptResult.failure()
    assert sink.events[0].event_type is AuthenticationEventType.PASSWORD_AUTH_FAILURE


def test_context_normalizes_and_bounds_optional_metadata() -> None:
    long_user_agent = "Synthetic-Agent/" + ("x" * 400)

    context = make_context(
        source_ip=" 2001:0db8:0000:0000:0000:0000:0000:0001 ",
        user_agent=long_user_agent,
    )
    malformed_optional = make_context(
        source_ip="not-an-ip-address",
        user_agent="unsafe\r\nheader",
    )

    assert context.source_ip == "2001:db8::1"
    assert context.user_agent == long_user_agent[:MAX_USER_AGENT_CHARACTERS]
    assert malformed_optional.source_ip is None
    assert malformed_optional.user_agent is None
    with pytest.raises(InvalidAuthenticationContext):
        AuthenticationRequestContext(request_id="not-a-uuid")  # type: ignore[arg-type]


def test_missing_or_malformed_optional_metadata_does_not_control_success(
    db_session: Session,
) -> None:
    users, service, sink = build_service(db_session)
    persist_user(users, PasswordService().hash(SYNTHETIC_PASSWORD))
    context = make_context(source_ip="invalid", user_agent="bad\nagent")

    result = service.attempt_login(
        "synthetic.operator", SYNTHETIC_PASSWORD, context
    )
    rejected = service.attempt_login(
        "synthetic.operator", WRONG_PASSWORD, context
    )

    assert result.status is LoginAttemptStatus.SUCCESS
    assert rejected == LoginAttemptResult.failure()
    assert sink.events[0].source_ip is None
    assert sink.events[0].user_agent is None
    assert sink.events[1].event_type is AuthenticationEventType.PASSWORD_AUTH_FAILURE


def test_legacy_audit_failure_does_not_block_success_or_rehash(
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
    users, service, _ = build_service(db_session, audit_sink=FailingAuditSink())
    user = persist_user(users, legacy_hasher.hash(SYNTHETIC_PASSWORD))
    original_hash = user.password_hash

    result = service.attempt_login(
        "synthetic.operator", SYNTHETIC_PASSWORD, make_context()
    )

    assert result.status is LoginAttemptStatus.SUCCESS
    assert user.password_hash != original_hash


def test_legacy_audit_failure_returns_normal_failure_result(
    db_session: Session,
) -> None:
    _, service, _ = build_service(db_session, audit_sink=FailingAuditSink())

    result = service.attempt_login(
        "synthetic.missing", SYNTHETIC_PASSWORD, make_context()
    )

    assert result == LoginAttemptResult.failure()


def test_successful_audited_login_upgrades_outdated_hash(
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
    users, service, sink = build_service(db_session)
    user = persist_user(users, legacy_hasher.hash(SYNTHETIC_PASSWORD))
    original_hash = user.password_hash

    result = service.attempt_login(
        "synthetic.operator", SYNTHETIC_PASSWORD, make_context()
    )

    assert result.status is LoginAttemptStatus.SUCCESS
    assert sink.events[0].event_type is AuthenticationEventType.PASSWORD_AUTH_SUCCESS
    assert user.password_hash != original_hash
    assert PasswordService().verify(SYNTHETIC_PASSWORD, user.password_hash) is True
