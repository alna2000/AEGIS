"""Server-side session token and lifecycle security tests."""

import base64
from datetime import datetime, timedelta, timezone
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.db.models import User, UserSession
from aegis.db.repositories import SessionRepository
from aegis.security.authentication_events import AuthenticationRequestContext
from aegis.security.passwords import PasswordService
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.sessions import (
    SESSION_TOKEN_BYTES,
    SessionService,
    generate_session_token,
    hash_session_token,
)


FIXED_NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
SYNTHETIC_PASSWORD = "Synthetic-Session-93!"


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def persist_user(db_session: Session, *, active: bool = True) -> User:
    user = User(
        username=f"synthetic.{uuid.uuid4().hex[:12]}",
        display_name="Synthetic Session User",
        email=None,
        password_hash=PasswordService().hash(SYNTHETIC_PASSWORD),
        is_active=active,
        disabled_at=None,
    )
    db_session.add(user)
    db_session.flush()
    return user


def principal_for(user: User) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
    )


def context() -> AuthenticationRequestContext:
    return AuthenticationRequestContext(
        request_id=uuid.uuid4(),
        source_ip="192.0.2.44",
        user_agent="AEGIS-Session-Test/1.0",
    )


def build_service(
    db_session: Session,
    clock: MutableClock,
    *,
    token_generator=generate_session_token,
) -> SessionService:
    return SessionService(
        SessionRepository(db_session),
        lifetime=timedelta(hours=8),
        clock=clock,
        token_generator=token_generator,
    )


def test_generated_tokens_have_256_bits_and_are_unique() -> None:
    first = generate_session_token()
    second = generate_session_token()

    decoded = base64.urlsafe_b64decode(first + "=")
    assert len(decoded) == SESSION_TOKEN_BYTES
    assert len(first) == 43
    assert first != second
    assert hash_session_token(first) != hash_session_token(second)


def test_create_persists_hash_only_and_resolves_presented_token(
    db_session: Session,
) -> None:
    user = persist_user(db_session)
    service = build_service(db_session, MutableClock(FIXED_NOW))

    issued = service.create_session(principal_for(user), context())
    stored = db_session.scalar(select(UserSession))

    assert stored is not None
    assert stored.token_hash == hash_session_token(issued.raw_token)
    assert stored.token_hash != issued.raw_token
    assert issued.raw_token not in tuple(str(value) for value in vars(stored).values())
    assert stored.source_ip == "192.0.2.44"
    assert stored.user_agent == "AEGIS-Session-Test/1.0"
    resolved = service.resolve_session(issued.raw_token)
    assert resolved is not None
    assert resolved.principal == principal_for(user)


def test_missing_malformed_and_unknown_tokens_fail_closed(db_session: Session) -> None:
    service = build_service(db_session, MutableClock(FIXED_NOW))

    assert service.resolve_session(None) is None
    assert service.resolve_session("too-short") is None
    assert service.resolve_session("x" * 10_000) is None
    assert service.resolve_session(generate_session_token()) is None


def test_expiry_boundary_is_deterministic(db_session: Session) -> None:
    user = persist_user(db_session)
    clock = MutableClock(FIXED_NOW)
    service = build_service(db_session, clock)
    issued = service.create_session(principal_for(user), context())

    clock.value = issued.expires_at - timedelta(microseconds=1)
    assert service.resolve_session(issued.raw_token) is not None
    clock.value = issued.expires_at
    assert service.resolve_session(issued.raw_token) is None


def test_revoked_session_and_disabled_users_fail_closed(db_session: Session) -> None:
    user = persist_user(db_session)
    service = build_service(db_session, MutableClock(FIXED_NOW))
    issued = service.create_session(principal_for(user), context())

    assert service.revoke_session(issued.raw_token) is True
    assert service.revoke_session(issued.raw_token) is False
    assert service.resolve_session(issued.raw_token) is None

    second = service.create_session(principal_for(user), context())
    user.is_active = False
    user.disabled_at = FIXED_NOW
    db_session.flush()
    assert service.resolve_session(second.raw_token) is None
