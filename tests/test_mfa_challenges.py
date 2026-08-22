"""MFA challenge token, expiry, binding, and single-use service tests."""

from datetime import datetime, timedelta, timezone
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.db.models import MfaChallenge, MfaCredential, User
from aegis.db.repositories import MfaChallengeRepository, MfaCredentialRepository
from aegis.security.authentication_events import AuthenticationRequestContext
from aegis.security.passwords import PasswordService
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.mfa_challenges import (
    MFA_CHALLENGE_TOKEN_BYTES,
    MfaChallengeService,
    MfaChallengeServiceError,
    generate_mfa_challenge_token,
    hash_mfa_challenge_token,
)


FIXED_NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def persist_principal(db_session: Session) -> tuple[User, AuthenticatedPrincipal]:
    user = User(
        username="synthetic.challenge",
        display_name="Synthetic Challenge User",
        email=None,
        password_hash=PasswordService().hash("Synthetic-Challenge-81!"),
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    return user, AuthenticatedPrincipal(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
    )


def build_service(db_session: Session, clock: MutableClock) -> MfaChallengeService:
    return MfaChallengeService(
        MfaChallengeRepository(db_session),
        MfaCredentialRepository(db_session),
        lifetime=timedelta(minutes=5),
        clock=clock,
    )


def context() -> AuthenticationRequestContext:
    return AuthenticationRequestContext(
        request_id=uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        source_ip="192.0.2.90",
        user_agent="AEGIS-Challenge-Test/1.0",
    )


def test_challenge_tokens_have_256_bits_are_distinct_and_hash_safely() -> None:
    first = generate_mfa_challenge_token()
    second = generate_mfa_challenge_token()

    import base64

    assert len(base64.urlsafe_b64decode(first + "=")) == MFA_CHALLENGE_TOKEN_BYTES
    assert first != second
    assert hash_mfa_challenge_token(first) != hash_mfa_challenge_token(second)
    assert hash_mfa_challenge_token(None) is None
    assert hash_mfa_challenge_token("malformed") is None


def test_create_stores_hash_only_and_binds_current_user(db_session: Session) -> None:
    user, principal = persist_principal(db_session)
    service = build_service(db_session, MutableClock(FIXED_NOW))

    issued = service.create_challenge(principal, context())
    stored = db_session.scalar(select(MfaChallenge))

    assert stored is not None
    assert stored.user_id == user.id
    assert stored.token_hash == hash_mfa_challenge_token(issued.raw_token)
    assert stored.token_hash != issued.raw_token
    assert issued.raw_token not in repr(issued)
    assert issued.raw_token not in tuple(str(value) for value in vars(stored).values())
    assert stored.expires_at == FIXED_NOW + timedelta(minutes=5)
    assert stored.source_ip == "192.0.2.90"
    assert stored.user_agent == "AEGIS-Challenge-Test/1.0"


def test_enabled_totp_requirement_ignores_pending_and_disabled(
    db_session: Session,
) -> None:
    user, principal = persist_principal(db_session)
    service = build_service(db_session, MutableClock(FIXED_NOW))
    credential = MfaCredential(
        user_id=user.id,
        encrypted_secret="synthetic-ciphertext",
        encryption_key_id="test-v1",
        enabled=False,
        created_at=FIXED_NOW,
    )
    db_session.add(credential)
    db_session.flush()

    assert service.requires_totp(principal) is False
    credential.enabled = True
    assert service.requires_totp(principal) is True
    credential.enabled = False
    credential.disabled_at = FIXED_NOW
    db_session.flush()
    assert service.requires_totp(principal) is False


def test_expiry_boundary_and_disabled_user_fail_closed(db_session: Session) -> None:
    user, principal = persist_principal(db_session)
    clock = MutableClock(FIXED_NOW)
    service = build_service(db_session, clock)
    issued = service.create_challenge(principal, context())

    clock.value = issued.expires_at - timedelta(microseconds=1)
    assert service.resolve_challenge(issued.raw_token) is not None
    clock.value = issued.expires_at
    assert service.resolve_challenge(issued.raw_token) is None
    clock.value = FIXED_NOW + timedelta(minutes=1)
    user.is_active = False
    user.disabled_at = clock.value
    assert service.resolve_challenge(issued.raw_token) is None


def test_consumption_is_single_use_and_second_consume_fails(db_session: Session) -> None:
    _, principal = persist_principal(db_session)
    clock = MutableClock(FIXED_NOW)
    service = build_service(db_session, clock)
    issued = service.create_challenge(principal, context())
    resolved = service.resolve_challenge(issued.raw_token)
    assert resolved is not None

    service.consume(resolved)

    assert service.resolve_challenge(issued.raw_token) is None
    with pytest.raises(MfaChallengeServiceError):
        service.consume(resolved)


def test_new_challenge_revokes_prior_open_challenge(db_session: Session) -> None:
    _, principal = persist_principal(db_session)
    clock = MutableClock(FIXED_NOW)
    service = build_service(db_session, clock)
    first = service.create_challenge(principal, context())
    clock.value += timedelta(seconds=1)
    second = service.create_challenge(principal, context())

    challenges = db_session.scalars(
        select(MfaChallenge).order_by(MfaChallenge.created_at)
    ).all()
    assert len(challenges) == 2
    assert challenges[0].revoked_at == clock.value
    assert service.resolve_challenge(first.raw_token) is None
    assert service.resolve_challenge(second.raw_token) is not None


def test_revoke_is_idempotent_and_prevents_resolution(db_session: Session) -> None:
    _, principal = persist_principal(db_session)
    service = build_service(db_session, MutableClock(FIXED_NOW))
    issued = service.create_challenge(principal, context())

    assert service.revoke(issued.raw_token) is True
    assert service.revoke(issued.raw_token) is False
    assert service.revoke(generate_mfa_challenge_token()) is False
    assert service.resolve_challenge(issued.raw_token) is None
