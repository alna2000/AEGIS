"""Encrypted TOTP enrollment, verification, replay, and lifecycle tests."""

from datetime import datetime, timedelta, timezone
import logging
import uuid

from cryptography.fernet import Fernet
import pyotp
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.core.config import Settings
from aegis.db.models import MfaCredential, User
from aegis.db.repositories import MfaCredentialRepository
from aegis.security.audit_sinks import LoggingAuthenticationAuditSink
from aegis.security.authentication_events import (
    AuthenticationAuditEvent,
    AuthenticationEventType,
    AuthenticationRequestContext,
    AuthenticationReasonCode,
)
from aegis.security.mfa_encryption import (
    MfaKeyConfigurationError,
    MfaSecretCipher,
    MfaSecretDecryptionError,
)
from aegis.security.passwords import PasswordService
from aegis.security.totp import TOTP_INTERVAL_SECONDS, TotpService
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.mfa import MfaEnrollmentConflict, MfaService


FIXED_NOW = datetime(2026, 8, 22, 12, 0, 5, tzinfo=timezone.utc)
SYNTHETIC_PASSWORD = "Synthetic-Mfa-91!"


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class CollectingAuditSink:
    def __init__(self) -> None:
        self.events: list[AuthenticationAuditEvent] = []

    def record(self, event: AuthenticationAuditEvent) -> None:
        self.events.append(event)


def persist_user(db_session: Session) -> tuple[User, AuthenticatedPrincipal]:
    user = User(
        username="synthetic.mfa.user",
        display_name="Synthetic MFA User",
        email=None,
        password_hash=PasswordService().hash(SYNTHETIC_PASSWORD),
        is_active=True,
        disabled_at=None,
    )
    db_session.add(user)
    db_session.flush()
    return user, AuthenticatedPrincipal(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
    )


def context() -> AuthenticationRequestContext:
    return AuthenticationRequestContext(
        request_id=uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    )


def build_service(
    db_session: Session,
    clock: MutableClock,
) -> tuple[MfaService, CollectingAuditSink, MfaSecretCipher]:
    sink = CollectingAuditSink()
    cipher = MfaSecretCipher(Fernet.generate_key().decode("ascii"), "test-v1")
    return (
        MfaService(
            MfaCredentialRepository(db_session),
            cipher,
            TotpService(),
            sink,
            clock=clock,
        ),
        sink,
        cipher,
    )


def code_for(secret: str, at: datetime) -> str:
    return pyotp.TOTP(secret, digits=6, interval=TOTP_INTERVAL_SECONDS).at(at)


def wrong_code_for(secret: str, at: datetime) -> str:
    valid = code_for(secret, at)
    replacement = "0" if valid[0] != "0" else "1"
    return f"{replacement}{valid[1:]}"


def test_authenticated_encryption_round_trip_is_randomized_and_secret_safe() -> None:
    key = Fernet.generate_key().decode("ascii")
    cipher = MfaSecretCipher(key, "test-v1")
    secret = pyotp.random_base32()

    first = cipher.encrypt(secret)
    second = cipher.encrypt(secret)

    assert first != secret
    assert first != second
    assert cipher.decrypt(first, "test-v1") == secret
    assert key not in first


def test_tampered_ciphertext_and_wrong_key_fail_closed() -> None:
    cipher = MfaSecretCipher(Fernet.generate_key().decode("ascii"), "test-v1")
    wrong_cipher = MfaSecretCipher(
        Fernet.generate_key().decode("ascii"), "test-v1"
    )
    ciphertext = cipher.encrypt(pyotp.random_base32())
    replacement = "A" if ciphertext[-2] != "A" else "B"
    tampered = f"{ciphertext[:-2]}{replacement}{ciphertext[-1]}"

    with pytest.raises(MfaSecretDecryptionError):
        cipher.decrypt(tampered, "test-v1")
    with pytest.raises(MfaSecretDecryptionError):
        wrong_cipher.decrypt(ciphertext, "test-v1")
    with pytest.raises(MfaSecretDecryptionError):
        cipher.decrypt(ciphertext, "unknown-key")


@pytest.mark.parametrize("key", [None, "", "not-a-valid-fernet-key"])
def test_missing_or_invalid_key_configuration_fails_safely(key: str | None) -> None:
    with pytest.raises(MfaKeyConfigurationError) as exc_info:
        MfaSecretCipher(key, "test-v1")

    assert not key or key not in str(exc_info.value)


def test_settings_keep_mfa_key_optional_and_secret_represented_until_use() -> None:
    settings = Settings(_env_file=None)
    with pytest.raises(MfaKeyConfigurationError):
        MfaSecretCipher(
            settings.mfa_encryption_key,
            settings.mfa_encryption_key_id,
        )

    key = Fernet.generate_key().decode("ascii")
    configured = Settings(mfa_encryption_key=key, _env_file=None)
    assert key not in repr(configured)
    cipher = MfaSecretCipher(
        configured.mfa_encryption_key,
        configured.mfa_encryption_key_id,
    )
    assert cipher.key_id == "v1"


def test_totp_generation_uri_encoding_and_deterministic_window() -> None:
    totp = TotpService()
    secret = totp.generate_secret()
    account_name = "synthetic analyst+one@example.test"
    uri = totp.provisioning_uri(secret, account_name)

    assert secret not in repr(totp)
    assert uri.startswith("otpauth://totp/AEGIS:")
    assert "synthetic%20analyst%2Bone%40example.test" in uri
    assert "issuer=AEGIS" in uri
    assert totp.matching_counter(secret, code_for(secret, FIXED_NOW), FIXED_NOW) is not None
    assert totp.matching_counter(
        secret, code_for(secret, FIXED_NOW - timedelta(seconds=30)), FIXED_NOW
    ) is not None
    assert totp.matching_counter(
        secret, code_for(secret, FIXED_NOW + timedelta(seconds=30)), FIXED_NOW
    ) is not None
    assert totp.matching_counter(
        secret, code_for(secret, FIXED_NOW - timedelta(seconds=60)), FIXED_NOW
    ) is None
    assert totp.matching_counter(
        secret, code_for(secret, FIXED_NOW + timedelta(seconds=60)), FIXED_NOW
    ) is None


@pytest.mark.parametrize("code", [None, 123456, "", "12345", "1234567", "12a456", "１２３４５６"])
def test_malformed_and_wrong_totp_codes_fail_safely(code: object) -> None:
    totp = TotpService()
    secret = totp.generate_secret()

    assert totp.matching_counter(secret, code, FIXED_NOW) is None
    assert totp.matching_counter(secret, wrong_code_for(secret, FIXED_NOW), FIXED_NOW) is None


def test_enrollment_persists_only_encrypted_pending_secret(
    db_session: Session,
) -> None:
    _, principal = persist_user(db_session)
    service, _, cipher = build_service(db_session, MutableClock(FIXED_NOW))

    material = service.begin_enrollment(principal)
    stored = db_session.scalar(select(MfaCredential))

    assert stored is not None
    assert stored.enabled is False
    assert stored.disabled_at is None
    assert stored.encrypted_secret != material.secret
    assert cipher.decrypt(stored.encrypted_secret, stored.encryption_key_id) == material.secret
    assert material.secret not in tuple(str(value) for value in vars(stored).values())
    assert material.secret not in repr(stored)
    assert material.secret not in repr(material)
    assert material.provisioning_uri not in repr(material)


def test_invalid_confirmation_does_not_enable_and_valid_confirmation_does(
    db_session: Session,
) -> None:
    _, principal = persist_user(db_session)
    service, sink, _ = build_service(db_session, MutableClock(FIXED_NOW))
    material = service.begin_enrollment(principal)

    assert service.confirm_enrollment(
        principal, wrong_code_for(material.secret, FIXED_NOW), context()
    ) is False
    stored = db_session.scalar(select(MfaCredential))
    assert stored is not None and stored.enabled is False
    assert stored.last_accepted_counter is None
    assert service.confirm_enrollment(
        principal, code_for(material.secret, FIXED_NOW), context()
    ) is True
    assert stored.enabled is True
    assert stored.last_accepted_counter is not None
    assert sink.events[0].event_type is AuthenticationEventType.TOTP_VERIFICATION_FAILURE
    assert sink.events[1].event_type is AuthenticationEventType.TOTP_VERIFICATION_SUCCESS


def test_pending_credential_fails_normal_verification_and_duplicate_enrollment(
    db_session: Session,
) -> None:
    _, principal = persist_user(db_session)
    service, sink, _ = build_service(db_session, MutableClock(FIXED_NOW))
    material = service.begin_enrollment(principal)

    assert service.verify(
        principal, code_for(material.secret, FIXED_NOW), context()
    ) is False
    assert sink.events[-1].reason_code is AuthenticationReasonCode.MFA_CREDENTIAL_UNUSABLE
    with pytest.raises(MfaEnrollmentConflict):
        service.begin_enrollment(principal)


def test_accepted_counter_cannot_replay_and_later_counter_succeeds(
    db_session: Session,
) -> None:
    _, principal = persist_user(db_session)
    clock = MutableClock(FIXED_NOW)
    service, sink, _ = build_service(db_session, clock)
    material = service.begin_enrollment(principal)
    current_code = code_for(material.secret, clock.value)
    assert service.confirm_enrollment(principal, current_code, context()) is True

    assert service.verify(principal, current_code, context()) is False
    assert sink.events[-1].reason_code is AuthenticationReasonCode.TOTP_REPLAYED
    clock.value += timedelta(seconds=30)
    assert service.verify(
        principal, code_for(material.secret, clock.value), context()
    ) is True


def test_failed_attempt_does_not_consume_a_later_valid_counter(
    db_session: Session,
) -> None:
    _, principal = persist_user(db_session)
    clock = MutableClock(FIXED_NOW)
    service, _, _ = build_service(db_session, clock)
    material = service.begin_enrollment(principal)
    assert service.confirm_enrollment(
        principal, code_for(material.secret, clock.value), context()
    ) is True

    clock.value += timedelta(seconds=30)
    assert service.verify(
        principal, wrong_code_for(material.secret, clock.value), context()
    ) is False
    assert service.verify(
        principal, code_for(material.secret, clock.value), context()
    ) is True


def test_disable_preserves_metadata_denies_verification_and_allows_fresh_pending(
    db_session: Session,
) -> None:
    _, principal = persist_user(db_session)
    clock = MutableClock(FIXED_NOW)
    service, _, _ = build_service(db_session, clock)
    material = service.begin_enrollment(principal)
    assert service.confirm_enrollment(
        principal, code_for(material.secret, clock.value), context()
    ) is True
    original = db_session.scalar(select(MfaCredential))
    assert original is not None
    original_ciphertext = original.encrypted_secret

    clock.value += timedelta(seconds=30)
    assert service.disable(principal) is True
    assert original.enabled is False
    assert original.disabled_at == clock.value
    assert original.encrypted_secret == original_ciphertext
    assert original.last_used_at is not None
    assert service.verify(
        principal, code_for(material.secret, clock.value), context()
    ) is False

    replacement = service.begin_enrollment(principal)
    assert replacement.secret != material.secret
    assert len(db_session.scalars(select(MfaCredential)).all()) == 2


def test_audit_events_and_logs_never_contain_secret_or_entered_code(
    db_session: Session,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _, principal = persist_user(db_session)
    clock = MutableClock(FIXED_NOW)
    cipher = MfaSecretCipher(Fernet.generate_key().decode("ascii"), "test-v1")
    logger = logging.getLogger("aegis.mfa.test")
    service = MfaService(
        MfaCredentialRepository(db_session),
        cipher,
        TotpService(),
        LoggingAuthenticationAuditSink(logger),
        clock=clock,
    )
    material = service.begin_enrollment(principal)
    code = code_for(material.secret, clock.value)

    with caplog.at_level(logging.INFO, logger=logger.name):
        assert service.confirm_enrollment(principal, code, context()) is True

    output = caplog.text
    assert material.secret not in output
    assert code not in output
