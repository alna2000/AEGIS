"""Password hashing and verifier-upgrade tests."""

from argon2 import PasswordHasher
from argon2.low_level import Type
import pytest

from aegis.security.passwords import InvalidPassword, PasswordService


SYNTHETIC_PASSWORD = "Synthetic-Raven-42!"


def test_new_password_requires_at_least_eight_unicode_characters() -> None:
    passwords = PasswordService()
    rejected_password = "1234567"

    with pytest.raises(InvalidPassword) as exc_info:
        passwords.hash(rejected_password)

    assert rejected_password not in str(exc_info.value)
    assert passwords.verify("12345678", passwords.hash("12345678")) is True


def test_new_password_accepts_unicode_and_passphrases_within_limit() -> None:
    passwords = PasswordService()
    unicode_password = "密码安全测试值！"
    passphrase = "a long synthetic passphrase with spaces " * 8

    unicode_hash = passwords.hash(unicode_password)
    passphrase_hash = passwords.hash(passphrase)

    assert passwords.verify(unicode_password, unicode_hash) is True
    assert passwords.verify(passphrase, passphrase_hash) is True


def test_malformed_unicode_fails_closed_without_plaintext_exposure() -> None:
    passwords = PasswordService()
    malformed_password = "synthetic-\ud800-password"
    valid_hash = passwords.hash(SYNTHETIC_PASSWORD)

    with pytest.raises(InvalidPassword) as exc_info:
        passwords.hash(malformed_password)

    assert malformed_password not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert passwords.verify(malformed_password, valid_hash) is False
    result = passwords.verify_and_update(malformed_password, valid_hash)
    assert result.valid is False
    assert result.replacement_hash is None


def test_hash_is_salted_verifier_and_not_plaintext() -> None:
    passwords = PasswordService()

    first_hash = passwords.hash(SYNTHETIC_PASSWORD)
    second_hash = passwords.hash(SYNTHETIC_PASSWORD)

    assert first_hash.startswith("$argon2id$")
    assert first_hash != SYNTHETIC_PASSWORD
    assert second_hash != first_hash


def test_correct_password_verifies_and_wrong_password_fails() -> None:
    passwords = PasswordService()
    password_hash = passwords.hash(SYNTHETIC_PASSWORD)

    assert passwords.verify(SYNTHETIC_PASSWORD, password_hash) is True
    assert passwords.verify("Synthetic-Wrong-Password!", password_hash) is False


def test_malformed_or_unsupported_verifier_fails_safely() -> None:
    passwords = PasswordService()

    assert passwords.verify(SYNTHETIC_PASSWORD, "not-a-password-verifier") is False
    assert passwords.verify(SYNTHETIC_PASSWORD, "$unsupported$v=1$data") is False


def test_outdated_valid_verifier_is_upgraded() -> None:
    legacy_hasher = PasswordHasher(
        time_cost=1,
        memory_cost=1024,
        parallelism=1,
        hash_len=16,
        salt_len=8,
        type=Type.ID,
    )
    legacy_hash = legacy_hasher.hash(SYNTHETIC_PASSWORD)
    passwords = PasswordService()

    result = passwords.verify_and_update(SYNTHETIC_PASSWORD, legacy_hash)

    assert result.valid is True
    assert result.replacement_hash is not None
    assert result.replacement_hash != legacy_hash
    assert passwords.verify(SYNTHETIC_PASSWORD, result.replacement_hash) is True
    assert passwords.verify_and_update(
        SYNTHETIC_PASSWORD, result.replacement_hash
    ).replacement_hash is None


def test_short_legacy_password_remains_verifiable_during_rehash() -> None:
    legacy_password = "seven77"
    legacy_hasher = PasswordHasher(
        time_cost=1,
        memory_cost=1024,
        parallelism=1,
        hash_len=16,
        salt_len=8,
        type=Type.ID,
    )
    passwords = PasswordService()
    legacy_hash = legacy_hasher.hash(legacy_password)

    result = passwords.verify_and_update(legacy_password, legacy_hash)

    assert result.valid is True
    assert result.replacement_hash is not None
    assert passwords.verify(legacy_password, result.replacement_hash) is True


def test_invalid_password_never_triggers_rehash() -> None:
    passwords = PasswordService()
    password_hash = passwords.hash(SYNTHETIC_PASSWORD)

    result = passwords.verify_and_update("Synthetic-Wrong-Password!", password_hash)

    assert result.valid is False
    assert result.replacement_hash is None
