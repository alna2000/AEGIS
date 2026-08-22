"""Argon2id password hashing and verifier-upgrade support."""

from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type


class InvalidPassword(ValueError):
    """Raised when a new password cannot be processed safely."""


MIN_PASSWORD_CHARACTERS = 8
MAX_PASSWORD_UTF8_BYTES = 1024


@dataclass(frozen=True, slots=True)
class PasswordVerification:
    """Controlled password verification result with an optional upgraded hash."""

    valid: bool
    replacement_hash: str | None = None


class PasswordService:
    """Hash and verify passwords with upgradeable Argon2id parameters."""

    def __init__(self, hasher: PasswordHasher | None = None) -> None:
        self._hasher = hasher or PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )

    @staticmethod
    def _utf8_length(password: str) -> int:
        if not isinstance(password, str):
            raise InvalidPassword("password must be a string")
        try:
            return len(password.encode("utf-8"))
        except UnicodeEncodeError:
            raise InvalidPassword("password must be valid UTF-8 encodable text") from None

    @classmethod
    def _validate_new_password(cls, password: str) -> None:
        encoded_length = cls._utf8_length(password)
        if len(password) < MIN_PASSWORD_CHARACTERS:
            raise InvalidPassword(
                f"password must contain at least {MIN_PASSWORD_CHARACTERS} characters"
            )
        if encoded_length > MAX_PASSWORD_UTF8_BYTES:
            raise InvalidPassword(
                f"password must not exceed {MAX_PASSWORD_UTF8_BYTES} UTF-8 bytes"
            )

    def hash(self, password: str) -> str:
        """Return a salted one-way verifier for a new password."""

        self._validate_new_password(password)
        return self._hasher.hash(password)

    def verify(self, password: str, password_hash: str) -> bool:
        """Return false for wrong passwords and invalid or unsupported verifiers."""

        if not isinstance(password, str) or not isinstance(password_hash, str):
            return False
        try:
            encoded_length = self._utf8_length(password)
        except InvalidPassword:
            return False
        if not password or encoded_length > MAX_PASSWORD_UTF8_BYTES:
            return False
        try:
            return self._hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError, ValueError):
            return False

    def verify_and_update(
        self, password: str, password_hash: str
    ) -> PasswordVerification:
        """Verify a password and replace valid verifiers using outdated parameters."""

        if not self.verify(password, password_hash):
            return PasswordVerification(valid=False)
        try:
            needs_rehash = self._hasher.check_needs_rehash(password_hash)
        except (InvalidHashError, ValueError):
            return PasswordVerification(valid=False)
        # A parameter-only upgrade must not apply today's new-password minimum to
        # a valid legacy credential. Verification already enforced encoding and
        # the unchanged resource-safety maximum before this replacement is made.
        replacement = self._hasher.hash(password) if needs_rehash else None
        return PasswordVerification(valid=True, replacement_hash=replacement)
