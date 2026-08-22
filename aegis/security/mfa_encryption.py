"""Authenticated encryption boundary for recoverable MFA secrets."""

import re

from cryptography.fernet import Fernet, InvalidToken
from pydantic import SecretStr


class MfaKeyConfigurationError(RuntimeError):
    """Raised when the separately configured MFA key is absent or invalid."""


class MfaSecretDecryptionError(RuntimeError):
    """Raised when MFA ciphertext cannot be authenticated and decrypted."""


class MfaSecretCipher:
    """Encrypt TOTP secrets with one configured Fernet key and version ID."""

    def __init__(self, key: SecretStr | str | None, key_id: str) -> None:
        raw_key = key.get_secret_value() if isinstance(key, SecretStr) else key
        if not isinstance(raw_key, str) or not raw_key:
            raise MfaKeyConfigurationError("a valid MFA encryption key is required")
        if not isinstance(key_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", key_id
        ):
            raise MfaKeyConfigurationError("a valid MFA encryption key ID is required")
        try:
            self._fernet = Fernet(raw_key.encode("ascii"))
        except (ValueError, TypeError, UnicodeError) as exc:
            raise MfaKeyConfigurationError(
                "the MFA encryption key must be URL-safe Base64 for exactly 32 bytes"
            ) from None
        self.key_id = key_id

    def encrypt(self, plaintext: str) -> str:
        if not isinstance(plaintext, str) or not plaintext:
            raise ValueError("MFA secret must be non-empty text")
        try:
            return self._fernet.encrypt(plaintext.encode("ascii")).decode("ascii")
        except UnicodeError:
            raise ValueError("MFA secret must be ASCII") from None

    def decrypt(self, ciphertext: str, key_id: str) -> str:
        if key_id != self.key_id or not isinstance(ciphertext, str):
            raise MfaSecretDecryptionError("MFA secret decryption failed")
        try:
            plaintext = self._fernet.decrypt(ciphertext.encode("ascii"))
            return plaintext.decode("ascii")
        except (InvalidToken, ValueError, TypeError, UnicodeError):
            raise MfaSecretDecryptionError("MFA secret decryption failed") from None
