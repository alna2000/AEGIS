"""Central standards-based TOTP generation and code matching."""

from datetime import datetime, timezone
from urllib.parse import urlparse

import pyotp


TOTP_DIGITS = 6
TOTP_INTERVAL_SECONDS = 30
TOTP_VALID_WINDOW = 1
TOTP_SECRET_CHARACTERS = 32


class TotpService:
    """Use SHA-1, six digits, 30-second steps, and a narrow +/-1 window."""

    issuer = "AEGIS"

    def generate_secret(self) -> str:
        return pyotp.random_base32(length=TOTP_SECRET_CHARACTERS)

    def provisioning_uri(self, secret: str, account_name: str) -> str:
        if not isinstance(account_name, str) or not account_name.strip():
            raise ValueError("TOTP account name is required")
        uri = self._totp(secret).provisioning_uri(
            name=account_name.strip(),
            issuer_name=self.issuer,
        )
        if urlparse(uri).scheme != "otpauth":
            raise RuntimeError("TOTP provisioning URI generation failed")
        return uri

    def matching_counter(self, secret: str, code: object, at: datetime) -> int | None:
        if (
            not isinstance(code, str)
            or len(code) != TOTP_DIGITS
            or not code.isascii()
            or not code.isdecimal()
        ):
            return None
        timestamp = self._timestamp(at)
        current_counter = int(timestamp) // TOTP_INTERVAL_SECONDS
        totp = self._totp(secret)
        for offset in range(-TOTP_VALID_WINDOW, TOTP_VALID_WINDOW + 1):
            counter = current_counter + offset
            if counter >= 0 and totp.verify(
                code,
                for_time=counter * TOTP_INTERVAL_SECONDS,
                valid_window=0,
            ):
                return counter
        return None

    @staticmethod
    def _totp(secret: str) -> pyotp.TOTP:
        return pyotp.TOTP(
            secret,
            digits=TOTP_DIGITS,
            interval=TOTP_INTERVAL_SECONDS,
        )

    @staticmethod
    def _timestamp(at: datetime) -> float:
        if not isinstance(at, datetime) or at.tzinfo is None:
            raise ValueError("TOTP verification time must be timezone-aware")
        return at.astimezone(timezone.utc).timestamp()
