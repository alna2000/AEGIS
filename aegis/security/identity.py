"""Deterministic canonicalization for authentication identifiers."""

import re


class InvalidIdentity(ValueError):
    """Raised when an identity value cannot be represented safely."""


_USERNAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}\Z")


def _require_ascii(value: str, field_name: str) -> None:
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise InvalidIdentity(f"{field_name} must contain ASCII characters only") from exc


def normalize_username(value: str) -> str:
    """Trim and ASCII-lowercase a username used for identity comparison."""

    if not isinstance(value, str):
        raise TypeError("username must be a string")
    normalized = value.strip()
    _require_ascii(normalized, "username")
    if not _USERNAME_PATTERN.fullmatch(normalized):
        raise InvalidIdentity(
            "username must be 3-64 ASCII letters, digits, dots, underscores, or hyphens"
        )
    return normalized.lower()


def normalize_display_name(value: str) -> str:
    """Trim a synthetic display name without using it for identity comparison."""

    if not isinstance(value, str):
        raise TypeError("display_name must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > 120:
        raise InvalidIdentity("display_name must be between 1 and 120 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise InvalidIdentity("display_name must not contain control characters")
    return normalized


def normalize_email(value: str | None) -> str | None:
    """Trim and ASCII-lowercase an optional email address as one identity value."""

    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("email must be a string or None")
    normalized = value.strip()
    _require_ascii(normalized, "email")
    if len(normalized) > 254 or normalized.count("@") != 1:
        raise InvalidIdentity("email must be a valid ASCII address")
    local_part, domain = normalized.split("@", maxsplit=1)
    if not local_part or not domain or any(character.isspace() for character in normalized):
        raise InvalidIdentity("email must be a valid ASCII address")
    return normalized.lower()
