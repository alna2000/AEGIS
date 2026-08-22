"""Application configuration loaded from environment variables."""

from functools import lru_cache
from typing import Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings used by the local AEGIS application."""

    app_name: str = "AEGIS"
    environment: str = "development"
    debug: bool = True
    database_url: str = "postgresql+psycopg://aegis_app@localhost:5432/aegis"
    session_lifetime_seconds: int = Field(default=8 * 60 * 60, ge=300, le=24 * 60 * 60)
    session_cookie_name: str = Field(
        default="aegis_session",
        pattern=r"^[A-Za-z0-9_-]{1,64}$",
    )
    session_cookie_secure: bool = False
    mfa_challenge_lifetime_seconds: int = Field(default=5 * 60, ge=60, le=10 * 60)
    mfa_challenge_cookie_name: str = Field(
        default="aegis_mfa_challenge",
        pattern=r"^[A-Za-z0-9_-]{1,64}$",
    )
    mfa_encryption_key: SecretStr | None = Field(default=None, repr=False)
    mfa_encryption_key_id: str = Field(
        default="v1",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="AEGIS_",
        extra="ignore",
    )

    @model_validator(mode="after")
    def _require_secure_cookie_outside_local_environments(self) -> Self:
        environment = self.environment.strip().lower()
        if environment not in {"development", "test"} and not self.session_cookie_secure:
            raise ValueError(
                "secure session cookies are required outside development and test"
            )
        if self.mfa_challenge_cookie_name == self.session_cookie_name:
            raise ValueError("session and MFA challenge cookie names must differ")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return one settings instance per application process."""

    return Settings()
