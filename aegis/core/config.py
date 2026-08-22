"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings used by the local AEGIS application."""

    app_name: str = "AEGIS"
    environment: str = "development"
    debug: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="AEGIS_",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return one settings instance per application process."""

    return Settings()
