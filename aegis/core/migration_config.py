"""Migration/setup-only configuration kept outside normal runtime settings."""

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class MigrationSettings(BaseSettings):
    """Load the explicit privileged local setup connection without fallback."""

    migration_database_url: SecretStr

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="AEGIS_",
        extra="ignore",
    )
