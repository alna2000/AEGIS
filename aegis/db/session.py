"""SQLAlchemy engine and session construction."""

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from aegis.core.config import Settings


def create_database_engine(settings: Settings) -> Engine:
    """Create the application engine from environment-backed settings."""

    return create_engine(settings.database_url, pool_pre_ping=True)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a transaction-oriented session factory for an engine."""

    return sessionmaker(bind=engine, expire_on_commit=False)
