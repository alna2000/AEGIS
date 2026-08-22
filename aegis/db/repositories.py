"""Small repository boundary for authentication persistence."""

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from aegis.db.models import User, UserSession
from aegis.security.identity import InvalidIdentity, normalize_username


class UserRepository:
    """Resolve and persist users without exposing query construction to services."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, user: User) -> User:
        """Add a user to the current transaction."""

        self._session.add(user)
        return user

    def get_by_username(self, username: str) -> User | None:
        """Resolve a user by the canonical form of a supplied username."""

        try:
            canonical_username = normalize_username(username)
        except (InvalidIdentity, TypeError):
            return None

        statement = select(User).where(User.username == canonical_username)
        return self._session.scalar(statement)

    def flush(self) -> None:
        """Flush current changes while leaving transaction ownership to callers."""

        self._session.flush()


class SessionRepository:
    """Persist and resolve hash-only server-side sessions."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, user_session: UserSession) -> UserSession:
        """Add a session to the caller-owned transaction."""

        self._session.add(user_session)
        return user_session

    def get_by_token_hash(self, token_hash: str) -> UserSession | None:
        """Resolve a session and its current user by deterministic token hash."""

        statement = (
            select(UserSession)
            .where(UserSession.token_hash == token_hash)
            .options(joinedload(UserSession.user))
        )
        return self._session.scalar(statement)

    def flush(self) -> None:
        """Flush session changes while leaving commit ownership to the caller."""

        self._session.flush()
