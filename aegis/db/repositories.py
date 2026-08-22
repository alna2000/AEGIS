"""Small repository boundary for authentication persistence."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.db.models import User
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
