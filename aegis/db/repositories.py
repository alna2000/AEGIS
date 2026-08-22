"""Small repository boundary for authentication persistence."""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session, contains_eager, joinedload

from aegis.db.models import MfaChallenge, MfaCredential, User, UserSession
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


class MfaCredentialRepository:
    """Persist and lock the current non-disabled TOTP credential."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, credential: MfaCredential) -> MfaCredential:
        self._session.add(credential)
        return credential

    def get_current_totp(
        self,
        user_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> MfaCredential | None:
        statement = select(MfaCredential).where(
            MfaCredential.user_id == user_id,
            MfaCredential.method_type == "TOTP",
            MfaCredential.disabled_at.is_(None),
        )
        if for_update:
            statement = statement.with_for_update()
        return self._session.scalar(statement)

    def flush(self) -> None:
        self._session.flush()


class MfaChallengeRepository:
    """Persist and lock short-lived hash-only MFA challenges."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, challenge: MfaChallenge) -> MfaChallenge:
        self._session.add(challenge)
        return challenge

    def get_by_token_hash_for_update(self, token_hash: str) -> MfaChallenge | None:
        statement = (
            select(MfaChallenge)
            .join(MfaChallenge.user)
            .where(MfaChallenge.token_hash == token_hash)
            .options(contains_eager(MfaChallenge.user))
            .with_for_update(of=(MfaChallenge, User))
        )
        return self._session.scalar(statement)

    def get_open_for_user_for_update(self, user_id: uuid.UUID) -> list[MfaChallenge]:
        statement = (
            select(MfaChallenge)
            .where(
                MfaChallenge.user_id == user_id,
                MfaChallenge.consumed_at.is_(None),
                MfaChallenge.revoked_at.is_(None),
            )
            .with_for_update()
        )
        return list(self._session.scalars(statement))

    def flush(self) -> None:
        self._session.flush()
