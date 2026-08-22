"""Password-authentication service without HTTP or authorization behavior."""

import uuid
from dataclasses import dataclass

from aegis.db.repositories import UserRepository
from aegis.security.passwords import PasswordService


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Verified identity only; this object grants no authorization."""

    user_id: uuid.UUID
    username: str
    display_name: str


class AuthenticationService:
    """Resolve a usable account and verify its stored password verifier."""

    def __init__(
        self,
        users: UserRepository,
        passwords: PasswordService,
    ) -> None:
        self._users = users
        self._passwords = passwords

    def authenticate(
        self, username: str, password: str
    ) -> AuthenticatedPrincipal | None:
        """Return a verified identity or fail closed with no public error detail."""

        # TODO(Phase 2 Part 2): the HTTP login boundary must perform equivalent
        # password work for nonexistent or unusable accounts so account state is
        # not exposed through observably cheaper processing.
        user = self._users.get_by_username(username)
        if user is None or not user.is_usable_for_authentication:
            return None

        verification = self._passwords.verify_and_update(password, user.password_hash)
        if not verification.valid:
            return None

        if verification.replacement_hash is not None:
            user.password_hash = verification.replacement_hash
            self._users.flush()

        return AuthenticatedPrincipal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
        )
