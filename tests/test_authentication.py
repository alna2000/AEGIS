"""Authentication service boundary tests."""

from datetime import datetime, timezone

from argon2 import PasswordHasher
from argon2.low_level import Type
from sqlalchemy.orm import Session

from aegis.db.models import User
from aegis.db.repositories import UserRepository
from aegis.security.passwords import PasswordService
from aegis.services.authentication import AuthenticationService


SYNTHETIC_PASSWORD = "Synthetic-Nightfall-73!"


def build_service(db_session: Session) -> tuple[UserRepository, AuthenticationService]:
    users = UserRepository(db_session)
    return users, AuthenticationService(users, PasswordService())


def persist_user(
    users: UserRepository,
    password_hash: str,
    *,
    is_active: bool = True,
    disabled_at: datetime | None = None,
) -> User:
    user = User(
        username="Synthetic.Operator",
        display_name="Synthetic Operator",
        email="operator@example.test",
        password_hash=password_hash,
        is_active=is_active,
        disabled_at=disabled_at,
    )
    users.add(user)
    users.flush()
    return user


def test_active_user_with_correct_password_authenticates(db_session: Session) -> None:
    users, authentication = build_service(db_session)
    password_hash = PasswordService().hash(SYNTHETIC_PASSWORD)
    user = persist_user(users, password_hash)

    principal = authentication.authenticate("SYNTHETIC.OPERATOR", SYNTHETIC_PASSWORD)

    assert principal is not None
    assert principal.user_id == user.id
    assert principal.username == "synthetic.operator"


def test_incorrect_password_and_nonexistent_user_fail_closed(
    db_session: Session,
) -> None:
    users, authentication = build_service(db_session)
    persist_user(users, PasswordService().hash(SYNTHETIC_PASSWORD))

    assert authentication.authenticate(
        "synthetic.operator", "Synthetic-Wrong-Password!"
    ) is None
    assert authentication.authenticate("synthetic.missing", SYNTHETIC_PASSWORD) is None
    assert authentication.authenticate("invalid username", SYNTHETIC_PASSWORD) is None


def test_disabled_user_never_becomes_a_principal(db_session: Session) -> None:
    users, authentication = build_service(db_session)
    persist_user(
        users,
        PasswordService().hash(SYNTHETIC_PASSWORD),
        is_active=False,
        disabled_at=datetime.now(timezone.utc),
    )

    assert authentication.authenticate(
        "synthetic.operator", SYNTHETIC_PASSWORD
    ) is None


def test_malformed_stored_password_hash_fails_closed(db_session: Session) -> None:
    users, authentication = build_service(db_session)
    persist_user(users, "malformed-stored-verifier")

    assert authentication.authenticate(
        "synthetic.operator", SYNTHETIC_PASSWORD
    ) is None


def test_successful_authentication_upgrades_outdated_hash(
    db_session: Session,
) -> None:
    legacy_hasher = PasswordHasher(
        time_cost=1,
        memory_cost=1024,
        parallelism=1,
        hash_len=16,
        salt_len=8,
        type=Type.ID,
    )
    users, authentication = build_service(db_session)
    user = persist_user(users, legacy_hasher.hash(SYNTHETIC_PASSWORD))
    original_hash = user.password_hash

    principal = authentication.authenticate("synthetic.operator", SYNTHETIC_PASSWORD)

    assert principal is not None
    assert user.password_hash != original_hash
    assert PasswordService().verify(SYNTHETIC_PASSWORD, user.password_hash) is True
