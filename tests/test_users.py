"""User identity normalization and persistence tests."""

from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aegis.db.models import User
from aegis.security.identity import InvalidIdentity, normalize_email, normalize_username
from aegis.security.passwords import PasswordService


SYNTHETIC_PASSWORD = "Synthetic-Orion-84!"


def make_user(
    passwords: PasswordService,
    *,
    username: str = "Synthetic.Analyst",
    email: str | None = "Analyst@Example.Test",
    is_active: bool = True,
    disabled_at: datetime | None = None,
) -> User:
    return User(
        username=username,
        display_name="Synthetic Analyst",
        email=email,
        password_hash=passwords.hash(SYNTHETIC_PASSWORD),
        is_active=is_active,
        disabled_at=disabled_at,
    )


def test_identity_normalization_is_explicit_and_deterministic() -> None:
    assert normalize_username("  Synthetic.Analyst  ") == "synthetic.analyst"
    assert normalize_email("  Analyst@Example.Test ") == "analyst@example.test"
    assert normalize_email(None) is None

    with pytest.raises(InvalidIdentity):
        normalize_username("Synthetıc")
    with pytest.raises(InvalidIdentity):
        normalize_email("synthetic example.test")


def test_valid_synthetic_user_persists_only_a_password_hash(
    db_session: Session,
) -> None:
    passwords = PasswordService()
    user = make_user(passwords)

    db_session.add(user)
    db_session.flush()

    persisted_hash = db_session.scalar(
        select(User.password_hash).where(User.id == user.id)
    )
    column_names = {column["name"] for column in inspect(db_session.bind).get_columns("users")}

    assert user.username == "synthetic.analyst"
    assert user.email == "analyst@example.test"
    assert user.created_at.tzinfo is not None
    assert user.updated_at.tzinfo is not None
    assert user.is_usable_for_authentication is True
    assert persisted_hash != SYNTHETIC_PASSWORD
    assert "password" not in column_names
    assert "password_hash" in column_names


def test_case_equivalent_username_is_rejected_by_unique_constraint(
    db_session: Session,
) -> None:
    passwords = PasswordService()
    db_session.add(make_user(passwords, username="Synthetic.Analyst"))
    db_session.flush()

    db_session.add(
        make_user(
            passwords,
            username="SYNTHETIC.ANALYST",
            email="second@example.test",
        )
    )

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_email_is_unique_when_present_and_multiple_nulls_are_allowed(
    db_session: Session,
) -> None:
    passwords = PasswordService()
    db_session.add_all(
        [
            make_user(passwords, username="synthetic.one", email=None),
            make_user(passwords, username="synthetic.two", email=None),
        ]
    )
    db_session.flush()

    db_session.add(
        make_user(
            passwords,
            username="synthetic.three",
            email="ANALYST@example.test",
        )
    )
    db_session.flush()
    db_session.add(
        make_user(
            passwords,
            username="synthetic.four",
            email="analyst@EXAMPLE.TEST",
        )
    )

    with pytest.raises(IntegrityError):
        db_session.flush()


def test_inactive_and_disabled_account_state_is_not_usable() -> None:
    passwords = PasswordService()
    inactive_user = make_user(passwords, is_active=False)
    disabled_user = make_user(
        passwords,
        username="synthetic.disabled",
        email="disabled@example.test",
        is_active=False,
        disabled_at=datetime.now(timezone.utc),
    )

    assert inactive_user.is_usable_for_authentication is False
    assert disabled_user.is_usable_for_authentication is False
