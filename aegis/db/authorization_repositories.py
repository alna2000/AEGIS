"""Read-only persistence boundary for current authorization subject facts."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload, selectinload

from aegis.db.models import User, UserCompartment, UserRole


class AuthorizationSubjectRepository:
    """Load one user's current normalized authorization relationships."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_user_id(self, user_id: uuid.UUID) -> User | None:
        statement = (
            select(User)
            .where(User.id == user_id)
            .options(
                joinedload(User.department),
                joinedload(User.clearance_level),
                selectinload(User.role_assignments).joinedload(UserRole.role),
                selectinload(User.compartment_assignments).joinedload(
                    UserCompartment.compartment
                ),
            )
        )
        return self._session.scalar(statement)
