"""Database types that preserve AEGIS security invariants across dialects."""

from datetime import datetime, timezone

from sqlalchemy import DateTime
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator[datetime]):
    """Store aware UTC datetimes and restore UTC metadata when a dialect drops it."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(
        self,
        value: datetime | None,
        dialect: Dialect,
    ) -> datetime | None:
        if value is None:
            return None
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError("timezone-aware datetime required")
        return value.astimezone(timezone.utc)

    def process_result_value(
        self,
        value: datetime | None,
        dialect: Dialect,
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
