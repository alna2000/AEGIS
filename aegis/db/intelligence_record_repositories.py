"""Read-only persistence boundary for intelligence-record policy facts."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload, load_only, selectinload

from aegis.db.models import (
    IntelligenceRecord,
    RecordCompartment,
    RecordDepartment,
)


@dataclass(frozen=True, slots=True)
class ClearancePolicyFacts:
    """One loaded classification reference without record content."""

    id: uuid.UUID
    name: str
    rank: int


@dataclass(frozen=True, slots=True)
class ActiveReferencePolicyFacts:
    """One lifecycle-aware department or compartment reference."""

    id: uuid.UUID
    name: str
    is_active: bool
    retired_at: datetime | None


@dataclass(frozen=True, slots=True)
class RecordReferencePolicyFacts:
    """One normalized record relationship and its referenced state."""

    record_id: uuid.UUID
    reference_id: uuid.UUID
    reference: ActiveReferencePolicyFacts | None


@dataclass(frozen=True, slots=True)
class IntelligenceRecordPolicyFacts:
    """Restricted database facts required for central authorization policy."""

    id: uuid.UUID
    record_code: str
    status: str
    classification_level_id: uuid.UUID
    classification: ClearancePolicyFacts | None
    created_by_user_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    retired_at: datetime | None
    department_relationships: tuple[RecordReferencePolicyFacts, ...]
    compartment_relationships: tuple[RecordReferencePolicyFacts, ...]


class IntelligenceRecordPolicyRepository:
    """Load record policy facts without deciding access or owning commits."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_policy_record_by_id(
        self, record_id: uuid.UUID
    ) -> IntelligenceRecordPolicyFacts | None:
        statement = (
            select(IntelligenceRecord)
            .where(IntelligenceRecord.id == record_id)
            .options(
                load_only(
                    IntelligenceRecord.id,
                    IntelligenceRecord.record_code,
                    IntelligenceRecord.status,
                    IntelligenceRecord.classification_level_id,
                    IntelligenceRecord.created_by_user_id,
                    IntelligenceRecord.created_at,
                    IntelligenceRecord.updated_at,
                    IntelligenceRecord.retired_at,
                    raiseload=True,
                ),
                joinedload(IntelligenceRecord.classification_level),
                selectinload(
                    IntelligenceRecord.department_assignments
                ).joinedload(RecordDepartment.department),
                selectinload(
                    IntelligenceRecord.compartment_assignments
                ).joinedload(RecordCompartment.compartment),
            )
        )
        record = self._session.scalar(statement)
        if record is None:
            return None

        classification = record.classification_level
        classification_facts = (
            None
            if classification is None
            else ClearancePolicyFacts(
                id=classification.id,
                name=classification.name,
                rank=classification.rank,
            )
        )
        return IntelligenceRecordPolicyFacts(
            id=record.id,
            record_code=record.record_code,
            status=record.status,
            classification_level_id=record.classification_level_id,
            classification=classification_facts,
            created_by_user_id=record.created_by_user_id,
            created_at=record.created_at,
            updated_at=record.updated_at,
            retired_at=record.retired_at,
            department_relationships=tuple(
                self._relationship_facts(
                    assignment.record_id,
                    assignment.department_id,
                    assignment.department,
                )
                for assignment in record.department_assignments
            ),
            compartment_relationships=tuple(
                self._relationship_facts(
                    assignment.record_id,
                    assignment.compartment_id,
                    assignment.compartment,
                )
                for assignment in record.compartment_assignments
            ),
        )

    @staticmethod
    def _relationship_facts(
        record_id: uuid.UUID,
        reference_id: uuid.UUID,
        reference: object,
    ) -> RecordReferencePolicyFacts:
        if reference is None:
            converted = None
        else:
            converted = ActiveReferencePolicyFacts(
                id=reference.id,
                name=reference.name,
                is_active=reference.is_active,
                retired_at=reference.retired_at,
            )
        return RecordReferencePolicyFacts(
            record_id=record_id,
            reference_id=reference_id,
            reference=converted,
        )
