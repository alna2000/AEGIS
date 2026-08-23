"""Read-only persistence boundary for intelligence-record policy facts."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload, load_only, selectinload

from aegis.db.models import (
    ClearanceLevel,
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


@dataclass(frozen=True, slots=True)
class IntelligenceRecordContent:
    """Restricted post-authorization content projection for one record."""

    id: uuid.UUID
    record_code: str
    title: str
    summary: str | None
    content: str
    classification: str
    status: str


class IntelligenceRecordPolicyRepository:
    """Load record policy facts without deciding access or owning commits."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_policy_record_by_id(
        self, record_id: uuid.UUID
    ) -> IntelligenceRecordPolicyFacts | None:
        return self._get_policy_record(IntelligenceRecord.id == record_id)

    def get_policy_record_by_code(
        self, record_code: str
    ) -> IntelligenceRecordPolicyFacts | None:
        """Load content-free policy facts selected by exact record code."""

        return self._get_policy_record(
            IntelligenceRecord.record_code == record_code
        )

    def _get_policy_record(
        self, criterion: object
    ) -> IntelligenceRecordPolicyFacts | None:
        statement = (
            select(IntelligenceRecord)
            .where(criterion)
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


class IntelligenceRecordContentRepository:
    """Load an explicit record representation only after caller authorization."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_content_record_by_id(
        self, record_id: uuid.UUID
    ) -> IntelligenceRecordContent | None:
        statement = (
            select(
                IntelligenceRecord.id.label("id"),
                IntelligenceRecord.record_code.label("record_code"),
                IntelligenceRecord.title.label("title"),
                IntelligenceRecord.summary.label("summary"),
                IntelligenceRecord.content.label("content"),
                ClearanceLevel.name.label("classification"),
                IntelligenceRecord.status.label("status"),
            )
            .join(
                ClearanceLevel,
                ClearanceLevel.id == IntelligenceRecord.classification_level_id,
            )
            .where(IntelligenceRecord.id == record_id)
        )
        row = self._session.execute(statement).mappings().one_or_none()
        if row is None:
            return None
        return IntelligenceRecordContent(
            id=row["id"],
            record_code=row["record_code"],
            title=row["title"],
            summary=row["summary"],
            content=row["content"],
            classification=row["classification"],
            status=row["status"],
        )
