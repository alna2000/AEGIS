"""Synthetic intelligence-record persistence and integrity tests."""

from datetime import datetime, timedelta, timezone
import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aegis.db.models import (
    ClearanceLevel,
    Compartment,
    Department,
    IntelligenceRecord,
    IntelligenceRecordStatus,
    RecordCompartment,
    RecordDepartment,
    User,
)


FIXED_NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
SECRET_ID = uuid.UUID("32000000-0000-0000-0000-000000000003")
CYBER_ID = uuid.UUID("31000000-0000-0000-0000-000000000001")
NIGHTFALL_ID = uuid.UUID("33000000-0000-0000-0000-000000000001")


def persist_dependencies(
    db_session: Session,
) -> tuple[ClearanceLevel, Department, Compartment, User]:
    clearance = ClearanceLevel(id=SECRET_ID, name="SECRET", rank=30)
    department = Department(
        id=CYBER_ID,
        name="Cyber Intelligence",
        is_active=True,
    )
    compartment = Compartment(
        id=NIGHTFALL_ID,
        name="NIGHTFALL",
        is_active=True,
    )
    creator = User(
        username="synthetic.record.creator",
        display_name="Synthetic Record Creator",
        password_hash="synthetic-nonempty-verifier",
        is_active=True,
    )
    db_session.add_all([clearance, department, compartment, creator])
    db_session.flush()
    return clearance, department, compartment, creator


def build_record(
    clearance: ClearanceLevel,
    creator: User,
    *,
    code: str = "INT-00482",
    status: IntelligenceRecordStatus = IntelligenceRecordStatus.ACTIVE,
    retired_at: datetime | None = None,
) -> IntelligenceRecord:
    return IntelligenceRecord(
        record_code=code,
        title="Synthetic NIGHTFALL Assessment",
        summary="Synthetic summary for authorization testing.",
        content="Entirely synthetic intelligence content.",
        classification_level=clearance,
        creator=creator,
        status=status,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        retired_at=retired_at,
    )


@pytest.mark.parametrize(
    ("status", "retired_at"),
    [
        (IntelligenceRecordStatus.DRAFT, None),
        (IntelligenceRecordStatus.ACTIVE, None),
        (IntelligenceRecordStatus.RETIRED, FIXED_NOW + timedelta(hours=1)),
    ],
)
def test_valid_record_persistence_and_controlled_lifecycle(
    db_session: Session,
    status: IntelligenceRecordStatus,
    retired_at: datetime | None,
) -> None:
    clearance, department, compartment, creator = persist_dependencies(db_session)
    record = build_record(
        clearance,
        creator,
        status=status,
        retired_at=retired_at,
    )
    record.department_assignments.append(RecordDepartment(department=department))
    record.compartment_assignments.append(
        RecordCompartment(compartment=compartment)
    )
    db_session.add(record)
    db_session.flush()

    assert isinstance(record.id, uuid.UUID)
    assert record.record_code == "INT-00482"
    assert record.classification_level_id == SECRET_ID
    assert record.created_by_user_id == creator.id
    assert record.status == status.value
    assert record.department_assignments[0].department_id == CYBER_ID
    assert record.compartment_assignments[0].compartment_id == NIGHTFALL_ID


@pytest.mark.parametrize(
    "record_code",
    ["int-00482", "INT-482", "INT-0048A", "EXT-00482", "INT-000001"],
)
def test_malformed_or_noncanonical_record_code_is_rejected(
    db_session: Session, record_code: str
) -> None:
    clearance, _, _, creator = persist_dependencies(db_session)
    with pytest.raises(ValueError):
        build_record(clearance, creator, code=record_code)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", "x" * 161),
        ("summary", "x" * 1001),
        ("content", "x" * 10001),
    ],
)
def test_oversized_record_content_fields_are_rejected(
    db_session: Session, field: str, value: str
) -> None:
    clearance, _, _, creator = persist_dependencies(db_session)
    record = build_record(clearance, creator)
    with pytest.raises(ValueError):
        setattr(record, field, value)


def test_unique_record_code_is_enforced(db_session: Session) -> None:
    clearance, _, _, creator = persist_dependencies(db_session)
    db_session.add_all(
        [
            build_record(clearance, creator),
            build_record(clearance, creator),
        ]
    )
    with pytest.raises(IntegrityError):
        db_session.flush()


@pytest.mark.parametrize(
    ("status", "retired_at", "updated_at"),
    [
        (IntelligenceRecordStatus.ACTIVE, FIXED_NOW, FIXED_NOW),
        (IntelligenceRecordStatus.DRAFT, FIXED_NOW, FIXED_NOW),
        (IntelligenceRecordStatus.RETIRED, None, FIXED_NOW),
        (
            IntelligenceRecordStatus.RETIRED,
            FIXED_NOW - timedelta(seconds=1),
            FIXED_NOW,
        ),
        (
            IntelligenceRecordStatus.ACTIVE,
            None,
            FIXED_NOW - timedelta(seconds=1),
        ),
    ],
)
def test_invalid_retirement_or_timestamp_state_is_rejected(
    db_session: Session,
    status: IntelligenceRecordStatus,
    retired_at: datetime | None,
    updated_at: datetime,
) -> None:
    clearance, _, _, creator = persist_dependencies(db_session)
    record = build_record(
        clearance,
        creator,
        status=status,
        retired_at=retired_at,
    )
    record.updated_at = updated_at
    db_session.add(record)
    with pytest.raises(IntegrityError):
        db_session.flush()


def test_invalid_lifecycle_value_is_rejected(db_session: Session) -> None:
    clearance, _, _, creator = persist_dependencies(db_session)
    record = build_record(clearance, creator)
    with pytest.raises(ValueError):
        record.status = "PUBLISHED"


@pytest.mark.parametrize("missing_field", ["classification", "creator"])
def test_classification_and_creator_are_required(
    db_session: Session, missing_field: str
) -> None:
    clearance, _, _, creator = persist_dependencies(db_session)
    record = build_record(clearance, creator)
    if missing_field == "classification":
        record.classification_level = None  # type: ignore[assignment]
        record.classification_level_id = None  # type: ignore[assignment]
    else:
        record.creator = None  # type: ignore[assignment]
        record.created_by_user_id = None  # type: ignore[assignment]
    db_session.add(record)
    with pytest.raises(IntegrityError):
        db_session.flush()


@pytest.mark.parametrize("relationship", ["department", "compartment"])
def test_record_policy_relationship_pairs_are_unique(
    db_session: Session, relationship: str
) -> None:
    clearance, department, compartment, creator = persist_dependencies(db_session)
    record = build_record(clearance, creator)
    db_session.add(record)
    db_session.flush()
    if relationship == "department":
        db_session.add_all(
            [
                RecordDepartment(record_id=record.id, department_id=department.id),
                RecordDepartment(record_id=record.id, department_id=department.id),
            ]
        )
    else:
        db_session.add_all(
            [
                RecordCompartment(
                    record_id=record.id,
                    compartment_id=compartment.id,
                ),
                RecordCompartment(
                    record_id=record.id,
                    compartment_id=compartment.id,
                ),
            ]
        )
    with pytest.raises(IntegrityError):
        db_session.flush()
