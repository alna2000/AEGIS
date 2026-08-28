"""Provision deterministic synthetic demo data with an explicit local command."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
import sys
import uuid

from sqlalchemy import Engine, create_engine, delete, inspect, select, text
from sqlalchemy.orm import Session

from aegis.core.config import Settings
from aegis.core.migration_config import MigrationSettings
from aegis.db.models import (
    ClearanceLevel, Compartment, Department, IntelligenceRecord,
    IntelligenceRecordStatus, MfaCredential, RecordCompartment,
    RecordDepartment, Role, User, UserCompartment, UserRole,
)
from aegis.db.session import create_session_factory
from aegis.security.passwords import PasswordService
from aegis.security.mfa_encryption import (
    MfaSecretCipher,
    MfaSecretDecryptionError,
)

REQUIRED_REVISION = "20260827_0010"
DEMO_PASSWORD_ENV = "AEGIS_DEMO_PASSWORD"
DEMO_MFA_SECRET_ENV = "AEGIS_DEMO_MFA_SECRET"
CREATED_AT = datetime(2026, 8, 24, 12, tzinfo=timezone.utc)


class DemoBootstrapError(RuntimeError):
    """A controlled refusal safe to display to a local operator."""


@dataclass(frozen=True, slots=True)
class UserSpec:
    id: uuid.UUID
    username: str
    display_name: str
    department: str
    clearance: str
    roles: tuple[str, ...]
    compartments: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RecordSpec:
    id: uuid.UUID
    code: str
    title: str
    summary: str
    content: str
    classification: str
    departments: tuple[str, ...]
    compartments: tuple[str, ...]
    creator: str


@dataclass(frozen=True, slots=True)
class BootstrapReport:
    environment: str
    revision: str
    created: tuple[str, ...]
    existed: tuple[str, ...]
    updated: tuple[str, ...]
    skipped: tuple[str, ...]


USERS = (
    UserSpec(uuid.UUID("40000000-0000-0000-0000-000000000001"), "demo.analyst", "Demo Analyst", "Cyber Intelligence", "SECRET", ("Analyst",), ("NIGHTFALL",)),
    UserSpec(uuid.UUID("40000000-0000-0000-0000-000000000002"), "demo.limited", "Demo Limited Analyst", "Cyber Intelligence", "CONFIDENTIAL", ("Analyst",), ()),
    UserSpec(uuid.UUID("40000000-0000-0000-0000-000000000003"), "demo.auditor", "Demo Security Auditor", "Cyber Intelligence", "CONFIDENTIAL", ("Security Auditor",), ()),
    UserSpec(uuid.UUID("40000000-0000-0000-0000-000000000004"), "demo.admin", "Demo System Administrator", "Cyber Intelligence", "CONFIDENTIAL", ("System Administrator",), ()),
)

RECORDS = (
    RecordSpec(uuid.UUID("41000000-0000-0000-0000-000000000001"), "INT-90001", "Synthetic Network Exposure Brief", "A CONFIDENTIAL Cyber Intelligence example readable by both demo users.", "Synthetic training content describing a fictional network exposure assessment.", "CONFIDENTIAL", ("Cyber Intelligence",), (), "demo.analyst"),
    RecordSpec(uuid.UUID("41000000-0000-0000-0000-000000000002"), "INT-90002", "Synthetic Nightfall Indicator Review", "A SECRET NIGHTFALL example readable by the primary demo analyst.", "Synthetic training content containing fictional NIGHTFALL indicators.", "SECRET", ("Cyber Intelligence",), ("NIGHTFALL",), "demo.limited"),
    RecordSpec(uuid.UUID("41000000-0000-0000-0000-000000000003"), "INT-90003", "Synthetic Top Secret Escalation", "A TOP SECRET example denied to the SECRET primary demo analyst.", "Synthetic training content for a fictional higher-classification scenario.", "TOP SECRET", ("Cyber Intelligence",), ("NIGHTFALL",), "demo.analyst"),
    RecordSpec(uuid.UUID("41000000-0000-0000-0000-000000000004"), "INT-90004", "Synthetic Strategic Assessment", "A department-mismatch example denied to Cyber Intelligence users.", "Synthetic training content owned by the fictional Strategic Analysis department.", "SECRET", ("Strategic Analysis",), (), "demo.analyst"),
    RecordSpec(uuid.UUID("41000000-0000-0000-0000-000000000005"), "INT-90005", "Synthetic Orion Compartment Brief", "A missing-compartment example denied to the NIGHTFALL-only analyst.", "Synthetic training content requiring the fictional ORION compartment.", "SECRET", ("Cyber Intelligence",), ("ORION",), "demo.analyst"),
)


def _environment(settings: Settings) -> str:
    value = settings.environment.strip().lower()
    if value not in {"development", "test"}:
        raise DemoBootstrapError("demo bootstrap is allowed only in development or test environments")
    return value


def _revision(engine: Engine) -> str:
    try:
        with engine.connect() as connection:
            if "alembic_version" not in inspect(connection).get_table_names():
                raise DemoBootstrapError("database has no Alembic revision; run migrations before bootstrapping")
            revisions = tuple(connection.execute(text("SELECT version_num FROM alembic_version")).scalars())
    except DemoBootstrapError:
        raise
    except Exception as error:
        raise DemoBootstrapError("could not verify the configured database revision") from error
    if revisions != (REQUIRED_REVISION,):
        found = ", ".join(sorted(revisions)) if revisions else "none"
        raise DemoBootstrapError(f"database revision must be {REQUIRED_REVISION}; found {found}")
    return revisions[0]


def _references(session: Session) -> dict[str, object]:
    expected = {
        "Analyst": (Role, "30000000-0000-0000-0000-000000000001"),
        "Security Auditor": (Role, "30000000-0000-0000-0000-000000000004"),
        "System Administrator": (Role, "30000000-0000-0000-0000-000000000005"),
        "Cyber Intelligence": (Department, "31000000-0000-0000-0000-000000000001"),
        "Strategic Analysis": (Department, "31000000-0000-0000-0000-000000000003"),
        "CONFIDENTIAL": (ClearanceLevel, "32000000-0000-0000-0000-000000000002"),
        "SECRET": (ClearanceLevel, "32000000-0000-0000-0000-000000000003"),
        "TOP SECRET": (ClearanceLevel, "32000000-0000-0000-0000-000000000004"),
        "NIGHTFALL": (Compartment, "33000000-0000-0000-0000-000000000001"),
        "ORION": (Compartment, "33000000-0000-0000-0000-000000000002"),
    }
    result: dict[str, object] = {}
    for name, (model, expected_id) in expected.items():
        item = session.scalar(select(model).where(model.name == name))
        if item is None or item.id != uuid.UUID(expected_id):
            raise DemoBootstrapError(f"controlled reference data is missing or inconsistent: {name}")
        if hasattr(item, "is_active") and (not item.is_active or item.retired_at is not None):
            raise DemoBootstrapError(f"controlled reference data is inactive: {name}")
        result[name] = item
    return result


def _status(label: str, changed: bool, existed: list[str], updated: list[str]) -> None:
    (updated if changed else existed).append(label)


def _users(session: Session, password: str, refs: dict[str, object], created: list[str], existed: list[str], updated: list[str]) -> dict[str, User]:
    passwords = PasswordService()
    result: dict[str, User] = {}
    for spec in USERS:
        by_id = session.get(User, spec.id)
        by_name = session.scalar(select(User).where(User.username == spec.username))
        if by_id is not None and by_id.username != spec.username:
            raise DemoBootstrapError(f"demo user ID collision: {spec.id}")
        if by_name is not None and by_name.id != spec.id:
            raise DemoBootstrapError(f"demo username collision: {spec.username}")
        user = by_id or by_name
        if user is None:
            user = User(id=spec.id, username=spec.username, display_name=spec.display_name, email=None, password_hash=passwords.hash(password), is_active=True, disabled_at=None, department_id=refs[spec.department].id, clearance_level_id=refs[spec.clearance].id, created_at=CREATED_AT, updated_at=CREATED_AT)
            session.add(user)
            session.flush()
            created.append(f"user:{spec.username}")
            changed = False
        else:
            changed = False
            values = {"display_name": spec.display_name, "email": None, "is_active": True, "disabled_at": None, "department_id": refs[spec.department].id, "clearance_level_id": refs[spec.clearance].id}
            for field, value in values.items():
                if getattr(user, field) != value:
                    setattr(user, field, value)
                    changed = True
            if not passwords.verify(password, user.password_hash):
                user.password_hash = passwords.hash(password)
                changed = True
            _status(f"user:{spec.username}", changed, existed, updated)
        expected_roles = {refs[name].id for name in spec.roles}
        current_roles = set(session.scalars(select(UserRole.role_id).where(UserRole.user_id == user.id)))
        expected_compartments = {refs[name].id for name in spec.compartments}
        current_compartments = set(session.scalars(select(UserCompartment.compartment_id).where(UserCompartment.user_id == user.id)))
        if current_roles != expected_roles or current_compartments != expected_compartments:
            session.execute(delete(UserRole).where(UserRole.user_id == user.id))
            session.execute(delete(UserCompartment).where(UserCompartment.user_id == user.id))
            session.add_all(UserRole(user_id=user.id, role_id=value, assigned_at=CREATED_AT) for value in expected_roles)
            session.add_all(UserCompartment(user_id=user.id, compartment_id=value, assigned_at=CREATED_AT) for value in expected_compartments)
            label = f"user:{spec.username}"
            if label in existed:
                existed.remove(label)
                updated.append(label)
        result[spec.username] = user
    session.flush()
    return result


def _records(session: Session, refs: dict[str, object], users: dict[str, User], created: list[str], existed: list[str], updated: list[str]) -> None:
    for spec in RECORDS:
        by_id = session.get(IntelligenceRecord, spec.id)
        by_code = session.scalar(select(IntelligenceRecord).where(IntelligenceRecord.record_code == spec.code))
        if by_id is not None and by_id.record_code != spec.code:
            raise DemoBootstrapError(f"demo record ID collision: {spec.id}")
        if by_code is not None and by_code.id != spec.id:
            raise DemoBootstrapError(f"demo record code collision: {spec.code}")
        record = by_id or by_code
        values = {"title": spec.title, "summary": spec.summary, "content": spec.content, "classification_level_id": refs[spec.classification].id, "created_by_user_id": users[spec.creator].id, "status": IntelligenceRecordStatus.ACTIVE.value, "retired_at": None}
        if record is None:
            record = IntelligenceRecord(id=spec.id, record_code=spec.code, created_at=CREATED_AT, updated_at=CREATED_AT, **values)
            session.add(record)
            session.flush()
            created.append(f"record:{spec.code}")
        else:
            changed = False
            for field, value in values.items():
                if getattr(record, field) != value:
                    setattr(record, field, value)
                    changed = True
            _status(f"record:{spec.code}", changed, existed, updated)
        expected_departments = {refs[name].id for name in spec.departments}
        current_departments = set(session.scalars(select(RecordDepartment.department_id).where(RecordDepartment.record_id == record.id)))
        expected_compartments = {refs[name].id for name in spec.compartments}
        current_compartments = set(session.scalars(select(RecordCompartment.compartment_id).where(RecordCompartment.record_id == record.id)))
        if current_departments != expected_departments or current_compartments != expected_compartments:
            session.execute(delete(RecordDepartment).where(RecordDepartment.record_id == record.id))
            session.execute(delete(RecordCompartment).where(RecordCompartment.record_id == record.id))
            session.add_all(RecordDepartment(record_id=record.id, department_id=value) for value in expected_departments)
            session.add_all(RecordCompartment(record_id=record.id, compartment_id=value) for value in expected_compartments)
            label = f"record:{spec.code}"
            if label in existed:
                existed.remove(label)
                updated.append(label)
    session.flush()


def _mfa(
    session: Session,
    settings: Settings,
    user: User,
    secret: str,
    created: list[str],
    existed: list[str],
    updated: list[str],
) -> None:
    cipher = MfaSecretCipher(
        settings.mfa_encryption_key,
        settings.mfa_encryption_key_id,
    )
    credential = session.scalar(
        select(MfaCredential).where(
            MfaCredential.user_id == user.id,
            MfaCredential.disabled_at.is_(None),
        )
    )
    label = f"mfa:{user.username}"
    if credential is None:
        session.add(
            MfaCredential(
                id=uuid.UUID("42000000-0000-0000-0000-000000000001"),
                user_id=user.id,
                encrypted_secret=cipher.encrypt(secret),
                encryption_key_id=cipher.key_id,
                enabled=True,
                created_at=CREATED_AT,
            )
        )
        created.append(label)
        return
    try:
        unchanged = (
            credential.enabled
            and credential.encryption_key_id == cipher.key_id
            and cipher.decrypt(
                credential.encrypted_secret,
                credential.encryption_key_id,
            )
            == secret
        )
    except MfaSecretDecryptionError:
        unchanged = False
    if unchanged:
        existed.append(label)
        return
    credential.encrypted_secret = cipher.encrypt(secret)
    credential.encryption_key_id = cipher.key_id
    credential.enabled = True
    credential.last_used_at = None
    credential.last_accepted_counter = None
    updated.append(label)


def bootstrap_demo(
    settings: Settings,
    password: str,
    *,
    mfa_secret: str | None = None,
    engine: Engine | None = None,
) -> BootstrapReport:
    """Provision the fixture only after local-environment and exact-schema checks."""
    environment = _environment(settings)
    PasswordService().hash(password)
    owns_engine = engine is None
    database_engine = engine or create_engine(
        MigrationSettings().migration_database_url.get_secret_value(),
        pool_pre_ping=True,
    )
    try:
        revision = _revision(database_engine)
        created: list[str] = []
        existed: list[str] = []
        updated: list[str] = []
        session_factory = create_session_factory(database_engine)
        with session_factory.begin() as session:
            refs = _references(session)
            users = _users(session, password, refs, created, existed, updated)
            _records(session, refs, users, created, existed, updated)
            if mfa_secret is not None:
                _mfa(
                    session,
                    settings,
                    users["demo.analyst"],
                    mfa_secret,
                    created,
                    existed,
                    updated,
                )
        return BootstrapReport(environment, revision, tuple(created), tuple(existed), tuple(updated), ())
    finally:
        if owns_engine:
            database_engine.dispose()


def _print(report: BootstrapReport) -> None:
    print("LOCAL SYNTHETIC DEMO DATA ONLY")
    print(f"AEGIS synthetic demo bootstrap complete ({report.environment}, {report.revision}).")
    for name in ("created", "existed", "updated", "skipped"):
        items = getattr(report, name)
        label = "already existed" if name == "existed" else name
        print(f"{label}: {len(items)}" + (f" [{', '.join(items)}]" if items else ""))
    print("primary login: demo.analyst (password read from AEGIS_DEMO_PASSWORD)")


def main() -> int:
    try:
        settings = Settings()
        _environment(settings)
        password = os.environ.get(DEMO_PASSWORD_ENV)
        if password is None:
            raise DemoBootstrapError(f"{DEMO_PASSWORD_ENV} must be set for this command")
        mfa_secret = os.environ.get(DEMO_MFA_SECRET_ENV)
        if mfa_secret is None:
            raise DemoBootstrapError(
                f"{DEMO_MFA_SECRET_ENV} must be set for this command"
            )
        _print(bootstrap_demo(settings, password, mfa_secret=mfa_secret))
        return 0
    except Exception as error:
        message = str(error) if isinstance(error, DemoBootstrapError) else "demo bootstrap failed; no demo data was committed"
        print(f"AEGIS demo bootstrap refused: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
