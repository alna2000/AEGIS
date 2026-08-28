"""HTTP access to explicitly authorized synthetic intelligence records."""

import logging

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from aegis.api.dependencies import (
    get_audit_service,
    get_availability_abuse_control,
    get_db_session,
    get_intelligence_record_collection_read_service,
    get_intelligence_record_read_service,
    get_session_service,
)
from aegis.core.config import Settings, get_settings
from aegis.security.abuse import AbuseDecision, AbuseDecisionReason, AbuseDecisionStatus
from aegis.security.authentication_events import AuthenticationRequestContext
from aegis.security.availability_abuse import AvailabilityAbuseControl
from aegis.security.security_events import (
    SecurityActorType,
    SecurityEventCode,
    SecurityEventDraft,
    SecurityEventReason,
    SecurityTargetType,
)
from aegis.services.audit import AuditService
from aegis.services.intelligence_records import (
    IntelligenceRecordCollectionReadOutcome,
    IntelligenceRecordCollectionReadResult,
    IntelligenceRecordCollectionReadService,
    IntelligenceRecordReadOutcome,
    IntelligenceRecordReadResult,
    IntelligenceRecordReadService,
)
from aegis.services.sessions import ResolvedSession, SessionService
import uuid


router = APIRouter(prefix="/records", tags=["intelligence-records"])
_LOGGER = logging.getLogger(__name__)
_RECORD_NOT_FOUND = "Record not found"
_RECORD_SERVICE_UNAVAILABLE = "Classified record service unavailable"


class IntelligenceRecordResponse(BaseModel):
    """The intentionally limited representation exposed to an authorized reader."""

    record_code: str
    title: str
    summary: str | None
    content: str
    classification: str


class IntelligenceRecordCollectionEntryResponse(BaseModel):
    """The metadata exposed for one authorized collection candidate."""

    record_code: str
    title: str
    classification: str


@router.get("", response_model=list[IntelligenceRecordCollectionEntryResponse])
def list_intelligence_records(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
    availability: Annotated[
        AvailabilityAbuseControl, Depends(get_availability_abuse_control)
    ],
    records: Annotated[
        IntelligenceRecordCollectionReadService,
        Depends(get_intelligence_record_collection_read_service),
    ],
    audit: Annotated[AuditService, Depends(get_audit_service)],
    database_session: Annotated[Session, Depends(get_db_session)],
) -> list[IntelligenceRecordCollectionEntryResponse]:
    """Return metadata only for records allowed for SEARCH and READ."""

    context = _request_context(request)
    _enforce_record_abuse(
        availability.admit_collection_outer(context), audit, database_session,
        context.request_id,
    )
    resolved = _resolve_session(request, settings, sessions)
    _enforce_record_abuse(
        availability.admit_collection_session(resolved.session_id), audit,
        database_session, context.request_id, resolved.principal.user_id,
    )
    decision, leases = availability.acquire_record_work(
        resolved.session_id, collection=True
    )
    _enforce_record_abuse(
        decision, audit, database_session, context.request_id,
        resolved.principal.user_id,
    )
    if leases is None:
        raise RuntimeError("allowed collection work lacked leases")
    try:
        with leases:
            result = records.read(resolved.principal)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_RECORD_SERVICE_UNAVAILABLE,
        ) from None
    if not isinstance(result, IntelligenceRecordCollectionReadResult):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_RECORD_SERVICE_UNAVAILABLE,
        )
    if (
        result.outcome
        is IntelligenceRecordCollectionReadOutcome.AUTHENTICATION_REQUIRED
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    if result.outcome is IntelligenceRecordCollectionReadOutcome.UNAVAILABLE:
        _commit_record_event(
            audit,
            database_session,
            SecurityEventDraft(
                event_code=SecurityEventCode.AUTHORIZATION_ERROR,
                actor_type=SecurityActorType.USER,
                actor_user_id=resolved.principal.user_id,
                request_id=context.request_id,
                target_type=SecurityTargetType.SECURITY_SUBSYSTEM,
                reason_code=SecurityEventReason.POLICY_EVALUATION_ERROR,
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_RECORD_SERVICE_UNAVAILABLE,
        )
    if (
        result.outcome is not IntelligenceRecordCollectionReadOutcome.AUTHORIZED
        or result.entries is None
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_RECORD_SERVICE_UNAVAILABLE,
        )
    try:
        audit.stage(
            SecurityEventDraft(
                event_code=SecurityEventCode.RESOURCE_COLLECTION_READ,
                actor_type=SecurityActorType.USER,
                actor_user_id=resolved.principal.user_id,
                request_id=context.request_id,
                target_type=SecurityTargetType.ENDPOINT,
            )
        )
        database_session.commit()
    except Exception:
        database_session.rollback()
        _LOGGER.error(
            "mandatory record audit persistence failed request_id=%s subsystem=audit",
            context.request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_RECORD_SERVICE_UNAVAILABLE,
        ) from None
    return [
        IntelligenceRecordCollectionEntryResponse(
            record_code=entry.record_code,
            title=entry.title,
            classification=entry.classification,
        )
        for entry in result.entries
    ]


@router.get("/{record_code}", response_model=IntelligenceRecordResponse)
def read_intelligence_record(
    record_code: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
    availability: Annotated[
        AvailabilityAbuseControl, Depends(get_availability_abuse_control)
    ],
    records: Annotated[
        IntelligenceRecordReadService,
        Depends(get_intelligence_record_read_service),
    ],
    audit: Annotated[AuditService, Depends(get_audit_service)],
    database_session: Annotated[Session, Depends(get_db_session)],
) -> IntelligenceRecordResponse:
    """Return one record only after current centralized authorization allows it."""

    context = _request_context(request)
    _enforce_record_abuse(
        availability.admit_detail_outer(context), audit, database_session,
        context.request_id,
    )
    resolved = _resolve_session(request, settings, sessions)
    _enforce_record_abuse(
        availability.admit_detail_session(resolved.session_id), audit,
        database_session, context.request_id, resolved.principal.user_id,
    )
    decision, leases = availability.acquire_record_work(
        resolved.session_id, collection=False
    )
    _enforce_record_abuse(
        decision, audit, database_session, context.request_id,
        resolved.principal.user_id,
    )
    if leases is None:
        raise RuntimeError("allowed detail work lacked leases")
    try:
        with leases:
            result = records.read(resolved.principal, record_code)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_RECORD_SERVICE_UNAVAILABLE,
        ) from None
    if not isinstance(result, IntelligenceRecordReadResult):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_RECORD_SERVICE_UNAVAILABLE,
        )
    if result.outcome is IntelligenceRecordReadOutcome.AUTHENTICATION_REQUIRED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    if result.outcome is IntelligenceRecordReadOutcome.INACCESSIBLE:
        _commit_record_event(
            audit, database_session,
            SecurityEventDraft(
                event_code=SecurityEventCode.AUTHORIZATION_DENIED,
                actor_type=SecurityActorType.USER,
                actor_user_id=resolved.principal.user_id,
                request_id=context.request_id,
                target_type=SecurityTargetType.INTELLIGENCE_RECORD,
                reason_code=SecurityEventReason.POLICY_DENIED,
            ),
            SecurityEventDraft(
                event_code=SecurityEventCode.RESOURCE_READ_INACCESSIBLE,
                actor_type=SecurityActorType.USER,
                actor_user_id=resolved.principal.user_id,
                request_id=context.request_id,
                target_type=SecurityTargetType.INTELLIGENCE_RECORD,
                reason_code=SecurityEventReason.RESOURCE_INACCESSIBLE,
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_RECORD_NOT_FOUND,
        )
    if result.outcome is IntelligenceRecordReadOutcome.UNAVAILABLE:
        _commit_record_event(
            audit, database_session,
            SecurityEventDraft(
                event_code=SecurityEventCode.AUTHORIZATION_ERROR,
                actor_type=SecurityActorType.USER,
                actor_user_id=resolved.principal.user_id,
                request_id=context.request_id,
                target_type=SecurityTargetType.SECURITY_SUBSYSTEM,
                reason_code=(
                    SecurityEventReason.DATABASE_ERROR
                    if result.failure_reason is not None
                    and result.failure_reason.value.endswith("LOAD_ERROR")
                    else SecurityEventReason.POLICY_EVALUATION_ERROR
                ),
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_RECORD_SERVICE_UNAVAILABLE,
        )
    if (
        result.outcome is not IntelligenceRecordReadOutcome.AUTHORIZED
        or result.record is None
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_RECORD_SERVICE_UNAVAILABLE,
        )
    if not isinstance(result.record_id, uuid.UUID):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_RECORD_SERVICE_UNAVAILABLE,
        )
    _commit_record_event(
        audit, database_session,
        SecurityEventDraft(
            event_code=SecurityEventCode.AUTHORIZATION_ALLOWED,
            actor_type=SecurityActorType.USER,
            actor_user_id=resolved.principal.user_id,
            request_id=context.request_id,
            target_type=SecurityTargetType.INTELLIGENCE_RECORD,
            target_id=result.record_id,
        ),
        SecurityEventDraft(
            event_code=SecurityEventCode.RESOURCE_READ_SUCCEEDED,
            actor_type=SecurityActorType.USER,
            actor_user_id=resolved.principal.user_id,
            request_id=context.request_id,
            target_type=SecurityTargetType.INTELLIGENCE_RECORD,
            target_id=result.record_id,
        ),
    )
    return IntelligenceRecordResponse(
        record_code=result.record.record_code,
        title=result.record.title,
        summary=result.record.summary,
        content=result.record.content,
        classification=result.record.classification,
    )


def _request_context(request: Request) -> AuthenticationRequestContext:
    return AuthenticationRequestContext(
        request_id=uuid.uuid4(),
        source_ip=request.client.host if request.client is not None else None,
    )


def _resolve_session(
    request: Request, settings: Settings, sessions: SessionService
) -> ResolvedSession:
    try:
        resolved = sessions.resolve_session(
            request.cookies.get(settings.session_cookie_name)
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable",
        ) from None
    if resolved is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return resolved


def _enforce_record_abuse(
    decision: AbuseDecision,
    audit: AuditService,
    database_session: Session,
    request_id: uuid.UUID,
    actor_user_id: uuid.UUID | None = None,
) -> None:
    if decision.status is AbuseDecisionStatus.ALLOW:
        return
    reason = SecurityEventReason(decision.reason.value)
    code = (
        SecurityEventCode.CONCURRENCY_SATURATED
        if decision.reason is AbuseDecisionReason.CONCURRENCY
        else SecurityEventCode.ABUSE_STORE_UNAVAILABLE
        if decision.status is AbuseDecisionStatus.UNAVAILABLE
        else SecurityEventCode.ABUSE_ADMISSION_DENIED
    )
    _commit_record_event(
        audit, database_session,
        SecurityEventDraft(
            event_code=code,
            actor_type=(
                SecurityActorType.USER
                if actor_user_id is not None
                else SecurityActorType.ANONYMOUS
            ),
            actor_user_id=actor_user_id,
            request_id=request_id,
            target_type=SecurityTargetType.ENDPOINT,
            reason_code=reason,
        ),
    )
    if decision.status is AbuseDecisionStatus.LIMITED:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Record request temporarily unavailable",
            headers={
                "Cache-Control": "no-store",
                "Retry-After": str(decision.retry_after_seconds),
            },
        )
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=_RECORD_SERVICE_UNAVAILABLE,
        headers={"Cache-Control": "no-store"},
    )


def _commit_record_event(
    audit: AuditService,
    database_session: Session,
    *drafts: SecurityEventDraft,
) -> None:
    try:
        for draft in drafts:
            audit.stage(draft)
        database_session.commit()
    except Exception:
        database_session.rollback()
        _LOGGER.error(
            "mandatory record audit persistence failed request_id=%s subsystem=audit",
            drafts[0].request_id if drafts else None,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_RECORD_SERVICE_UNAVAILABLE,
        ) from None
