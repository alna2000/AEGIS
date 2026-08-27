"""HTTP access to explicitly authorized synthetic intelligence records."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from aegis.api.dependencies import (
    get_availability_abuse_control,
    get_intelligence_record_collection_read_service,
    get_intelligence_record_read_service,
    get_session_service,
)
from aegis.core.config import Settings, get_settings
from aegis.security.abuse import AbuseDecision, AbuseDecisionStatus
from aegis.security.authentication_events import AuthenticationRequestContext
from aegis.security.availability_abuse import AvailabilityAbuseControl
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
) -> list[IntelligenceRecordCollectionEntryResponse]:
    """Return metadata only for records allowed for SEARCH and READ."""

    context = _request_context(request)
    _enforce_record_abuse(availability.admit_collection_outer(context))
    resolved = _resolve_session(request, settings, sessions)
    _enforce_record_abuse(
        availability.admit_collection_session(resolved.session_id)
    )
    decision, leases = availability.acquire_record_work(
        resolved.session_id, collection=True
    )
    _enforce_record_abuse(decision)
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
) -> IntelligenceRecordResponse:
    """Return one record only after current centralized authorization allows it."""

    context = _request_context(request)
    _enforce_record_abuse(availability.admit_detail_outer(context))
    resolved = _resolve_session(request, settings, sessions)
    _enforce_record_abuse(availability.admit_detail_session(resolved.session_id))
    decision, leases = availability.acquire_record_work(
        resolved.session_id, collection=False
    )
    _enforce_record_abuse(decision)
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_RECORD_NOT_FOUND,
        )
    if result.outcome is IntelligenceRecordReadOutcome.UNAVAILABLE:
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


def _enforce_record_abuse(decision: AbuseDecision) -> None:
    if decision.status is AbuseDecisionStatus.ALLOW:
        return
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
