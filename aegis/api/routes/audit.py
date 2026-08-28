"""Backend-authorized bounded security audit queries."""

from __future__ import annotations

import uuid
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from aegis.api.dependencies import (
    get_audit_query_service,
    get_authorization_subject_service,
    get_current_principal,
    get_detection_service,
)
from aegis.security.authorization import (
    AuthorizationAction,
    AuthorizationOutcome,
    AuthorizationResourceType,
    ResourcePolicy,
    authorize,
)
from aegis.security.security_events import (
    SecurityEventCode,
    SecurityEventOutcome,
    SecurityEventSeverity,
    SecurityTargetType,
)
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.audit_queries import (
    AuditEventProjection,
    AuditQueryService,
    InvalidAuditQuery,
)
from aegis.services.authorization import AuthorizationSubjectService
from aegis.services.detections import DetectionService


router = APIRouter(prefix="/audit", tags=["security-audit"])


class AuditEventResponse(BaseModel):
    id: uuid.UUID
    occurred_at: datetime
    event_code: str
    outcome: str
    severity: str
    actor_type: str
    actor_user_id: uuid.UUID | None
    subject_user_id: uuid.UUID | None
    target_type: str | None
    target_id: uuid.UUID | None
    action: str
    reason_code: str | None
    request_id: uuid.UUID | None


class AuditEventPageResponse(BaseModel):
    events: list[AuditEventResponse]
    next_cursor: str | None


class DetectionFindingResponse(BaseModel):
    finding_code: str
    severity: str
    window_start: datetime
    window_end: datetime
    subject_user_id: uuid.UUID | None
    event_count: int
    supporting_event_ids: list[uuid.UUID]


class DetectionFindingListResponse(BaseModel):
    findings: list[DetectionFindingResponse]


@router.get("/events", response_model=AuditEventPageResponse)
def list_audit_events(
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    subjects: Annotated[
        AuthorizationSubjectService, Depends(get_authorization_subject_service)
    ],
    queries: Annotated[AuditQueryService, Depends(get_audit_query_service)],
    start: datetime | None = None,
    end: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(min_length=1, max_length=256)] = None,
    event_code: SecurityEventCode | None = None,
    outcome: SecurityEventOutcome | None = None,
    severity: SecurityEventSeverity | None = None,
    actor_user_id: uuid.UUID | None = None,
    target_type: SecurityTargetType | None = None,
    target_id: uuid.UUID | None = None,
    request_id: uuid.UUID | None = None,
) -> AuditEventPageResponse:
    """Return a bounded safe projection only after central explicit ALLOW."""

    loaded = subjects.load(principal)
    if loaded.subject is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE
            if loaded.failure_reason is not None
            and loaded.failure_reason.value.endswith("LOAD_ERROR")
            else status.HTTP_403_FORBIDDEN,
            detail="Audit service unavailable"
            if loaded.failure_reason is not None
            and loaded.failure_reason.value.endswith("LOAD_ERROR")
            else "Access denied",
        )
    decision = authorize(
        loaded.subject,
        AuthorizationAction.AUDIT,
        ResourcePolicy(AuthorizationResourceType.AUDIT_EVENT),
    )
    if decision.outcome is not AuthorizationOutcome.ALLOW:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    try:
        page = queries.query(
            now=datetime.now(timezone.utc),
            start=start,
            end=end,
            limit=limit,
            cursor=cursor,
            event_code=event_code,
            outcome=outcome,
            severity=severity,
            actor_user_id=actor_user_id,
            target_type=target_type,
            target_id=target_id,
            request_id=request_id,
        )
    except InvalidAuditQuery:
        raise HTTPException(status_code=400, detail="Invalid audit query") from None
    except Exception:
        raise HTTPException(status_code=503, detail="Audit service unavailable") from None
    return AuditEventPageResponse(
        events=[_response(event) for event in page.events],
        next_cursor=page.next_cursor,
    )


@router.get("/detections", response_model=DetectionFindingListResponse)
def list_detection_findings(
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    subjects: Annotated[
        AuthorizationSubjectService, Depends(get_authorization_subject_service)
    ],
    detections: Annotated[DetectionService, Depends(get_detection_service)],
    lookback_hours: Annotated[int, Query(ge=1, le=24)] = 24,
) -> DetectionFindingListResponse:
    """Return bounded derived review signals after central explicit ALLOW."""

    loaded = subjects.load(principal)
    if loaded.subject is None:
        unavailable = (
            loaded.failure_reason is not None
            and loaded.failure_reason.value.endswith("LOAD_ERROR")
        )
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
                if unavailable
                else status.HTTP_403_FORBIDDEN
            ),
            detail="Detection service unavailable" if unavailable else "Access denied",
        )
    decision = authorize(
        loaded.subject,
        AuthorizationAction.AUDIT,
        ResourcePolicy(AuthorizationResourceType.AUDIT_EVENT),
    )
    if decision.outcome is not AuthorizationOutcome.ALLOW:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    try:
        findings = detections.detect(
            now=datetime.now(timezone.utc),
            lookback=timedelta(hours=lookback_hours),
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection service unavailable",
        ) from None
    return DetectionFindingListResponse(
        findings=[DetectionFindingResponse(**asdict(finding)) for finding in findings]
    )


def _response(event: AuditEventProjection) -> AuditEventResponse:
    return AuditEventResponse(**asdict(event))
