"""HTTP access to explicitly authorized synthetic intelligence records."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from aegis.api.dependencies import (
    get_current_principal,
    get_intelligence_record_collection_read_service,
    get_intelligence_record_read_service,
)
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.intelligence_records import (
    IntelligenceRecordCollectionReadOutcome,
    IntelligenceRecordCollectionReadResult,
    IntelligenceRecordCollectionReadService,
    IntelligenceRecordReadOutcome,
    IntelligenceRecordReadResult,
    IntelligenceRecordReadService,
)


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
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    records: Annotated[
        IntelligenceRecordCollectionReadService,
        Depends(get_intelligence_record_collection_read_service),
    ],
) -> list[IntelligenceRecordCollectionEntryResponse]:
    """Return metadata only for records allowed for SEARCH and READ."""

    try:
        result = records.read(principal)
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
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    records: Annotated[
        IntelligenceRecordReadService,
        Depends(get_intelligence_record_read_service),
    ],
) -> IntelligenceRecordResponse:
    """Return one record only after current centralized authorization allows it."""

    try:
        result = records.read(principal, record_code)
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
