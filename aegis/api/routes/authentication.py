"""HTTP password login and server-side session routes."""

from typing import Annotated
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, StrictStr
from sqlalchemy.orm import Session

from aegis.api.dependencies import (
    build_mfa_service,
    get_authentication_abuse_control,
    get_authentication_audit_sink,
    get_authentication_service,
    get_current_principal,
    get_db_session,
    get_mfa_challenge_service,
    get_mfa_service,
    get_session_service,
)
from aegis.core.config import Settings, get_settings
from aegis.security.authentication_events import (
    AuthenticationAuditSink,
    AuthenticationRequestContext,
)
from aegis.security.abuse import AbuseDecision, AbuseDecisionStatus
from aegis.security.authentication_abuse import AuthenticationAbuseControl
from aegis.services.authentication import (
    AuthenticatedPrincipal,
    AuthenticationService,
    LoginAttemptStatus,
)
from aegis.services.mfa import MfaService, MfaVerificationStatus
from aegis.services.mfa_challenges import MfaChallengeService
from aegis.services.sessions import SessionService


router = APIRouter(prefix="/auth", tags=["authentication"])
_GENERIC_LOGIN_FAILURE = "Invalid username or password"
_GENERIC_MFA_FAILURE = "MFA verification failed"
_GENERIC_SERVICE_FAILURE = "Authentication service unavailable"
_GENERIC_ABUSE_LIMIT = "Authentication temporarily unavailable"


class LoginRequest(BaseModel):
    """The only client-controlled fields accepted by password login."""

    model_config = ConfigDict(extra="forbid")

    username: StrictStr
    password: StrictStr = Field(repr=False)


class LoginResponse(BaseModel):
    authenticated: bool
    mfa_required: bool


class TotpVerificationRequest(BaseModel):
    """The only client-controlled field accepted by TOTP completion."""

    model_config = ConfigDict(extra="forbid")

    code: StrictStr = Field(min_length=6, max_length=6, repr=False)


class CurrentIdentityResponse(BaseModel):
    username: str
    display_name: str


def _request_context(request: Request) -> AuthenticationRequestContext:
    return AuthenticationRequestContext(
        request_id=uuid.uuid4(),
        source_ip=request.client.host if request.client is not None else None,
        user_agent=request.headers.get("user-agent"),
    )


def _enforce_abuse_decision(decision: AbuseDecision) -> None:
    if decision.status is AbuseDecisionStatus.ALLOW:
        return
    if decision.status is AbuseDecisionStatus.LIMITED:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_GENERIC_ABUSE_LIMIT,
            headers={
                "Cache-Control": "no-store",
                "Retry-After": str(decision.retry_after_seconds),
            },
        )
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=_GENERIC_SERVICE_FAILURE,
        headers={"Cache-Control": "no-store"},
    )


@router.post("/login", response_model=LoginResponse)
def login(
    credentials: LoginRequest,
    request: Request,
    response: Response,
    database_session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    authentication: Annotated[
        AuthenticationService, Depends(get_authentication_service)
    ],
    sessions: Annotated[SessionService, Depends(get_session_service)],
    challenges: Annotated[
        MfaChallengeService, Depends(get_mfa_challenge_service)
    ],
    audit_sink: Annotated[
        AuthenticationAuditSink, Depends(get_authentication_audit_sink)
    ],
    abuse: Annotated[
        AuthenticationAbuseControl, Depends(get_authentication_abuse_control)
    ],
) -> LoginResponse:
    """Authenticate a password, then issue a session or an MFA challenge."""

    context = _request_context(request)
    _enforce_abuse_decision(abuse.admit_login(credentials.username, context))
    acquisition = abuse.acquire_login_work()
    _enforce_abuse_decision(acquisition.decision)
    if acquisition.lease is None:
        raise RuntimeError("allowed login work lacked a concurrency lease")
    try:
        with acquisition.lease:
            result = authentication.attempt_login(
                credentials.username,
                credentials.password,
                context,
            )
            if result.status is LoginAttemptStatus.FAILURE:
                database_session.rollback()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=_GENERIC_LOGIN_FAILURE,
                )

            if result.principal is None:
                raise RuntimeError("successful authentication result lacked identity")
            if challenges.requires_totp(result.principal):
                # Validate the external encryption configuration before issuing a
                # challenge that could otherwise never be completed.
                build_mfa_service(database_session, settings, audit_sink)
                issued_challenge = challenges.create_challenge(result.principal, context)
                database_session.commit()
                response.set_cookie(
                    key=settings.mfa_challenge_cookie_name,
                    value=issued_challenge.raw_token,
                    max_age=settings.mfa_challenge_lifetime_seconds,
                    expires=issued_challenge.expires_at,
                    path="/auth",
                    secure=settings.session_cookie_secure,
                    httponly=True,
                    samesite="strict",
                )
                return LoginResponse(authenticated=False, mfa_required=True)

            challenges.revoke(
                request.cookies.get(settings.mfa_challenge_cookie_name)
            )
            sessions.revoke_session(request.cookies.get(settings.session_cookie_name))
            issued = sessions.create_session(result.principal, context)
            database_session.commit()
    except HTTPException:
        raise
    except Exception:
        database_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_GENERIC_SERVICE_FAILURE,
        ) from None

    response.set_cookie(
        key=settings.session_cookie_name,
        value=issued.raw_token,
        max_age=settings.session_lifetime_seconds,
        expires=issued.expires_at,
        path="/",
        secure=settings.session_cookie_secure,
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(
        key=settings.mfa_challenge_cookie_name,
        path="/auth",
        secure=settings.session_cookie_secure,
        httponly=True,
        samesite="strict",
    )
    return LoginResponse(authenticated=True, mfa_required=False)


@router.post("/mfa/totp/verify", response_model=LoginResponse)
def verify_totp(
    verification: TotpVerificationRequest,
    request: Request,
    response: Response,
    database_session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
    challenges: Annotated[
        MfaChallengeService, Depends(get_mfa_challenge_service)
    ],
    mfa: Annotated[MfaService, Depends(get_mfa_service)],
    abuse: Annotated[
        AuthenticationAbuseControl, Depends(get_authentication_abuse_control)
    ],
) -> LoginResponse:
    """Complete a password-verified MFA challenge and issue a fresh session."""

    context = _request_context(request)
    raw_challenge_token = request.cookies.get(settings.mfa_challenge_cookie_name)
    _enforce_abuse_decision(abuse.admit_mfa(raw_challenge_token, context))
    _enforce_abuse_decision(abuse.check_mfa_cooldown(raw_challenge_token))
    acquisition = abuse.acquire_mfa_work(raw_challenge_token)
    _enforce_abuse_decision(acquisition.decision)
    if acquisition.lease is None:
        raise RuntimeError("allowed MFA work lacked a concurrency lease")
    try:
        with acquisition.lease:
            resolved = challenges.resolve_challenge(raw_challenge_token)
            verification_status = (
                mfa.verify_result(resolved.principal, verification.code, context)
                if resolved is not None
                else None
            )
            if verification_status is not MfaVerificationStatus.SUCCESS:
                if (
                    resolved is not None
                    and verification_status is MfaVerificationStatus.FACTOR_FAILURE
                ):
                    failure_count = challenges.record_factor_failure(
                        resolved,
                        maximum_failures=abuse.policy.mfa_max_factor_failures,
                    )
                    if failure_count < abuse.policy.mfa_max_factor_failures and failure_count >= 2:
                        cooldown = abuse.activate_mfa_cooldown(
                            raw_challenge_token, factor_failure_count=failure_count
                        )
                        if cooldown.status is AbuseDecisionStatus.UNAVAILABLE:
                            database_session.rollback()
                            _enforce_abuse_decision(cooldown)
                    database_session.commit()
                else:
                    database_session.rollback()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=_GENERIC_MFA_FAILURE,
                )

            challenges.consume(resolved)
            sessions.revoke_session(request.cookies.get(settings.session_cookie_name))
            issued = sessions.create_session(resolved.principal, context)
            database_session.commit()
    except HTTPException:
        raise
    except Exception:
        database_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_GENERIC_SERVICE_FAILURE,
        ) from None

    response.delete_cookie(
        key=settings.mfa_challenge_cookie_name,
        path="/auth",
        secure=settings.session_cookie_secure,
        httponly=True,
        samesite="strict",
    )
    response.set_cookie(
        key=settings.session_cookie_name,
        value=issued.raw_token,
        max_age=settings.session_lifetime_seconds,
        expires=issued.expires_at,
        path="/",
        secure=settings.session_cookie_secure,
        httponly=True,
        samesite="strict",
    )
    return LoginResponse(authenticated=True, mfa_required=False)


@router.get("/me", response_model=CurrentIdentityResponse)
def current_identity(
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> CurrentIdentityResponse:
    """Return safe identity only for a currently usable authenticated session."""

    return CurrentIdentityResponse(
        username=principal.username,
        display_name=principal.display_name,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    database_session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
    challenges: Annotated[
        MfaChallengeService, Depends(get_mfa_challenge_service)
    ],
) -> None:
    """Revoke a presented server-side session and remove its client cookie."""

    try:
        sessions.revoke_session(request.cookies.get(settings.session_cookie_name))
        challenges.revoke(
            request.cookies.get(settings.mfa_challenge_cookie_name)
        )
        database_session.commit()
    except Exception:
        database_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_GENERIC_SERVICE_FAILURE,
        ) from None

    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        secure=settings.session_cookie_secure,
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(
        key=settings.mfa_challenge_cookie_name,
        path="/auth",
        secure=settings.session_cookie_secure,
        httponly=True,
        samesite="strict",
    )
