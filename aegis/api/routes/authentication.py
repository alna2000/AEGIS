"""HTTP password login and server-side session routes."""

from typing import Annotated
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, StrictStr
from sqlalchemy.orm import Session

from aegis.api.dependencies import (
    build_mfa_service,
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
from aegis.services.authentication import (
    AuthenticatedPrincipal,
    AuthenticationService,
    LoginAttemptStatus,
)
from aegis.services.mfa import MfaService
from aegis.services.mfa_challenges import MfaChallengeService
from aegis.services.sessions import SessionService


router = APIRouter(prefix="/auth", tags=["authentication"])
_GENERIC_LOGIN_FAILURE = "Invalid username or password"
_GENERIC_MFA_FAILURE = "MFA verification failed"
_GENERIC_SERVICE_FAILURE = "Authentication service unavailable"


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
) -> LoginResponse:
    """Authenticate a password, then issue a session or an MFA challenge."""

    context = _request_context(request)
    try:
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
) -> LoginResponse:
    """Complete a password-verified MFA challenge and issue a fresh session."""

    context = _request_context(request)
    try:
        resolved = challenges.resolve_challenge(
            request.cookies.get(settings.mfa_challenge_cookie_name)
        )
        if resolved is None or not mfa.verify(
            resolved.principal, verification.code, context
        ):
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
