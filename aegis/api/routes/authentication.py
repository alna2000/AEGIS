"""HTTP password login and server-side session routes."""

from typing import Annotated
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, StrictStr
from sqlalchemy.orm import Session

from aegis.api.dependencies import (
    get_authentication_service,
    get_current_principal,
    get_db_session,
    get_session_service,
)
from aegis.core.config import Settings, get_settings
from aegis.security.authentication_events import AuthenticationRequestContext
from aegis.services.authentication import (
    AuthenticatedPrincipal,
    AuthenticationService,
    LoginAttemptStatus,
)
from aegis.services.sessions import SessionService


router = APIRouter(prefix="/auth", tags=["authentication"])
_GENERIC_LOGIN_FAILURE = "Invalid username or password"
_GENERIC_SERVICE_FAILURE = "Authentication service unavailable"


class LoginRequest(BaseModel):
    """The only client-controlled fields accepted by password login."""

    model_config = ConfigDict(extra="forbid")

    username: StrictStr
    password: StrictStr = Field(repr=False)


class LoginResponse(BaseModel):
    authenticated: bool


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
) -> LoginResponse:
    """Authenticate credentials and durably create a fresh server-side session."""

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
    return LoginResponse(authenticated=True)


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
) -> None:
    """Revoke a presented server-side session and remove its client cookie."""

    try:
        sessions.revoke_session(request.cookies.get(settings.session_cookie_name))
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
