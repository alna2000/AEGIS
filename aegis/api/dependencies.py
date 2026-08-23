"""Central FastAPI dependencies for database and authentication services."""

from collections.abc import Iterator
from datetime import timedelta
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session, sessionmaker

from aegis.core.config import Settings, get_settings
from aegis.db.repositories import (
    MfaChallengeRepository,
    MfaCredentialRepository,
    SessionRepository,
    UserRepository,
)
from aegis.db.authorization_repositories import AuthorizationSubjectRepository
from aegis.db.intelligence_record_repositories import (
    IntelligenceRecordContentRepository,
    IntelligenceRecordPolicyRepository,
)
from aegis.db.session import create_database_engine, create_session_factory
from aegis.security.audit_sinks import LoggingAuthenticationAuditSink
from aegis.security.authentication_events import AuthenticationAuditSink
from aegis.security.passwords import PasswordService
from aegis.security.mfa_encryption import MfaKeyConfigurationError, MfaSecretCipher
from aegis.security.totp import TotpService
from aegis.services.authentication import AuthenticatedPrincipal, AuthenticationService
from aegis.services.mfa import MfaService
from aegis.services.mfa_challenges import MfaChallengeService
from aegis.services.sessions import SessionService
from aegis.services.authorization import AuthorizationSubjectService
from aegis.services.intelligence_records import (
    IntelligenceRecordPolicyService,
    IntelligenceRecordReadService,
)


@lru_cache
def _session_factory(database_url: str) -> sessionmaker[Session]:
    settings = Settings(
        database_url=database_url,
        environment="development",
        session_cookie_secure=False,
        _env_file=None,
    )
    return create_session_factory(create_database_engine(settings))


def get_db_session(
    settings: Annotated[Settings, Depends(get_settings)],
) -> Iterator[Session]:
    """Yield one caller-owned database transaction scope per request."""

    with _session_factory(settings.database_url)() as database_session:
        yield database_session


@lru_cache
def get_authentication_audit_sink() -> AuthenticationAuditSink:
    """Return the current non-persistent controlled authentication audit sink."""

    return LoggingAuthenticationAuditSink()


def get_authentication_service(
    database_session: Annotated[Session, Depends(get_db_session)],
    audit_sink: Annotated[
        AuthenticationAuditSink, Depends(get_authentication_audit_sink)
    ],
) -> AuthenticationService:
    return AuthenticationService(
        UserRepository(database_session),
        PasswordService(),
        audit_sink,
    )


def get_session_service(
    database_session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SessionService:
    return SessionService(
        SessionRepository(database_session),
        lifetime=timedelta(seconds=settings.session_lifetime_seconds),
    )


def build_mfa_service(
    database_session: Session,
    settings: Settings,
    audit_sink: AuthenticationAuditSink,
) -> MfaService:
    """Build MFA verification only when its external key is valid."""

    return MfaService(
        MfaCredentialRepository(database_session),
        MfaSecretCipher(
            settings.mfa_encryption_key,
            settings.mfa_encryption_key_id,
        ),
        TotpService(),
        audit_sink,
    )


def get_mfa_service(
    database_session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    audit_sink: Annotated[
        AuthenticationAuditSink, Depends(get_authentication_audit_sink)
    ],
) -> MfaService:
    try:
        return build_mfa_service(database_session, settings, audit_sink)
    except MfaKeyConfigurationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable",
        ) from None


def get_mfa_challenge_service(
    database_session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> MfaChallengeService:
    return MfaChallengeService(
        MfaChallengeRepository(database_session),
        MfaCredentialRepository(database_session),
        lifetime=timedelta(seconds=settings.mfa_challenge_lifetime_seconds),
    )


def get_current_principal(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
) -> AuthenticatedPrincipal:
    """Resolve identity through the one authoritative session-validation path."""

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
    return resolved.principal


def get_intelligence_record_read_service(
    database_session: Annotated[Session, Depends(get_db_session)],
) -> IntelligenceRecordReadService:
    """Compose the centralized policy-first classified-record read service."""

    return IntelligenceRecordReadService(
        AuthorizationSubjectService(
            AuthorizationSubjectRepository(database_session)
        ),
        IntelligenceRecordPolicyService(
            IntelligenceRecordPolicyRepository(database_session)
        ),
        IntelligenceRecordContentRepository(database_session),
    )
