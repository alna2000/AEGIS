"""Local-learning availability policy for session, record, and public routes.

The defaults protect one AEGIS process and are reviewable learning values, not
production tuning recommendations. Edge bandwidth and connection controls remain
deployment concerns.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from aegis.security.abuse import (
    AbuseControlEngine,
    AbuseDecision,
    AbuseDecisionStatus,
    AbuseScope,
    AbuseScopeKind,
    AdmissionRule,
    ConcurrencyLease,
    ConcurrencyPolicy,
    CorrelationKeyDeriver,
    CounterPolicy,
    FixedAbuseScope,
    InMemoryAbuseStateStore,
)
from aegis.security.authentication_events import AuthenticationRequestContext


@dataclass(frozen=True, slots=True)
class AvailabilityAbusePolicy:
    """Central finite defaults for Phase 5 Part 4 endpoint families."""

    auth_me_global: CounterPolicy = CounterPolicy(600, 60)
    auth_me_source: CounterPolicy = CounterPolicy(120, 60)
    auth_me_session: CounterPolicy = CounterPolicy(120, 60)
    logout_global: CounterPolicy = CounterPolicy(600, 60)
    logout_source: CounterPolicy = CounterPolicy(120, 60)
    collection_global: CounterPolicy = CounterPolicy(120, 60)
    collection_source: CounterPolicy = CounterPolicy(30, 60)
    collection_session: CounterPolicy = CounterPolicy(20, 60)
    detail_global: CounterPolicy = CounterPolicy(600, 60)
    detail_source: CounterPolicy = CounterPolicy(120, 60)
    detail_session: CounterPolicy = CounterPolicy(120, 60)
    public_global: CounterPolicy = CounterPolicy(2000, 60)
    public_source: CounterPolicy = CounterPolicy(300, 60)
    expensive_global_concurrency: ConcurrencyPolicy = ConcurrencyPolicy(8, 30)
    collection_session_concurrency: ConcurrencyPolicy = ConcurrencyPolicy(1, 30)
    detail_session_concurrency: ConcurrencyPolicy = ConcurrencyPolicy(4, 30)


@dataclass(slots=True)
class RecordWorkLeases:
    """Exception-safe ownership of acquired record-work leases."""

    global_lease: ConcurrencyLease = field(repr=False)
    session_lease: ConcurrencyLease | None = field(default=None, repr=False)

    def release(self) -> None:
        if self.session_lease is not None:
            self.session_lease.release()
        self.global_lease.release()

    def __enter__(self) -> "RecordWorkLeases":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.release()


class AvailabilityAbuseControl:
    """Apply bounded endpoint-family policy using opaque source/session scopes."""

    def __init__(
        self,
        engine: AbuseControlEngine,
        deriver: CorrelationKeyDeriver,
        *,
        policy: AvailabilityAbusePolicy | None = None,
    ) -> None:
        self._engine = engine
        self._deriver = deriver
        self.policy = policy or AvailabilityAbusePolicy()

    @classmethod
    def create_local(cls) -> "AvailabilityAbuseControl":
        return cls(
            AbuseControlEngine(
                InMemoryAbuseStateStore(maximum_entries=8192, reserved_entries=2)
            ),
            CorrelationKeyDeriver(max_input_bytes=256),
        )

    def admit_auth_me_outer(self, context: AuthenticationRequestContext) -> AbuseDecision:
        return self._admit_outer(
            FixedAbuseScope.AUTH_ME_ENDPOINT,
            "auth-me",
            context,
            self.policy.auth_me_global,
            self.policy.auth_me_source,
        )

    def admit_auth_me_session(self, session_id: uuid.UUID) -> AbuseDecision:
        return self._engine.admit(
            (
                AdmissionRule(
                    self._session_scope("auth-me", session_id),
                    self.policy.auth_me_session,
                ),
            )
        )

    def admit_logout(self, context: AuthenticationRequestContext) -> AbuseDecision:
        return self._admit_outer(
            FixedAbuseScope.LOGOUT_ENDPOINT,
            "logout",
            context,
            self.policy.logout_global,
            self.policy.logout_source,
        )

    def admit_collection_outer(
        self, context: AuthenticationRequestContext
    ) -> AbuseDecision:
        return self._admit_outer(
            FixedAbuseScope.RECORD_COLLECTION_ENDPOINT,
            "record-collection",
            context,
            self.policy.collection_global,
            self.policy.collection_source,
        )

    def admit_collection_session(self, session_id: uuid.UUID) -> AbuseDecision:
        return self._engine.admit(
            (
                AdmissionRule(
                    self._session_scope("record-collection", session_id),
                    self.policy.collection_session,
                ),
            )
        )

    def admit_detail_outer(self, context: AuthenticationRequestContext) -> AbuseDecision:
        return self._admit_outer(
            FixedAbuseScope.RECORD_DETAIL_ENDPOINT,
            "record-detail",
            context,
            self.policy.detail_global,
            self.policy.detail_source,
        )

    def admit_detail_session(self, session_id: uuid.UUID) -> AbuseDecision:
        return self._engine.admit(
            (
                AdmissionRule(
                    self._session_scope("record-detail", session_id),
                    self.policy.detail_session,
                ),
            )
        )

    def acquire_record_work(
        self, session_id: uuid.UUID, *, collection: bool
    ) -> tuple[AbuseDecision, RecordWorkLeases | None]:
        global_result = self._engine.acquire_concurrency(
            AbuseScope.fixed(FixedAbuseScope.GLOBAL),
            self.policy.expensive_global_concurrency,
        )
        if global_result.decision.status is not AbuseDecisionStatus.ALLOW:
            return global_result.decision, None
        if global_result.lease is None:
            raise RuntimeError("allowed global record work lacked a lease")
        session_result = self._engine.acquire_concurrency(
            self._session_scope(
                "record-collection-work" if collection else "record-detail-work",
                session_id,
            ),
            (
                self.policy.collection_session_concurrency
                if collection
                else self.policy.detail_session_concurrency
            ),
        )
        if session_result.decision.status is not AbuseDecisionStatus.ALLOW:
            global_result.lease.release()
            return session_result.decision, None
        if session_result.lease is None:
            global_result.lease.release()
            raise RuntimeError("allowed session record work lacked a lease")
        return (
            session_result.decision,
            RecordWorkLeases(global_result.lease, session_result.lease),
        )

    def admit_public(self, context: AuthenticationRequestContext) -> AbuseDecision:
        return self._admit_outer(
            FixedAbuseScope.PUBLIC_ENDPOINT,
            "public",
            context,
            self.policy.public_global,
            self.policy.public_source,
        )

    def _admit_outer(
        self,
        fixed: FixedAbuseScope,
        domain: str,
        context: AuthenticationRequestContext,
        global_policy: CounterPolicy,
        source_policy: CounterPolicy,
    ) -> AbuseDecision:
        return self._engine.admit(
            (
                AdmissionRule(AbuseScope.fixed(fixed), global_policy),
                AdmissionRule(self._source_scope(domain, context), source_policy),
            )
        )

    def _source_scope(
        self, domain: str, context: AuthenticationRequestContext
    ) -> AbuseScope:
        source = context.source_ip or "unavailable"
        return self._correlated(AbuseScopeKind.SOURCE, f"{domain}-source", source)

    def _session_scope(self, domain: str, session_id: uuid.UUID) -> AbuseScope:
        if not isinstance(session_id, uuid.UUID):
            raise TypeError("session abuse scope requires an internal UUID")
        return self._correlated(AbuseScopeKind.SESSION, domain, session_id.bytes)

    def _correlated(
        self, kind: AbuseScopeKind, domain: str, value: str | bytes
    ) -> AbuseScope:
        encoded_domain = domain.encode("ascii") + b"\0"
        encoded_value = value.encode("utf-8") if isinstance(value, str) else value
        return AbuseScope.correlated(kind, self._deriver.derive(encoded_domain + encoded_value))

    def __repr__(self) -> str:
        return f"AvailabilityAbuseControl(policy={self.policy!r}, secret=<redacted>)"
