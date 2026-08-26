"""Local-learning abuse policy for password login and TOTP completion.

These finite defaults protect one AEGIS process. They are intentionally easy to
review and test, and are not production tuning recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.security.abuse import (
    AbuseControlEngine,
    AbuseDecision,
    AbuseDecisionStatus,
    AbuseScope,
    AbuseScopeKind,
    AdmissionRule,
    ConcurrencyPolicy,
    CorrelationKeyDeriver,
    CooldownPolicy,
    CounterPolicy,
    FixedAbuseScope,
    InMemoryAbuseStateStore,
    LeaseAcquisition,
)
from aegis.security.authentication_events import AuthenticationRequestContext
from aegis.security.identity import InvalidIdentity, normalize_username
from aegis.services.mfa_challenges import hash_mfa_challenge_token


@dataclass(frozen=True, slots=True)
class AuthenticationAbusePolicy:
    """Central Phase 5 local-learning thresholds for protected authentication."""

    login_global: CounterPolicy = CounterPolicy(300, 60)
    login_source: CounterPolicy = CounterPolicy(30, 60)
    login_identity: CounterPolicy = CounterPolicy(10, 300)
    login_concurrency: ConcurrencyPolicy = ConcurrencyPolicy(8, 30)
    mfa_global: CounterPolicy = CounterPolicy(300, 60)
    mfa_source: CounterPolicy = CounterPolicy(60, 60)
    mfa_token: CounterPolicy = CounterPolicy(12, 300)
    mfa_concurrency: ConcurrencyPolicy = ConcurrencyPolicy(1, 30)
    mfa_cooldown: CooldownPolicy = CooldownPolicy(1, 4)
    mfa_max_factor_failures: int = 5

    def __post_init__(self) -> None:
        if type(self.mfa_max_factor_failures) is not int or self.mfa_max_factor_failures != 5:
            raise ValueError("the Phase 5 MFA factor-failure bound must be five")


class AuthenticationAbuseControl:
    """Derive opaque endpoint scopes and apply the endpoint abuse policy."""

    def __init__(
        self,
        engine: AbuseControlEngine,
        deriver: CorrelationKeyDeriver,
        *,
        policy: AuthenticationAbusePolicy | None = None,
    ) -> None:
        self._engine = engine
        self._deriver = deriver
        self.policy = policy or AuthenticationAbusePolicy()

    @classmethod
    def create_local(cls) -> "AuthenticationAbuseControl":
        return cls(
            AbuseControlEngine(
                InMemoryAbuseStateStore(maximum_entries=4096, reserved_entries=2)
            ),
            CorrelationKeyDeriver(max_input_bytes=256),
        )

    def admit_login(
        self, username: str, context: AuthenticationRequestContext
    ) -> AbuseDecision:
        identity_scope = self._login_identity_scope(username)
        return self._engine.admit(
            (
                AdmissionRule(
                    AbuseScope.fixed(FixedAbuseScope.LOGIN_ENDPOINT),
                    self.policy.login_global,
                ),
                AdmissionRule(self._source_scope("login", context), self.policy.login_source),
                AdmissionRule(identity_scope, self.policy.login_identity),
            )
        )

    def acquire_login_work(self) -> LeaseAcquisition:
        return self._engine.acquire_concurrency(
            AbuseScope.fixed(FixedAbuseScope.LOGIN_ENDPOINT),
            self.policy.login_concurrency,
        )

    def admit_mfa(
        self, raw_token: str | None, context: AuthenticationRequestContext
    ) -> AbuseDecision:
        outer_decision = self._engine.admit(
            (
                AdmissionRule(
                    AbuseScope.fixed(FixedAbuseScope.MFA_ENDPOINT),
                    self.policy.mfa_global,
                ),
                AdmissionRule(self._source_scope("mfa", context), self.policy.mfa_source),
            )
        )
        if outer_decision.status is not AbuseDecisionStatus.ALLOW:
            return outer_decision
        # Allocate high-cardinality presented-token state only after the fixed
        # endpoint and direct-source budgets have admitted the request.
        return self._engine.admit(
            (
                AdmissionRule(
                    self._mfa_token_scope(raw_token, "admission"),
                    self.policy.mfa_token,
                ),
            )
        )

    def check_mfa_cooldown(self, raw_token: str | None) -> AbuseDecision:
        return self._engine.check_cooldowns(
            (self._mfa_token_scope(raw_token, "cooldown"),)
        )

    def activate_mfa_cooldown(
        self, raw_token: str | None, *, factor_failure_count: int
    ) -> AbuseDecision:
        if type(factor_failure_count) is not int or factor_failure_count < 2:
            raise ValueError("MFA cooldown starts with the second factor failure")
        return self._engine.activate_cooldown(
            self._mfa_token_scope(raw_token, "cooldown"),
            self.policy.mfa_cooldown,
            level=factor_failure_count - 1,
        )

    def acquire_mfa_work(self, raw_token: str | None) -> LeaseAcquisition:
        return self._engine.acquire_concurrency(
            self._mfa_token_scope(raw_token, "work"), self.policy.mfa_concurrency
        )

    def _login_identity_scope(self, username: str) -> AbuseScope:
        try:
            normalized = normalize_username(username)
        except (InvalidIdentity, TypeError):
            return AbuseScope.fixed(FixedAbuseScope.MALFORMED_LOGIN_IDENTITY)
        return self._correlated(AbuseScopeKind.IDENTITY, "login-identity", normalized)

    def _source_scope(
        self, endpoint: str, context: AuthenticationRequestContext
    ) -> AbuseScope:
        source = context.source_ip or "unavailable"
        return self._correlated(AbuseScopeKind.SOURCE, f"{endpoint}-source", source)

    def _mfa_token_scope(self, raw_token: str | None, purpose: str) -> AbuseScope:
        token_hash = hash_mfa_challenge_token(raw_token)
        controlled = token_hash if token_hash is not None else "malformed-or-missing"
        return self._correlated(AbuseScopeKind.CHALLENGE, f"mfa-{purpose}", controlled)

    def _correlated(self, kind: AbuseScopeKind, domain: str, value: str) -> AbuseScope:
        return AbuseScope.correlated(kind, self._deriver.derive(f"{domain}\0{value}"))

    def __repr__(self) -> str:
        return f"AuthenticationAbuseControl(policy={self.policy!r}, secret=<redacted>)"


def is_allowed(decision: AbuseDecision) -> bool:
    return decision.status is AbuseDecisionStatus.ALLOW
