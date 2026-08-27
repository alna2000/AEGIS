"""Typed, bounded abuse-control primitives for one local AEGIS process.

The in-memory store is ephemeral and thread-safe within one Python process. It
does not synchronize across worker processes and is not a distributed store.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, Self


MAX_ADMISSION_SCOPES = 8
MAX_CONCURRENCY_LEASES_PER_SCOPE = 1024
MIN_CORRELATION_SECRET_BYTES = 32
MAX_CORRELATION_INPUT_BYTES = 4096


class AbuseDecisionStatus(str, Enum):
    """Controlled outcomes returned by the abuse-control boundary."""

    ALLOW = "ALLOW"
    LIMITED = "LIMITED"
    UNAVAILABLE = "UNAVAILABLE"


class AbuseDecisionReason(str, Enum):
    """Internal controlled reasons that never contain request-derived data."""

    RATE_LIMIT = "RATE_LIMIT"
    COOLDOWN = "COOLDOWN"
    CONCURRENCY = "CONCURRENCY"
    STORE_CAPACITY = "STORE_CAPACITY"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class AbuseDecision:
    """Minimal decision safe to map to an HTTP response in a later phase."""

    status: AbuseDecisionStatus
    reason: AbuseDecisionReason | None = None
    retry_after_seconds: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, AbuseDecisionStatus):
            raise ValueError("abuse-control decision status must be controlled")
        if self.status is AbuseDecisionStatus.ALLOW:
            valid = self.reason is None and self.retry_after_seconds is None
        elif self.status is AbuseDecisionStatus.LIMITED:
            valid = (
                self.reason
                in {
                    AbuseDecisionReason.RATE_LIMIT,
                    AbuseDecisionReason.COOLDOWN,
                    AbuseDecisionReason.CONCURRENCY,
                }
                and type(self.retry_after_seconds) is int
                and self.retry_after_seconds > 0
            )
        else:
            valid = (
                self.reason
                in {
                    AbuseDecisionReason.STORE_CAPACITY,
                    AbuseDecisionReason.STORE_UNAVAILABLE,
                }
                and self.retry_after_seconds is None
            )
        if not valid:
            raise ValueError("invalid abuse-control decision state")

    @classmethod
    def allow(cls) -> Self:
        return cls(AbuseDecisionStatus.ALLOW)

    @classmethod
    def limited(cls, reason: AbuseDecisionReason, retry_after_seconds: int) -> Self:
        return cls(AbuseDecisionStatus.LIMITED, reason, retry_after_seconds)

    @classmethod
    def unavailable(cls, reason: AbuseDecisionReason) -> Self:
        return cls(AbuseDecisionStatus.UNAVAILABLE, reason)


class AbuseScopeKind(str, Enum):
    """Controlled semantic classes for opaque abuse-state scopes."""

    FIXED = "FIXED"
    SOURCE = "SOURCE"
    NETWORK = "NETWORK"
    IDENTITY = "IDENTITY"
    CHALLENGE = "CHALLENGE"
    SESSION = "SESSION"


class FixedAbuseScope(str, Enum):
    """Bounded scopes that require no request-derived key material."""

    GLOBAL = "global"
    LOGIN_ENDPOINT = "login-endpoint"
    MFA_ENDPOINT = "mfa-endpoint"
    SESSION_ENDPOINT = "session-endpoint"
    AUTH_ME_ENDPOINT = "auth-me-endpoint"
    LOGOUT_ENDPOINT = "logout-endpoint"
    RECORD_COLLECTION_ENDPOINT = "record-collection-endpoint"
    RECORD_DETAIL_ENDPOINT = "record-detail-endpoint"
    PUBLIC_ENDPOINT = "public-endpoint"
    MALFORMED_LOGIN_IDENTITY = "malformed-login-identity"


@dataclass(frozen=True, slots=True)
class CorrelationKey:
    """Opaque HMAC output whose representation suppresses the digest."""

    _digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self._digest, bytes) or len(self._digest) != 32:
            raise ValueError("correlation key must be a SHA-256 digest")

    def __repr__(self) -> str:
        return "CorrelationKey(<redacted>)"


class CorrelationKeyDeriver:
    """Derive non-reversible process-local correlation keys using HMAC-SHA-256."""

    __slots__ = ("_secret", "max_input_bytes")

    def __init__(
        self,
        secret: bytes | None = None,
        *,
        max_input_bytes: int = 256,
    ) -> None:
        secret = secrets.token_bytes(MIN_CORRELATION_SECRET_BYTES) if secret is None else secret
        if not isinstance(secret, bytes) or len(secret) < MIN_CORRELATION_SECRET_BYTES:
            raise ValueError("abuse correlation secret must contain at least 32 bytes")
        if (
            type(max_input_bytes) is not int
            or not 1 <= max_input_bytes <= MAX_CORRELATION_INPUT_BYTES
        ):
            raise ValueError("correlation input bound is invalid")
        self._secret = secret
        self.max_input_bytes = max_input_bytes

    def derive(self, value: str | bytes) -> CorrelationKey:
        if isinstance(value, str):
            try:
                encoded = value.encode("utf-8")
            except UnicodeEncodeError:
                raise ValueError("correlation input must be valid UTF-8") from None
        elif isinstance(value, bytes):
            encoded = value
        else:
            raise TypeError("correlation input must be text or bytes")
        if not encoded or len(encoded) > self.max_input_bytes:
            raise ValueError("correlation input is empty or exceeds its bound")
        return CorrelationKey(hmac.new(self._secret, encoded, hashlib.sha256).digest())

    def __repr__(self) -> str:
        return (
            "CorrelationKeyDeriver("
            f"max_input_bytes={self.max_input_bytes}, secret=<redacted>)"
        )


@dataclass(frozen=True, slots=True, init=False)
class AbuseScope:
    """A fixed or opaque scope; raw request strings cannot initialize it directly."""

    kind: AbuseScopeKind
    _identifier: bytes = field(repr=False)
    _reserved: bool = field(repr=False)

    @classmethod
    def fixed(cls, identifier: FixedAbuseScope) -> Self:
        if not isinstance(identifier, FixedAbuseScope):
            raise TypeError("fixed abuse scope must use a controlled identifier")
        return cls._create(
            AbuseScopeKind.FIXED,
            identifier.value.encode("ascii"),
            reserved=identifier is FixedAbuseScope.GLOBAL,
        )

    @classmethod
    def correlated(cls, kind: AbuseScopeKind, key: CorrelationKey) -> Self:
        if not isinstance(kind, AbuseScopeKind) or kind is AbuseScopeKind.FIXED:
            raise ValueError("correlated scope kind must be semantic")
        if not isinstance(key, CorrelationKey):
            raise TypeError("correlated scope requires an opaque correlation key")
        return cls._create(kind, key._digest, reserved=False)

    @classmethod
    def _create(cls, kind: AbuseScopeKind, identifier: bytes, *, reserved: bool) -> Self:
        instance = object.__new__(cls)
        object.__setattr__(instance, "kind", kind)
        object.__setattr__(instance, "_identifier", identifier)
        object.__setattr__(instance, "_reserved", reserved)
        return instance

    @property
    def uses_reserved_capacity(self) -> bool:
        return self._reserved

    def __repr__(self) -> str:
        return f"AbuseScope(kind={self.kind.value}, identifier=<redacted>)"


@dataclass(frozen=True, slots=True)
class CounterPolicy:
    """A fixed-window admission policy."""

    limit: int
    window_seconds: float

    def __post_init__(self) -> None:
        if type(self.limit) is not int or self.limit <= 0:
            raise ValueError("counter limit must be a positive integer")
        _require_positive_finite(self.window_seconds, "counter window")


@dataclass(frozen=True, slots=True)
class AdmissionRule:
    """One scope and its fixed-window policy in an atomic admission."""

    scope: AbuseScope
    policy: CounterPolicy

    def __post_init__(self) -> None:
        if not isinstance(self.scope, AbuseScope) or not isinstance(
            self.policy, CounterPolicy
        ):
            raise TypeError("admission rules require a scope and counter policy")


@dataclass(frozen=True, slots=True)
class CooldownPolicy:
    """Bounded exponential cooldown suitable for later endpoint policy."""

    initial_delay_seconds: float
    maximum_delay_seconds: float

    def __post_init__(self) -> None:
        _require_positive_finite(self.initial_delay_seconds, "initial cooldown")
        _require_positive_finite(self.maximum_delay_seconds, "maximum cooldown")
        if self.initial_delay_seconds > self.maximum_delay_seconds:
            raise ValueError("initial cooldown cannot exceed maximum cooldown")

    def delay_for_level(self, level: int) -> float:
        if type(level) is not int or level <= 0:
            raise ValueError("cooldown level must be a positive integer")
        if level > 63:
            return self.maximum_delay_seconds
        return min(
            self.initial_delay_seconds * (2 ** (level - 1)),
            self.maximum_delay_seconds,
        )


@dataclass(frozen=True, slots=True)
class ConcurrencyPolicy:
    """Maximum active work and leaked-lease recovery duration."""

    limit: int
    lease_seconds: float

    def __post_init__(self) -> None:
        if (
            type(self.limit) is not int
            or not 1 <= self.limit <= MAX_CONCURRENCY_LEASES_PER_SCOPE
        ):
            raise ValueError("concurrency limit is outside the safe bound")
        _require_positive_finite(self.lease_seconds, "concurrency lease")


class AbuseStoreUnavailable(RuntimeError):
    """Expected inability of an abuse-state adapter to serve an operation."""


class AbuseStoreStatus(Enum):
    """Controlled outcomes returned by an abuse-state adapter."""

    ALLOWED = "ALLOWED"
    LIMITED = "LIMITED"
    CAPACITY = "CAPACITY"


@dataclass(frozen=True, slots=True)
class AbuseStoreResult:
    """Endpoint-neutral store result without any raw state key."""

    status: AbuseStoreStatus
    retry_after_seconds: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, AbuseStoreStatus):
            raise ValueError("abuse store status must be controlled")
        if self.status is AbuseStoreStatus.LIMITED:
            _require_positive_finite(self.retry_after_seconds, "store retry duration")
        elif self.retry_after_seconds is not None:
            raise ValueError("only a limited store result may contain retry duration")


@dataclass(frozen=True, slots=True)
class AbuseStoreLeaseResult:
    """Store acquisition result with an internal opaque lease credential."""

    result: AbuseStoreResult
    lease_token: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.result, AbuseStoreResult):
            raise TypeError("store lease result requires a controlled result")
        allowed = self.result.status is AbuseStoreStatus.ALLOWED
        if allowed != (isinstance(self.lease_token, str) and bool(self.lease_token)):
            raise ValueError("only allowed store acquisition may contain a lease token")


class AbuseStateStore(Protocol):
    """Replaceable synchronous boundary for ephemeral abuse state."""

    def admit(self, rules: tuple[AdmissionRule, ...]) -> AbuseStoreResult: ...

    def check_cooldowns(self, scopes: tuple[AbuseScope, ...]) -> AbuseStoreResult: ...

    def activate_cooldown(
        self, scope: AbuseScope, delay_seconds: float
    ) -> AbuseStoreResult: ...

    def acquire_lease(
        self, scope: AbuseScope, policy: ConcurrencyPolicy
    ) -> AbuseStoreLeaseResult: ...

    def release_lease(self, scope: AbuseScope, lease_token: str) -> bool: ...


class _StateKind(Enum):
    COUNTER = "COUNTER"
    COOLDOWN = "COOLDOWN"
    CONCURRENCY = "CONCURRENCY"


@dataclass(frozen=True, slots=True)
class _StateKey:
    kind: _StateKind
    scope: AbuseScope


@dataclass(slots=True)
class _CounterEntry:
    count: int
    expires_at: float
    policy: CounterPolicy


@dataclass(slots=True)
class _CooldownEntry:
    expires_at: float


@dataclass(slots=True)
class _ConcurrencyEntry:
    leases: dict[str, float]


class InMemoryAbuseStateStore:
    """Bounded and atomic abuse state for exactly one Python process."""

    def __init__(
        self,
        *,
        maximum_entries: int,
        reserved_entries: int = 1,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if type(maximum_entries) is not int or maximum_entries < 2:
            raise ValueError("maximum entries must be at least two")
        if (
            type(reserved_entries) is not int
            or not 1 <= reserved_entries < maximum_entries
        ):
            raise ValueError("reserved entries must leave ordinary capacity")
        if not callable(clock):
            raise TypeError("abuse-state clock must be callable")
        self.maximum_entries = maximum_entries
        self.reserved_entries = reserved_entries
        self._clock = clock
        self._entries: dict[
            _StateKey, _CounterEntry | _CooldownEntry | _ConcurrencyEntry
        ] = {}
        self._lock = threading.RLock()
        self._last_time: float | None = None

    def admit(self, rules: tuple[AdmissionRule, ...]) -> AbuseStoreResult:
        _validate_rules(rules)
        with self._lock:
            now = self._now()
            self._purge_expired(now)
            limited_until: list[float] = []
            new_keys: list[_StateKey] = []
            for rule in rules:
                key = _StateKey(_StateKind.COUNTER, rule.scope)
                entry = self._entries.get(key)
                if entry is None:
                    new_keys.append(key)
                    continue
                if not isinstance(entry, _CounterEntry):
                    raise RuntimeError("abuse-state kind mismatch")
                if entry.policy != rule.policy:
                    raise ValueError("active counter scope cannot change policy")
                if entry.count >= rule.policy.limit:
                    limited_until.append(entry.expires_at)
            if limited_until:
                return AbuseStoreResult(
                    AbuseStoreStatus.LIMITED,
                    max(limited_until) - now,
                )
            if not self._has_capacity_for(new_keys):
                return AbuseStoreResult(AbuseStoreStatus.CAPACITY)
            for rule in rules:
                key = _StateKey(_StateKind.COUNTER, rule.scope)
                entry = self._entries.get(key)
                if entry is None:
                    self._entries[key] = _CounterEntry(
                        count=1,
                        expires_at=now + rule.policy.window_seconds,
                        policy=rule.policy,
                    )
                else:
                    if not isinstance(entry, _CounterEntry):
                        raise RuntimeError("abuse-state kind mismatch")
                    if entry.policy != rule.policy:
                        raise ValueError("active counter scope cannot change policy")
                    entry.count += 1
            return AbuseStoreResult(AbuseStoreStatus.ALLOWED)

    def check_cooldowns(self, scopes: tuple[AbuseScope, ...]) -> AbuseStoreResult:
        _validate_scopes(scopes)
        with self._lock:
            now = self._now()
            self._purge_expired(now)
            deadlines = []
            for scope in scopes:
                entry = self._entries.get(_StateKey(_StateKind.COOLDOWN, scope))
                if entry is not None:
                    if not isinstance(entry, _CooldownEntry):
                        raise RuntimeError("abuse-state kind mismatch")
                    deadlines.append(entry.expires_at)
            if not deadlines:
                return AbuseStoreResult(AbuseStoreStatus.ALLOWED)
            return AbuseStoreResult(AbuseStoreStatus.LIMITED, max(deadlines) - now)

    def activate_cooldown(
        self, scope: AbuseScope, delay_seconds: float
    ) -> AbuseStoreResult:
        if not isinstance(scope, AbuseScope):
            raise TypeError("cooldown requires an abuse scope")
        delay = _require_positive_finite(delay_seconds, "cooldown delay")
        with self._lock:
            now = self._now()
            self._purge_expired(now)
            key = _StateKey(_StateKind.COOLDOWN, scope)
            entry = self._entries.get(key)
            if entry is None:
                if not self._has_capacity_for([key]):
                    return AbuseStoreResult(AbuseStoreStatus.CAPACITY)
                deadline = now + delay
                self._entries[key] = _CooldownEntry(deadline)
            else:
                if not isinstance(entry, _CooldownEntry):
                    raise RuntimeError("abuse-state kind mismatch")
                entry.expires_at = max(entry.expires_at, now + delay)
                deadline = entry.expires_at
            return AbuseStoreResult(AbuseStoreStatus.LIMITED, deadline - now)

    def acquire_lease(
        self, scope: AbuseScope, policy: ConcurrencyPolicy
    ) -> AbuseStoreLeaseResult:
        if not isinstance(scope, AbuseScope) or not isinstance(
            policy, ConcurrencyPolicy
        ):
            raise TypeError("concurrency acquisition requires scope and policy")
        with self._lock:
            now = self._now()
            self._purge_expired(now)
            key = _StateKey(_StateKind.CONCURRENCY, scope)
            entry = self._entries.get(key)
            if entry is None:
                if not self._has_capacity_for([key]):
                    return AbuseStoreLeaseResult(
                        AbuseStoreResult(AbuseStoreStatus.CAPACITY)
                    )
                entry = _ConcurrencyEntry({})
                self._entries[key] = entry
            elif not isinstance(entry, _ConcurrencyEntry):
                raise RuntimeError("abuse-state kind mismatch")
            if len(entry.leases) >= policy.limit:
                retry = min(entry.leases.values()) - now
                return AbuseStoreLeaseResult(
                    AbuseStoreResult(AbuseStoreStatus.LIMITED, retry)
                )
            lease_token = secrets.token_urlsafe(24)
            entry.leases[lease_token] = now + policy.lease_seconds
            return AbuseStoreLeaseResult(
                AbuseStoreResult(AbuseStoreStatus.ALLOWED),
                lease_token,
            )

    def release_lease(self, scope: AbuseScope, lease_token: str) -> bool:
        if not isinstance(scope, AbuseScope) or not isinstance(lease_token, str):
            raise TypeError("lease release requires controlled scope and token")
        with self._lock:
            now = self._now()
            self._purge_expired(now)
            key = _StateKey(_StateKind.CONCURRENCY, scope)
            entry = self._entries.get(key)
            if entry is None:
                return False
            if not isinstance(entry, _ConcurrencyEntry):
                raise RuntimeError("abuse-state kind mismatch")
            removed = entry.leases.pop(lease_token, None) is not None
            if not entry.leases:
                del self._entries[key]
            return removed

    def entry_count(self) -> int:
        """Return current bounded entry count for diagnostics and tests."""

        with self._lock:
            now = self._now()
            self._purge_expired(now)
            return len(self._entries)

    def _now(self) -> float:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("monotonic clock must return a number")
        current = float(value)
        if not math.isfinite(current) or current < 0:
            raise ValueError("monotonic clock returned an invalid value")
        if self._last_time is not None and current < self._last_time:
            raise ValueError("monotonic clock moved backwards")
        self._last_time = current
        return current

    def _purge_expired(self, now: float) -> None:
        expired: list[_StateKey] = []
        for key, entry in self._entries.items():
            if isinstance(entry, _ConcurrencyEntry):
                expired_leases = [
                    token for token, deadline in entry.leases.items() if deadline <= now
                ]
                for token in expired_leases:
                    del entry.leases[token]
                if not entry.leases:
                    expired.append(key)
            elif entry.expires_at <= now:
                expired.append(key)
        for key in expired:
            del self._entries[key]

    def _has_capacity_for(self, keys: list[_StateKey]) -> bool:
        unique_new = {key for key in keys if key not in self._entries}
        if not unique_new:
            return True
        ordinary_existing = sum(
            not key.scope.uses_reserved_capacity for key in self._entries
        )
        ordinary_new = sum(
            not key.scope.uses_reserved_capacity for key in unique_new
        )
        ordinary_limit = self.maximum_entries - self.reserved_entries
        return (
            ordinary_existing + ordinary_new <= ordinary_limit
            and len(self._entries) + len(unique_new) <= self.maximum_entries
        )


class ConcurrencyLease:
    """One opaque expiring lease with idempotent explicit/context cleanup."""

    __slots__ = ("_store", "_scope", "_token", "_released")

    def __init__(
        self,
        store: AbuseStateStore,
        scope: AbuseScope,
        token: str,
    ) -> None:
        self._store = store
        self._scope = scope
        self._token = token
        self._released = False

    @property
    def released(self) -> bool:
        return self._released

    def release(self) -> bool:
        if self._released:
            return False
        released = self._store.release_lease(self._scope, self._token)
        self._released = True
        return released

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.release()

    def __repr__(self) -> str:
        return f"ConcurrencyLease(released={self._released}, token=<redacted>)"


@dataclass(frozen=True, slots=True)
class LeaseAcquisition:
    """Controlled concurrency decision and lease only after admission."""

    decision: AbuseDecision
    lease: ConcurrencyLease | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (self.decision.status is AbuseDecisionStatus.ALLOW) != isinstance(
            self.lease, ConcurrencyLease
        ):
            raise ValueError("only allowed concurrency acquisition may contain a lease")


class AbuseControlEngine:
    """Map expected store outcomes into controlled endpoint-neutral decisions."""

    def __init__(self, store: AbuseStateStore) -> None:
        self._store = store

    def admit(self, rules: tuple[AdmissionRule, ...]) -> AbuseDecision:
        _validate_rules(rules)
        try:
            result = self._store.admit(rules)
        except AbuseStoreUnavailable:
            return AbuseDecision.unavailable(AbuseDecisionReason.STORE_UNAVAILABLE)
        return _map_store_result(result, AbuseDecisionReason.RATE_LIMIT)

    def check_cooldowns(self, scopes: tuple[AbuseScope, ...]) -> AbuseDecision:
        _validate_scopes(scopes)
        try:
            result = self._store.check_cooldowns(scopes)
        except AbuseStoreUnavailable:
            return AbuseDecision.unavailable(AbuseDecisionReason.STORE_UNAVAILABLE)
        return _map_store_result(result, AbuseDecisionReason.COOLDOWN)

    def activate_cooldown(
        self,
        scope: AbuseScope,
        policy: CooldownPolicy,
        *,
        level: int = 1,
    ) -> AbuseDecision:
        if not isinstance(scope, AbuseScope) or not isinstance(policy, CooldownPolicy):
            raise TypeError("cooldown activation requires scope and policy")
        delay = policy.delay_for_level(level)
        try:
            result = self._store.activate_cooldown(scope, delay)
        except AbuseStoreUnavailable:
            return AbuseDecision.unavailable(AbuseDecisionReason.STORE_UNAVAILABLE)
        return _map_store_result(result, AbuseDecisionReason.COOLDOWN)

    def acquire_concurrency(
        self,
        scope: AbuseScope,
        policy: ConcurrencyPolicy,
    ) -> LeaseAcquisition:
        if not isinstance(scope, AbuseScope) or not isinstance(
            policy, ConcurrencyPolicy
        ):
            raise TypeError("concurrency acquisition requires scope and policy")
        try:
            result = self._store.acquire_lease(scope, policy)
        except AbuseStoreUnavailable:
            return LeaseAcquisition(
                AbuseDecision.unavailable(AbuseDecisionReason.STORE_UNAVAILABLE)
            )
        decision = _map_store_result(result.result, AbuseDecisionReason.CONCURRENCY)
        lease = (
            ConcurrencyLease(self._store, scope, result.lease_token)
            if decision.status is AbuseDecisionStatus.ALLOW
            and result.lease_token is not None
            else None
        )
        return LeaseAcquisition(decision, lease)


def _map_store_result(
    result: AbuseStoreResult,
    limited_reason: AbuseDecisionReason,
) -> AbuseDecision:
    if not isinstance(result, AbuseStoreResult):
        raise TypeError("abuse store returned an invalid result")
    if result.status is AbuseStoreStatus.ALLOWED:
        return AbuseDecision.allow()
    if result.status is AbuseStoreStatus.CAPACITY:
        return AbuseDecision.unavailable(AbuseDecisionReason.STORE_CAPACITY)
    if result.status is AbuseStoreStatus.LIMITED:
        if result.retry_after_seconds is None:
            raise ValueError("limited store result requires retry duration")
        return AbuseDecision.limited(
            limited_reason,
            max(1, math.ceil(result.retry_after_seconds)),
        )
    raise ValueError("unknown abuse store result")


def _validate_rules(rules: tuple[AdmissionRule, ...]) -> None:
    if type(rules) is not tuple or not rules:
        raise ValueError("admission requires a non-empty immutable rule group")
    if len(rules) > MAX_ADMISSION_SCOPES:
        raise ValueError("admission scope count exceeds the fixed maximum")
    if not all(isinstance(rule, AdmissionRule) for rule in rules):
        raise TypeError("admission group contains an invalid rule")
    scopes = tuple(rule.scope for rule in rules)
    if len(set(scopes)) != len(scopes):
        raise ValueError("admission scopes must be unique")


def _validate_scopes(scopes: tuple[AbuseScope, ...]) -> None:
    if type(scopes) is not tuple or not scopes:
        raise ValueError("operation requires a non-empty immutable scope group")
    if len(scopes) > MAX_ADMISSION_SCOPES:
        raise ValueError("scope count exceeds the fixed maximum")
    if not all(isinstance(scope, AbuseScope) for scope in scopes):
        raise TypeError("scope group contains an invalid scope")
    if len(set(scopes)) != len(scopes):
        raise ValueError("scopes must be unique")


def _require_positive_finite(value: float, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field_name} must be numeric")
    converted = float(value)
    if not math.isfinite(converted) or converted <= 0:
        raise ValueError(f"{field_name} must be positive and finite")
    return converted
