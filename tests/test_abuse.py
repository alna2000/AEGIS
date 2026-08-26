"""Deterministic tests for the bounded single-process abuse-control core."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import threading

import pytest

from aegis.security.abuse import (
    MAX_ADMISSION_SCOPES,
    MAX_CONCURRENCY_LEASES_PER_SCOPE,
    AbuseControlEngine,
    AbuseDecisionReason,
    AbuseDecisionStatus,
    AbuseScope,
    AbuseScopeKind,
    AbuseStoreUnavailable,
    AbuseStoreResult,
    AbuseStoreStatus,
    AdmissionRule,
    ConcurrencyPolicy,
    CooldownPolicy,
    CorrelationKeyDeriver,
    CounterPolicy,
    FixedAbuseScope,
    InMemoryAbuseStateStore,
)


@dataclass
class MutableMonotonicClock:
    value: float = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def engine_and_clock(
    *, maximum_entries: int = 32, reserved_entries: int = 1
) -> tuple[AbuseControlEngine, InMemoryAbuseStateStore, MutableMonotonicClock]:
    clock = MutableMonotonicClock()
    store = InMemoryAbuseStateStore(
        maximum_entries=maximum_entries,
        reserved_entries=reserved_entries,
        clock=clock,
    )
    return AbuseControlEngine(store), store, clock


def fixed_rule(
    identifier: FixedAbuseScope = FixedAbuseScope.LOGIN_ENDPOINT,
    *,
    limit: int = 2,
    window_seconds: float = 10,
) -> AdmissionRule:
    return AdmissionRule(
        AbuseScope.fixed(identifier),
        CounterPolicy(limit=limit, window_seconds=window_seconds),
    )


def correlated_scope(value: str, *, kind: AbuseScopeKind = AbuseScopeKind.IDENTITY):
    deriver = CorrelationKeyDeriver(b"k" * 32)
    return AbuseScope.correlated(kind, deriver.derive(value))


def test_counter_allows_first_and_last_slots_then_returns_rounded_retry() -> None:
    engine, _, clock = engine_and_clock()
    rule = fixed_rule(limit=2, window_seconds=10.25)

    assert engine.admit((rule,)).status is AbuseDecisionStatus.ALLOW
    assert engine.admit((rule,)).status is AbuseDecisionStatus.ALLOW
    clock.advance(0.5)
    rejected = engine.admit((rule,))

    assert rejected.status is AbuseDecisionStatus.LIMITED
    assert rejected.reason is AbuseDecisionReason.RATE_LIMIT
    assert rejected.retry_after_seconds == 10


def test_counter_window_expires_using_injected_monotonic_time() -> None:
    engine, store, clock = engine_and_clock()
    rule = fixed_rule(limit=1, window_seconds=5)

    assert engine.admit((rule,)).status is AbuseDecisionStatus.ALLOW
    assert engine.admit((rule,)).status is AbuseDecisionStatus.LIMITED
    clock.advance(5)
    assert store.entry_count() == 0
    assert engine.admit((rule,)).status is AbuseDecisionStatus.ALLOW


def test_clock_regression_is_a_programming_error_not_an_ordinary_limit() -> None:
    engine, _, clock = engine_and_clock()
    assert engine.admit((fixed_rule(),)).status is AbuseDecisionStatus.ALLOW

    clock.value -= 1
    with pytest.raises(ValueError, match="monotonic clock moved backwards"):
        engine.admit((fixed_rule(),))


def test_concurrent_counter_calls_cannot_oversubscribe_final_slot() -> None:
    engine, _, _ = engine_and_clock()
    rule = fixed_rule(limit=3, window_seconds=60)
    workers = 12
    barrier = threading.Barrier(workers)

    def attempt() -> AbuseDecisionStatus:
        barrier.wait()
        return engine.admit((rule,)).status

    with ThreadPoolExecutor(max_workers=workers) as executor:
        statuses = list(executor.map(lambda _index: attempt(), range(workers)))

    assert statuses.count(AbuseDecisionStatus.ALLOW) == 3
    assert statuses.count(AbuseDecisionStatus.LIMITED) == workers - 3


def test_multi_scope_admission_consumes_all_scopes_atomically() -> None:
    engine, _, _ = engine_and_clock()
    global_rule = fixed_rule(FixedAbuseScope.GLOBAL, limit=2)
    identity_rule = AdmissionRule(
        correlated_scope("synthetic.user"), CounterPolicy(1, 10)
    )

    assert engine.admit((global_rule, identity_rule)).status is AbuseDecisionStatus.ALLOW
    limited = engine.admit((global_rule, identity_rule))
    assert limited.status is AbuseDecisionStatus.LIMITED

    # Rejection by identity did not partially consume the final global slot.
    assert engine.admit((global_rule,)).status is AbuseDecisionStatus.ALLOW
    assert engine.admit((global_rule,)).status is AbuseDecisionStatus.LIMITED


def test_multi_scope_capacity_failure_does_not_partially_consume() -> None:
    engine, _, _ = engine_and_clock(maximum_entries=3, reserved_entries=1)
    existing = AdmissionRule(correlated_scope("existing"), CounterPolicy(1, 10))
    first_new = AdmissionRule(correlated_scope("first-new"), CounterPolicy(1, 10))
    second_new = AdmissionRule(correlated_scope("second-new"), CounterPolicy(1, 10))
    assert engine.admit((existing,)).status is AbuseDecisionStatus.ALLOW

    unavailable = engine.admit((first_new, second_new))
    assert unavailable.status is AbuseDecisionStatus.UNAVAILABLE
    assert unavailable.reason is AbuseDecisionReason.STORE_CAPACITY

    # One ordinary slot remains, proving neither failed scope was inserted.
    assert engine.admit((first_new,)).status is AbuseDecisionStatus.ALLOW


def test_multi_scope_group_is_bounded_and_requires_unique_scopes() -> None:
    engine, _, _ = engine_and_clock(maximum_entries=32)
    rules = tuple(
        AdmissionRule(correlated_scope(f"identity-{index}"), CounterPolicy(1, 10))
        for index in range(MAX_ADMISSION_SCOPES + 1)
    )
    with pytest.raises(ValueError, match="fixed maximum"):
        engine.admit(rules)

    duplicate = fixed_rule()
    with pytest.raises(ValueError, match="unique"):
        engine.admit((duplicate, duplicate))


def test_active_counter_scope_cannot_silently_change_policy() -> None:
    engine, _, _ = engine_and_clock()
    assert engine.admit((fixed_rule(limit=1),)).status is AbuseDecisionStatus.ALLOW
    with pytest.raises(ValueError, match="cannot change policy"):
        engine.admit((fixed_rule(limit=2),))


def test_expired_entries_free_capacity_and_store_never_exceeds_bound() -> None:
    engine, store, clock = engine_and_clock(maximum_entries=3, reserved_entries=1)
    first = AdmissionRule(correlated_scope("one"), CounterPolicy(1, 5))
    second = AdmissionRule(correlated_scope("two"), CounterPolicy(1, 5))
    third = AdmissionRule(correlated_scope("three"), CounterPolicy(1, 5))
    assert engine.admit((first,)).status is AbuseDecisionStatus.ALLOW
    assert engine.admit((second,)).status is AbuseDecisionStatus.ALLOW
    assert engine.admit((third,)).reason is AbuseDecisionReason.STORE_CAPACITY
    assert store.entry_count() == 2

    clock.advance(5)
    assert engine.admit((third,)).status is AbuseDecisionStatus.ALLOW
    assert store.entry_count() == 1


def test_high_cardinality_cannot_consume_reserved_global_capacity() -> None:
    engine, store, _ = engine_and_clock(maximum_entries=4, reserved_entries=1)
    decisions = [
        engine.admit(
            (
                AdmissionRule(
                    correlated_scope(f"attacker-value-{index}"),
                    CounterPolicy(1, 60),
                ),
            )
        )
        for index in range(20)
    ]

    assert sum(
        decision.status is AbuseDecisionStatus.ALLOW for decision in decisions
    ) == 3
    assert all(
        decision.reason is AbuseDecisionReason.STORE_CAPACITY
        for decision in decisions[3:]
    )
    assert store.entry_count() == 3

    global_decision = engine.admit(
        (fixed_rule(FixedAbuseScope.GLOBAL, limit=1, window_seconds=60),)
    )
    assert global_decision.status is AbuseDecisionStatus.ALLOW
    assert store.entry_count() == 4


def test_fixed_malformed_scope_needs_no_request_content() -> None:
    scope = AbuseScope.fixed(FixedAbuseScope.MALFORMED_LOGIN_IDENTITY)
    assert scope.kind is AbuseScopeKind.FIXED
    assert "malformed-login-identity" not in repr(scope)
    with pytest.raises(TypeError):
        AbuseScope(  # type: ignore[call-arg]
            AbuseScopeKind.IDENTITY,
            b"attacker-controlled",
            False,
        )


def test_cooldown_progresses_is_bounded_and_expires() -> None:
    engine, _, clock = engine_and_clock()
    scope = correlated_scope("cooldown-subject")
    policy = CooldownPolicy(initial_delay_seconds=2, maximum_delay_seconds=7)

    first = engine.activate_cooldown(scope, policy, level=1)
    assert first.status is AbuseDecisionStatus.LIMITED
    assert first.retry_after_seconds == 2
    clock.advance(2)
    assert engine.check_cooldowns((scope,)).status is AbuseDecisionStatus.ALLOW

    maximum = engine.activate_cooldown(scope, policy, level=50)
    assert maximum.retry_after_seconds == 7
    clock.advance(6.1)
    assert engine.check_cooldowns((scope,)).retry_after_seconds == 1
    clock.advance(0.9)
    assert engine.check_cooldowns((scope,)).status is AbuseDecisionStatus.ALLOW


def test_cooldown_capacity_failure_is_controlled() -> None:
    engine, _, _ = engine_and_clock(maximum_entries=2, reserved_entries=1)
    policy = CooldownPolicy(1, 5)
    assert engine.activate_cooldown(
        correlated_scope("first"), policy
    ).status is AbuseDecisionStatus.LIMITED
    unavailable = engine.activate_cooldown(correlated_scope("second"), policy)
    assert unavailable.status is AbuseDecisionStatus.UNAVAILABLE
    assert unavailable.reason is AbuseDecisionReason.STORE_CAPACITY


def test_concurrency_acquisition_release_and_expiry_recovery() -> None:
    engine, _, clock = engine_and_clock()
    scope = correlated_scope("session", kind=AbuseScopeKind.SESSION)
    policy = ConcurrencyPolicy(limit=2, lease_seconds=5)

    first = engine.acquire_concurrency(scope, policy)
    second = engine.acquire_concurrency(scope, policy)
    rejected = engine.acquire_concurrency(scope, policy)
    assert first.lease is not None and second.lease is not None
    assert rejected.decision.status is AbuseDecisionStatus.LIMITED
    assert rejected.decision.reason is AbuseDecisionReason.CONCURRENCY
    assert rejected.decision.retry_after_seconds == 5

    assert first.lease.release() is True
    assert first.lease.release() is False
    replacement = engine.acquire_concurrency(scope, policy)
    assert replacement.decision.status is AbuseDecisionStatus.ALLOW

    clock.advance(5)
    recovered = engine.acquire_concurrency(scope, policy)
    assert recovered.decision.status is AbuseDecisionStatus.ALLOW


def test_concurrency_context_manager_releases_after_exception() -> None:
    engine, _, _ = engine_and_clock()
    scope = correlated_scope("collection", kind=AbuseScopeKind.SESSION)
    policy = ConcurrencyPolicy(limit=1, lease_seconds=30)
    acquired = engine.acquire_concurrency(scope, policy)
    assert acquired.lease is not None

    with pytest.raises(RuntimeError, match="synthetic work failure"):
        with acquired.lease:
            raise RuntimeError("synthetic work failure")

    assert acquired.lease.released is True
    assert engine.acquire_concurrency(scope, policy).decision.status is (
        AbuseDecisionStatus.ALLOW
    )


def test_concurrent_lease_acquisition_respects_limit() -> None:
    engine, _, _ = engine_and_clock()
    scope = correlated_scope("expensive-work", kind=AbuseScopeKind.SESSION)
    policy = ConcurrencyPolicy(limit=2, lease_seconds=30)
    workers = 10
    barrier = threading.Barrier(workers)

    def acquire():
        barrier.wait()
        return engine.acquire_concurrency(scope, policy)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(lambda _index: acquire(), range(workers)))

    assert sum(
        result.decision.status is AbuseDecisionStatus.ALLOW for result in results
    ) == 2


def test_concurrency_policy_has_a_hard_per_scope_capacity_bound() -> None:
    with pytest.raises(ValueError, match="safe bound"):
        ConcurrencyPolicy(
            limit=MAX_CONCURRENCY_LEASES_PER_SCOPE + 1,
            lease_seconds=30,
        )


def test_correlation_is_deterministic_distinct_keyed_and_plaintext_free() -> None:
    first = CorrelationKeyDeriver(b"a" * 32)
    same = CorrelationKeyDeriver(b"a" * 32)
    other = CorrelationKeyDeriver(b"b" * 32)
    plaintext = "synthetic.user"

    first_key = first.derive(plaintext)
    assert first_key == same.derive(plaintext)
    assert first_key != first.derive("synthetic.other")
    assert first_key != other.derive(plaintext)
    assert first_key == first.derive(plaintext.encode("utf-8"))
    assert plaintext not in repr(first_key)
    assert plaintext not in repr(AbuseScope.correlated(AbuseScopeKind.IDENTITY, first_key))


def test_correlation_secret_and_digest_are_suppressed_from_repr() -> None:
    secret = b"synthetic-secret-material-32bytes!"
    assert len(secret) >= 32
    deriver = CorrelationKeyDeriver(secret)
    derived = deriver.derive("bounded-input")

    assert secret.decode("ascii") not in repr(deriver)
    assert derived._digest.hex() not in repr(derived)
    assert "bounded-input" not in repr(derived)


@pytest.mark.parametrize("value", ["", b"", "x" * 17, b"x" * 17])
def test_correlation_rejects_empty_or_oversized_input_without_echo(value) -> None:
    deriver = CorrelationKeyDeriver(b"k" * 32, max_input_bytes=16)
    with pytest.raises(ValueError) as raised:
        deriver.derive(value)
    assert "x" * 17 not in str(raised.value)


class FailingStore:
    def _fail(self):
        raise AbuseStoreUnavailable("synthetic expected outage")

    def admit(self, _rules):
        return self._fail()

    def check_cooldowns(self, _scopes):
        return self._fail()

    def activate_cooldown(self, _scope, _delay_seconds):
        return self._fail()

    def acquire_lease(self, _scope, _policy):
        return self._fail()

    def release_lease(self, _scope, _lease_token):
        return self._fail()


class ProgrammingErrorStore(FailingStore):
    def admit(self, _rules):
        raise RuntimeError("synthetic programming defect")


def test_expected_store_failure_maps_to_controlled_unavailable_decisions() -> None:
    engine = AbuseControlEngine(FailingStore())
    scope = AbuseScope.fixed(FixedAbuseScope.GLOBAL)

    for decision in (
        engine.admit((fixed_rule(FixedAbuseScope.GLOBAL),)),
        engine.check_cooldowns((scope,)),
        engine.activate_cooldown(scope, CooldownPolicy(1, 2)),
        engine.acquire_concurrency(scope, ConcurrencyPolicy(1, 2)).decision,
    ):
        assert decision.status is AbuseDecisionStatus.UNAVAILABLE
        assert decision.reason is AbuseDecisionReason.STORE_UNAVAILABLE
        assert decision.retry_after_seconds is None


def test_programming_errors_are_not_silently_converted_to_limits() -> None:
    engine = AbuseControlEngine(ProgrammingErrorStore())
    with pytest.raises(RuntimeError, match="programming defect"):
        engine.admit((fixed_rule(FixedAbuseScope.GLOBAL),))


def test_store_result_rejects_malformed_adapter_states() -> None:
    with pytest.raises(ValueError, match="controlled"):
        AbuseStoreResult("LIMITED", 1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="retry duration"):
        AbuseStoreResult(AbuseStoreStatus.ALLOWED, 1)
    with pytest.raises(ValueError, match="positive and finite"):
        AbuseStoreResult(AbuseStoreStatus.LIMITED, 0)


def test_lease_and_decisions_do_not_expose_internal_credentials() -> None:
    engine, _, _ = engine_and_clock()
    scope = correlated_scope("opaque-session-value", kind=AbuseScopeKind.SESSION)
    acquisition = engine.acquire_concurrency(scope, ConcurrencyPolicy(1, 5))
    assert acquisition.lease is not None

    representation = repr(acquisition.lease)
    assert "opaque-session-value" not in representation
    assert "token=<redacted>" in representation
    assert "opaque-session-value" not in repr(acquisition)
