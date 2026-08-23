"""Convert persisted intelligence-record facts into central resource policy."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Callable

from aegis.db.intelligence_record_repositories import (
    IntelligenceRecordCollectionEntry,
    IntelligenceRecordContent,
    IntelligenceRecordContentRepository,
    IntelligenceRecordPolicyFacts,
    IntelligenceRecordPolicyRepository,
    RecordReferencePolicyFacts,
)
from aegis.db.models import IntelligenceRecordStatus
from aegis.security.authorization import (
    AuthorizationAction,
    AuthorizationDecision,
    AuthorizationDenyReason,
    AuthorizationOutcome,
    AuthorizationResourceType,
    CONTROLLED_CLEARANCE_NAME_RANKS,
    CONTROLLED_COMPARTMENT_NAMES,
    CONTROLLED_DEPARTMENT_NAMES,
    ResourcePolicy,
    authorize,
)
from aegis.services.authentication import AuthenticatedPrincipal
from aegis.services.authorization import AuthorizationSubjectService


_RECORD_CODE_PATTERN = re.compile(r"^INT-[0-9]{5}$")
MAX_INTELLIGENCE_RECORD_COLLECTION_CANDIDATES = 100


@dataclass(frozen=True, slots=True)
class ResourcePolicyLoadResult:
    """Exactly one successful resource policy or controlled load failure."""

    record_id: uuid.UUID | None
    policy: ResourcePolicy | None
    failure_reason: AuthorizationDenyReason | None

    def __post_init__(self) -> None:
        success = (
            isinstance(self.record_id, uuid.UUID)
            and isinstance(self.policy, ResourcePolicy)
            and self.failure_reason is None
        )
        failure = (
            self.record_id is None
            and self.policy is None
            and isinstance(self.failure_reason, AuthorizationDenyReason)
        )
        if not (success or failure):
            raise ValueError("resource-policy loading requires one result state")

    @classmethod
    def success(
        cls, record_id: uuid.UUID, policy: ResourcePolicy
    ) -> ResourcePolicyLoadResult:
        return cls(record_id=record_id, policy=policy, failure_reason=None)

    @classmethod
    def failure(
        cls, reason: AuthorizationDenyReason
    ) -> ResourcePolicyLoadResult:
        return cls(record_id=None, policy=None, failure_reason=reason)


@dataclass(frozen=True, slots=True)
class IntelligenceRecordPolicyCandidate:
    """One validated content-free candidate and its central policy."""

    record_id: uuid.UUID
    record_code: str
    policy: ResourcePolicy


class ResourcePolicyCollectionFailure(Enum):
    LOAD_ERROR = "LOAD_ERROR"
    INVALID_POLICY = "INVALID_POLICY"
    CAPACITY_EXCEEDED = "CAPACITY_EXCEEDED"


@dataclass(frozen=True, slots=True)
class ResourcePolicyCollectionLoadResult:
    """Controlled all-or-nothing collection policy loading result."""

    candidates: tuple[IntelligenceRecordPolicyCandidate, ...] | None
    failure: ResourcePolicyCollectionFailure | None

    def __post_init__(self) -> None:
        success = type(self.candidates) is tuple and self.failure is None
        failure = self.candidates is None and isinstance(
            self.failure, ResourcePolicyCollectionFailure
        )
        if not (success or failure):
            raise ValueError("collection policy loading requires one result state")
        if success and not all(
            isinstance(candidate, IntelligenceRecordPolicyCandidate)
            for candidate in self.candidates or ()
        ):
            raise ValueError("collection policy candidates must be controlled")

    @classmethod
    def success(
        cls, candidates: tuple[IntelligenceRecordPolicyCandidate, ...]
    ) -> ResourcePolicyCollectionLoadResult:
        return cls(candidates, None)

    @classmethod
    def failed(
        cls, failure: ResourcePolicyCollectionFailure
    ) -> ResourcePolicyCollectionLoadResult:
        return cls(None, failure)


class IntelligenceRecordPolicyService:
    """Load, validate, and convert record facts without deciding access."""

    def __init__(self, records: IntelligenceRecordPolicyRepository) -> None:
        self._records = records

    def load(self, record_id: uuid.UUID) -> ResourcePolicyLoadResult:
        if not isinstance(record_id, uuid.UUID):
            return ResourcePolicyLoadResult.failure(
                AuthorizationDenyReason.RESOURCE_MISSING
            )
        try:
            facts = self._records.get_policy_record_by_id(record_id)
        except Exception:
            return ResourcePolicyLoadResult.failure(
                AuthorizationDenyReason.RESOURCE_LOAD_ERROR
            )
        if facts is None:
            return ResourcePolicyLoadResult.failure(
                AuthorizationDenyReason.RESOURCE_MISSING
            )
        try:
            policy = self._convert(facts)
        except Exception:
            return ResourcePolicyLoadResult.failure(
                AuthorizationDenyReason.INVALID_RESOURCE_POLICY
            )
        return ResourcePolicyLoadResult.success(facts.id, policy)

    def load_by_record_code(self, record_code: str) -> ResourcePolicyLoadResult:
        """Resolve an exact canonical code to content-free policy facts."""

        if (
            not isinstance(record_code, str)
            or _RECORD_CODE_PATTERN.fullmatch(record_code) is None
        ):
            return ResourcePolicyLoadResult.failure(
                AuthorizationDenyReason.RESOURCE_MISSING
            )
        try:
            facts = self._records.get_policy_record_by_code(record_code)
        except Exception:
            return ResourcePolicyLoadResult.failure(
                AuthorizationDenyReason.RESOURCE_LOAD_ERROR
            )
        if facts is None:
            return ResourcePolicyLoadResult.failure(
                AuthorizationDenyReason.RESOURCE_MISSING
            )
        try:
            policy = self._convert(facts)
        except Exception:
            return ResourcePolicyLoadResult.failure(
                AuthorizationDenyReason.INVALID_RESOURCE_POLICY
            )
        return ResourcePolicyLoadResult.success(facts.id, policy)

    def load_collection(
        self,
        *,
        maximum_candidates: int = MAX_INTELLIGENCE_RECORD_COLLECTION_CANDIDATES,
    ) -> ResourcePolicyCollectionLoadResult:
        """Load and validate an all-or-nothing bounded policy collection."""

        if type(maximum_candidates) is not int or maximum_candidates <= 0:
            return ResourcePolicyCollectionLoadResult.failed(
                ResourcePolicyCollectionFailure.INVALID_POLICY
            )
        try:
            facts_collection = self._records.list_policy_records(
                limit=maximum_candidates + 1
            )
        except Exception:
            return ResourcePolicyCollectionLoadResult.failed(
                ResourcePolicyCollectionFailure.LOAD_ERROR
            )
        if type(facts_collection) is not tuple:
            return ResourcePolicyCollectionLoadResult.failed(
                ResourcePolicyCollectionFailure.INVALID_POLICY
            )
        if len(facts_collection) > maximum_candidates:
            return ResourcePolicyCollectionLoadResult.failed(
                ResourcePolicyCollectionFailure.CAPACITY_EXCEEDED
            )

        candidates: list[IntelligenceRecordPolicyCandidate] = []
        record_ids: set[uuid.UUID] = set()
        record_codes: set[str] = set()
        try:
            for facts in facts_collection:
                policy = self._convert(facts)
                if facts.id in record_ids or facts.record_code in record_codes:
                    raise ValueError("duplicate collection candidate")
                record_ids.add(facts.id)
                record_codes.add(facts.record_code)
                candidates.append(
                    IntelligenceRecordPolicyCandidate(
                        record_id=facts.id,
                        record_code=facts.record_code,
                        policy=policy,
                    )
                )
        except Exception:
            return ResourcePolicyCollectionLoadResult.failed(
                ResourcePolicyCollectionFailure.INVALID_POLICY
            )
        return ResourcePolicyCollectionLoadResult.success(tuple(candidates))

    @staticmethod
    def _convert(facts: IntelligenceRecordPolicyFacts) -> ResourcePolicy:
        if not isinstance(facts, IntelligenceRecordPolicyFacts):
            raise ValueError("unexpected record policy facts")
        if (
            not isinstance(facts.id, uuid.UUID)
            or not isinstance(facts.created_by_user_id, uuid.UUID)
            or not isinstance(facts.record_code, str)
            or _RECORD_CODE_PATTERN.fullmatch(facts.record_code) is None
            or not _valid_timestamp(facts.created_at)
            or not _valid_timestamp(facts.updated_at)
            or facts.updated_at < facts.created_at
        ):
            raise ValueError("invalid record identity or lifecycle facts")

        try:
            status = IntelligenceRecordStatus(facts.status)
        except (TypeError, ValueError) as error:
            raise ValueError("invalid record lifecycle") from error
        if status is IntelligenceRecordStatus.RETIRED:
            if (
                not _valid_timestamp(facts.retired_at)
                or facts.retired_at < facts.created_at
            ):
                raise ValueError("invalid retired lifecycle")
        elif facts.retired_at is not None:
            raise ValueError("non-retired record has retirement timestamp")

        classification = facts.classification
        if (
            not isinstance(facts.classification_level_id, uuid.UUID)
            or classification is None
            or not isinstance(classification.id, uuid.UUID)
            or classification.id != facts.classification_level_id
            or not isinstance(classification.name, str)
            or type(classification.rank) is not int
            or CONTROLLED_CLEARANCE_NAME_RANKS.get(classification.name)
            != classification.rank
        ):
            raise ValueError("invalid controlled classification")

        department_ids = _validated_reference_ids(
            facts.department_relationships,
            facts.id,
            CONTROLLED_DEPARTMENT_NAMES,
        )
        if status is not IntelligenceRecordStatus.DRAFT and not department_ids:
            raise ValueError("non-draft record requires a department policy")
        compartment_ids = _validated_reference_ids(
            facts.compartment_relationships,
            facts.id,
            CONTROLLED_COMPARTMENT_NAMES,
        )

        return ResourcePolicy(
            resource_type=AuthorizationResourceType.INTELLIGENCE_RECORD,
            usable=status is IntelligenceRecordStatus.ACTIVE,
            classification_rank=classification.rank,
            authorized_department_ids=department_ids,
            required_compartment_ids=compartment_ids,
        )


def _validated_reference_ids(
    relationships: object,
    record_id: uuid.UUID,
    controlled_names: frozenset[str],
) -> frozenset[uuid.UUID]:
    if type(relationships) is not tuple:
        raise ValueError("record relationships must be an immutable tuple")
    seen: set[uuid.UUID] = set()
    for relationship in relationships:
        if not isinstance(relationship, RecordReferencePolicyFacts):
            raise ValueError("malformed record relationship")
        reference = relationship.reference
        if (
            relationship.record_id != record_id
            or not isinstance(relationship.reference_id, uuid.UUID)
            or relationship.reference_id in seen
            or reference is None
            or not isinstance(reference.id, uuid.UUID)
            or reference.id != relationship.reference_id
            or not isinstance(reference.name, str)
            or reference.name not in controlled_names
            or reference.is_active is not True
            or reference.retired_at is not None
        ):
            raise ValueError("invalid record reference state")
        seen.add(relationship.reference_id)
    return frozenset(seen)


def _valid_timestamp(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )


@dataclass(frozen=True, slots=True)
class AuthorizedIntelligenceRecord:
    """Validated service representation safe for the outward API schema."""

    record_code: str
    title: str
    summary: str | None
    content: str
    classification: str


class IntelligenceRecordReadOutcome(Enum):
    AUTHORIZED = "AUTHORIZED"
    INACCESSIBLE = "INACCESSIBLE"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class IntelligenceRecordReadResult:
    """Controlled read outcome that cannot carry content unless authorized."""

    outcome: IntelligenceRecordReadOutcome
    record: AuthorizedIntelligenceRecord | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, IntelligenceRecordReadOutcome):
            raise ValueError("record read outcome must be controlled")
        if (self.outcome is IntelligenceRecordReadOutcome.AUTHORIZED) != (
            isinstance(self.record, AuthorizedIntelligenceRecord)
        ):
            raise ValueError("only an authorized read may contain a record")

    @classmethod
    def authorized(
        cls, record: AuthorizedIntelligenceRecord
    ) -> IntelligenceRecordReadResult:
        return cls(IntelligenceRecordReadOutcome.AUTHORIZED, record)

    @classmethod
    def inaccessible(cls) -> IntelligenceRecordReadResult:
        return cls(IntelligenceRecordReadOutcome.INACCESSIBLE)

    @classmethod
    def authentication_required(cls) -> IntelligenceRecordReadResult:
        return cls(IntelligenceRecordReadOutcome.AUTHENTICATION_REQUIRED)

    @classmethod
    def unavailable(cls) -> IntelligenceRecordReadResult:
        return cls(IntelligenceRecordReadOutcome.UNAVAILABLE)


class IntelligenceRecordReadService:
    """Authorize one record candidate before loading its sensitive content."""

    def __init__(
        self,
        subjects: AuthorizationSubjectService,
        policies: IntelligenceRecordPolicyService,
        content: IntelligenceRecordContentRepository,
        *,
        evaluator: Callable[..., AuthorizationDecision] = authorize,
    ) -> None:
        self._subjects = subjects
        self._policies = policies
        self._content = content
        self._evaluator = evaluator

    def read(
        self,
        principal: AuthenticatedPrincipal,
        record_code: str,
    ) -> IntelligenceRecordReadResult:
        """Return content only after current facts produce explicit ALLOW."""

        try:
            subject_result = self._subjects.load(principal)
            if (
                subject_result.failure_reason
                is AuthorizationDenyReason.SUBJECT_LOAD_ERROR
            ):
                return IntelligenceRecordReadResult.unavailable()
            if subject_result.subject is None:
                return IntelligenceRecordReadResult.authentication_required()
            subject = subject_result.subject
            if subject.account_usable is not True:
                return IntelligenceRecordReadResult.authentication_required()

            policy_result = self._policies.load_by_record_code(record_code)
            if (
                policy_result.failure_reason
                is AuthorizationDenyReason.RESOURCE_LOAD_ERROR
            ):
                return IntelligenceRecordReadResult.unavailable()
            if policy_result.policy is None or policy_result.record_id is None:
                return IntelligenceRecordReadResult.inaccessible()

            decision = self._evaluator(
                subject,
                AuthorizationAction.READ,
                policy_result.policy,
            )
            if not isinstance(decision, AuthorizationDecision):
                return IntelligenceRecordReadResult.unavailable()
            if decision.outcome is not AuthorizationOutcome.ALLOW:
                if (
                    decision.deny_reason
                    is AuthorizationDenyReason.POLICY_EVALUATION_ERROR
                ):
                    return IntelligenceRecordReadResult.unavailable()
                return IntelligenceRecordReadResult.inaccessible()

            loaded = self._content.get_content_record_by_id(policy_result.record_id)
            if loaded is None:
                return IntelligenceRecordReadResult.inaccessible()
            authorized = self._validate_content(
                loaded,
                policy_result.record_id,
                record_code,
                policy_result.policy,
            )
            return IntelligenceRecordReadResult.authorized(authorized)
        except Exception:
            return IntelligenceRecordReadResult.unavailable()

    @staticmethod
    def _validate_content(
        loaded: IntelligenceRecordContent,
        authorized_id: uuid.UUID,
        authorized_code: str,
        policy: ResourcePolicy,
    ) -> AuthorizedIntelligenceRecord:
        if (
            not isinstance(loaded, IntelligenceRecordContent)
            or loaded.id != authorized_id
            or loaded.record_code != authorized_code
            or _RECORD_CODE_PATTERN.fullmatch(loaded.record_code) is None
            or not isinstance(loaded.title, str)
            or not 1 <= len(loaded.title) <= 160
            or loaded.title != loaded.title.strip()
            or (
                loaded.summary is not None
                and (
                    not isinstance(loaded.summary, str)
                    or not 1 <= len(loaded.summary) <= 1000
                    or loaded.summary != loaded.summary.strip()
                )
            )
            or not isinstance(loaded.content, str)
            or not 1 <= len(loaded.content) <= 10000
            or CONTROLLED_CLEARANCE_NAME_RANKS.get(loaded.classification)
            != policy.classification_rank
            or loaded.status != IntelligenceRecordStatus.ACTIVE.value
        ):
            raise ValueError("inconsistent authorized content projection")
        return AuthorizedIntelligenceRecord(
            record_code=loaded.record_code,
            title=loaded.title,
            summary=loaded.summary,
            content=loaded.content,
            classification=loaded.classification,
        )


@dataclass(frozen=True, slots=True)
class AuthorizedIntelligenceRecordCollectionEntry:
    """Validated metadata safe for one outward collection entry."""

    record_code: str
    title: str
    classification: str


class IntelligenceRecordCollectionReadOutcome(Enum):
    AUTHORIZED = "AUTHORIZED"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class IntelligenceRecordCollectionReadResult:
    """Controlled collection result with entries only on success."""

    outcome: IntelligenceRecordCollectionReadOutcome
    entries: tuple[AuthorizedIntelligenceRecordCollectionEntry, ...] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, IntelligenceRecordCollectionReadOutcome):
            raise ValueError("collection read outcome must be controlled")
        authorized = self.outcome is IntelligenceRecordCollectionReadOutcome.AUTHORIZED
        if authorized != (type(self.entries) is tuple):
            raise ValueError("only an authorized collection may contain entries")
        if authorized and not all(
            isinstance(entry, AuthorizedIntelligenceRecordCollectionEntry)
            for entry in self.entries or ()
        ):
            raise ValueError("collection entries must be controlled")

    @classmethod
    def authorized(
        cls,
        entries: tuple[AuthorizedIntelligenceRecordCollectionEntry, ...],
    ) -> IntelligenceRecordCollectionReadResult:
        return cls(IntelligenceRecordCollectionReadOutcome.AUTHORIZED, entries)

    @classmethod
    def authentication_required(cls) -> IntelligenceRecordCollectionReadResult:
        return cls(IntelligenceRecordCollectionReadOutcome.AUTHENTICATION_REQUIRED)

    @classmethod
    def unavailable(cls) -> IntelligenceRecordCollectionReadResult:
        return cls(IntelligenceRecordCollectionReadOutcome.UNAVAILABLE)


class IntelligenceRecordCollectionReadService:
    """Authorize a bounded collection before loading any outward metadata."""

    def __init__(
        self,
        subjects: AuthorizationSubjectService,
        policies: IntelligenceRecordPolicyService,
        content: IntelligenceRecordContentRepository,
        *,
        evaluator: Callable[..., AuthorizationDecision] = authorize,
    ) -> None:
        self._subjects = subjects
        self._policies = policies
        self._content = content
        self._evaluator = evaluator

    def read(
        self, principal: AuthenticatedPrincipal
    ) -> IntelligenceRecordCollectionReadResult:
        """Return only metadata for candidates explicitly allowed twice."""

        try:
            subject_result = self._subjects.load(principal)
            if (
                subject_result.failure_reason
                is AuthorizationDenyReason.SUBJECT_LOAD_ERROR
            ):
                return IntelligenceRecordCollectionReadResult.unavailable()
            if subject_result.subject is None:
                return IntelligenceRecordCollectionReadResult.authentication_required()
            subject = subject_result.subject
            if subject.account_usable is not True:
                return IntelligenceRecordCollectionReadResult.authentication_required()

            policy_result = self._policies.load_collection()
            if policy_result.candidates is None:
                return IntelligenceRecordCollectionReadResult.unavailable()

            allowed: list[IntelligenceRecordPolicyCandidate] = []
            for candidate in policy_result.candidates:
                search = self._evaluate(
                    subject, AuthorizationAction.SEARCH, candidate.policy
                )
                if search is None:
                    return IntelligenceRecordCollectionReadResult.unavailable()
                if search.outcome is not AuthorizationOutcome.ALLOW:
                    continue

                read = self._evaluate(
                    subject, AuthorizationAction.READ, candidate.policy
                )
                if read is None:
                    return IntelligenceRecordCollectionReadResult.unavailable()
                if read.outcome is not AuthorizationOutcome.ALLOW:
                    continue
                allowed.append(candidate)

            if not allowed:
                return IntelligenceRecordCollectionReadResult.authorized(())

            projections = self._content.get_collection_entries_by_ids(
                tuple(candidate.record_id for candidate in allowed)
            )
            entries = self._validate_collection(projections, tuple(allowed))
            return IntelligenceRecordCollectionReadResult.authorized(entries)
        except Exception:
            return IntelligenceRecordCollectionReadResult.unavailable()

    def _evaluate(
        self,
        subject: object,
        action: AuthorizationAction,
        policy: ResourcePolicy,
    ) -> AuthorizationDecision | None:
        decision = self._evaluator(subject, action, policy)
        if not isinstance(decision, AuthorizationDecision):
            return None
        if decision.deny_reason is AuthorizationDenyReason.POLICY_EVALUATION_ERROR:
            return None
        return decision

    @staticmethod
    def _validate_collection(
        projections: object,
        allowed: tuple[IntelligenceRecordPolicyCandidate, ...],
    ) -> tuple[AuthorizedIntelligenceRecordCollectionEntry, ...]:
        if type(projections) is not tuple or len(projections) != len(allowed):
            raise ValueError("incomplete collection representation")
        candidate_by_id = {candidate.record_id: candidate for candidate in allowed}
        if len(candidate_by_id) != len(allowed):
            raise ValueError("duplicate authorized collection candidate")

        seen_ids: set[uuid.UUID] = set()
        entries: list[AuthorizedIntelligenceRecordCollectionEntry] = []
        for projection in projections:
            if not isinstance(projection, IntelligenceRecordCollectionEntry):
                raise ValueError("malformed collection representation")
            candidate = candidate_by_id.get(projection.id)
            if candidate is None or projection.id in seen_ids:
                raise ValueError("unexpected collection representation")
            if (
                projection.record_code != candidate.record_code
                or _RECORD_CODE_PATTERN.fullmatch(projection.record_code) is None
                or not isinstance(projection.title, str)
                or not 1 <= len(projection.title) <= 160
                or projection.title != projection.title.strip()
                or CONTROLLED_CLEARANCE_NAME_RANKS.get(projection.classification)
                != candidate.policy.classification_rank
                or projection.status != IntelligenceRecordStatus.ACTIVE.value
            ):
                raise ValueError("inconsistent collection representation")
            seen_ids.add(projection.id)
            entries.append(
                AuthorizedIntelligenceRecordCollectionEntry(
                    record_code=projection.record_code,
                    title=projection.title,
                    classification=projection.classification,
                )
            )
        return tuple(sorted(entries, key=lambda entry: entry.record_code))
