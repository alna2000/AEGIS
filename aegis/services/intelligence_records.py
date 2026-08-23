"""Convert persisted intelligence-record facts into central resource policy."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Callable

from aegis.db.intelligence_record_repositories import (
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
