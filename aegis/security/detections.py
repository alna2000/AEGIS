"""Typed immutable outputs for deterministic security detections."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class DetectionFindingCode(str, Enum):
    REPEATED_PASSWORD_FAILURE = "REPEATED_PASSWORD_FAILURE"
    MFA_FAILURE_PATTERN = "MFA_FAILURE_PATTERN"
    MFA_CHALLENGE_EXHAUSTION = "MFA_CHALLENGE_EXHAUSTION"
    AUTHORIZATION_DENIAL_SPIKE = "AUTHORIZATION_DENIAL_SPIKE"
    AUTHORIZATION_SYSTEM_ERROR = "AUTHORIZATION_SYSTEM_ERROR"
    RESOURCE_ACCESS_PROBING = "RESOURCE_ACCESS_PROBING"
    ABUSE_PRESSURE = "ABUSE_PRESSURE"
    ABUSE_STORE_FAILURE = "ABUSE_STORE_FAILURE"
    AUDIT_SYSTEM_FAILURE = "AUDIT_SYSTEM_FAILURE"


class DetectionSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True, slots=True)
class DetectionFinding:
    """Bounded derived visibility; it is not persistent evidence or enforcement."""

    finding_code: DetectionFindingCode
    severity: DetectionSeverity
    window_start: datetime
    window_end: datetime
    subject_user_id: uuid.UUID | None
    event_count: int
    supporting_event_ids: tuple[uuid.UUID, ...]

    def __post_init__(self) -> None:
        if self.window_start.tzinfo is None or self.window_end.tzinfo is None:
            raise ValueError("detection windows must be timezone-aware")
        if self.window_start > self.window_end:
            raise ValueError("detection window is invalid")
        if type(self.event_count) is not int or self.event_count <= 0:
            raise ValueError("detection event count must be positive")
        if not 1 <= len(self.supporting_event_ids) <= 25:
            raise ValueError("supporting evidence exceeds its bound")
        if not all(isinstance(identifier, uuid.UUID) for identifier in self.supporting_event_ids):
            raise ValueError("supporting evidence IDs must be UUIDs")
