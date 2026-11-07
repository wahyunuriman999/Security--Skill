"""Evidence-driven finding lifecycle with guarded state transitions."""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum


class FindingStateError(ValueError):
    pass


class FindingStatus(str, Enum):
    IDEA = "IDEA"
    LEAD = "LEAD"
    TESTABLE = "TESTABLE"
    OBSERVED = "OBSERVED"
    VALIDATING = "VALIDATING"
    CONFIRMED = "CONFIRMED"
    PARKED = "PARKED"
    REFUTED = "REFUTED"
    DUPLICATE = "DUPLICATE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    REJECTED = "REJECTED"


_ALLOWED_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.IDEA: frozenset({FindingStatus.LEAD, FindingStatus.PARKED, FindingStatus.REJECTED}),
    FindingStatus.LEAD: frozenset({FindingStatus.TESTABLE, FindingStatus.PARKED,
                                   FindingStatus.DUPLICATE, FindingStatus.OUT_OF_SCOPE,
                                   FindingStatus.REJECTED}),
    FindingStatus.TESTABLE: frozenset({FindingStatus.OBSERVED, FindingStatus.PARKED,
                                       FindingStatus.OUT_OF_SCOPE, FindingStatus.REJECTED}),
    FindingStatus.OBSERVED: frozenset({FindingStatus.VALIDATING, FindingStatus.PARKED,
                                       FindingStatus.REFUTED, FindingStatus.DUPLICATE,
                                       FindingStatus.OUT_OF_SCOPE}),
    FindingStatus.VALIDATING: frozenset({FindingStatus.CONFIRMED, FindingStatus.REFUTED,
                                         FindingStatus.PARKED, FindingStatus.DUPLICATE,
                                         FindingStatus.OUT_OF_SCOPE, FindingStatus.REJECTED}),
    FindingStatus.CONFIRMED: frozenset(),
    FindingStatus.PARKED: frozenset(),
    FindingStatus.REFUTED: frozenset(),
    FindingStatus.DUPLICATE: frozenset(),
    FindingStatus.OUT_OF_SCOPE: frozenset(),
    FindingStatus.REJECTED: frozenset(),
}
_SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    summary: str
    status: FindingStatus = FindingStatus.IDEA
    evidence_refs: tuple[str, ...] = ()
    severity: str | None = None
    impact: str | None = None
    confidence: float | None = None

    def __post_init__(self) -> None:
        for field_name, value in (("finding_id", self.finding_id),
                                  ("title", self.title), ("summary", self.summary)):
            if not isinstance(value, str) or not value.strip():
                raise FindingStateError(f"{field_name} is required")
        if not isinstance(self.status, FindingStatus):
            raise FindingStateError("status must be a FindingStatus")
        if self.severity is not None and (
            not isinstance(self.severity, str) or self.severity not in _SEVERITIES
        ):
            raise FindingStateError("invalid severity")
        if self.impact is not None and (
            not isinstance(self.impact, str) or not self.impact.strip()
        ):
            raise FindingStateError("impact must be a non-empty string when supplied")
        if self.confidence is not None:
            if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
                raise FindingStateError("confidence must be numeric")
            if not 0.0 <= self.confidence <= 1.0:
                raise FindingStateError("confidence must be between 0 and 1")
        if not isinstance(self.evidence_refs, tuple) or any(
            not isinstance(ref, str) or not ref.strip() for ref in self.evidence_refs
        ):
            raise FindingStateError("evidence references must be non-empty strings in a tuple")

    def transition(
        self,
        target: FindingStatus,
        *,
        actor: str,
        reason: str,
        evidence_refs: tuple[str, ...] | None = None,
        severity: str | None = None,
        impact: str | None = None,
        confidence: float | None = None,
        now: datetime | None = None,
    ) -> tuple["Finding", "FindingTransition"]:
        if not isinstance(target, FindingStatus):
            raise FindingStateError("target must be a FindingStatus")
        if not isinstance(actor, str) or not isinstance(reason, str):
            raise FindingStateError("actor and transition reason must be strings")
        if target not in _ALLOWED_TRANSITIONS[self.status]:
            raise FindingStateError(f"transition_not_allowed:{self.status.value}->{target.value}")
        if not actor.strip() or not reason.strip():
            raise FindingStateError("actor and transition reason are required")

        merged_evidence = self.evidence_refs if evidence_refs is None else evidence_refs
        merged_severity = self.severity if severity is None else severity
        merged_impact = self.impact if impact is None else impact
        merged_confidence = self.confidence if confidence is None else confidence

        if merged_impact is not None and (
            not isinstance(merged_impact, str) or not merged_impact.strip()
        ):
            raise FindingStateError("impact must be a non-empty string")
        if target in {FindingStatus.OBSERVED, FindingStatus.VALIDATING, FindingStatus.CONFIRMED}:
            if not merged_evidence:
                raise FindingStateError(f"{target.value.lower()}_requires_evidence")
        if target is FindingStatus.CONFIRMED:
            if merged_severity is None or not merged_impact or not merged_impact.strip():
                raise FindingStateError("confirmed_requires_severity_and_impact")
            if merged_confidence is None:
                raise FindingStateError("confirmed_requires_confidence")

        timestamp = now or datetime.now(timezone.utc)
        if not isinstance(timestamp, datetime):
            raise FindingStateError("transition timestamp must be a datetime")
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise FindingStateError("transition timestamp must be timezone-aware")
        updated = replace(
            self, status=target, evidence_refs=tuple(merged_evidence),
            severity=merged_severity, impact=merged_impact,
            confidence=merged_confidence,
        )
        event = FindingTransition(
            finding_id=self.finding_id, from_status=self.status, to_status=target,
            actor=actor.strip(), reason=reason.strip(),
            timestamp=timestamp.astimezone(timezone.utc),
        )
        return updated, event


@dataclass(frozen=True)
class FindingTransition:
    finding_id: str
    from_status: FindingStatus
    to_status: FindingStatus
    actor: str
    reason: str
    timestamp: datetime
