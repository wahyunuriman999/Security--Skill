import unittest
from datetime import datetime, timezone

from apex.core.findings import Finding, FindingStateError, FindingStatus


NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)


class TestFindingLifecycle(unittest.TestCase):
    def test_happy_path_requires_evidence_and_confirmed_impact(self):
        finding = Finding("APEX-001", "Example issue", "Initial hypothesis")
        finding, event = finding.transition(
            FindingStatus.LEAD, actor="analyst", reason="Initial triage", now=NOW)
        self.assertEqual(event.from_status, FindingStatus.IDEA)
        finding, _ = finding.transition(
            FindingStatus.TESTABLE, actor="analyst", reason="Reproducible hypothesis", now=NOW)
        with self.assertRaisesRegex(FindingStateError, "observed_requires_evidence"):
            finding.transition(FindingStatus.OBSERVED, actor="analyst", reason="Observed", now=NOW)
        finding, _ = finding.transition(
            FindingStatus.OBSERVED, actor="analyst", reason="Evidence captured",
            evidence_refs=("evidence://sha256/abc",), now=NOW)
        finding, _ = finding.transition(
            FindingStatus.VALIDATING, actor="reviewer", reason="Independent validation", now=NOW)
        with self.assertRaisesRegex(FindingStateError, "confirmed_requires_severity"):
            finding.transition(FindingStatus.CONFIRMED, actor="reviewer",
                               reason="Validation passed", now=NOW)
        confirmed, event = finding.transition(
            FindingStatus.CONFIRMED, actor="reviewer", reason="Impact reproduced",
            severity="high", impact="Unauthorized access to another user's record",
            confidence=0.95, now=NOW)
        self.assertEqual(confirmed.status, FindingStatus.CONFIRMED)
        self.assertEqual(event.to_status, FindingStatus.CONFIRMED)

    def test_illegal_transition_rejected(self):
        finding = Finding("APEX-002", "Test", "Summary")
        with self.assertRaisesRegex(FindingStateError, "transition_not_allowed"):
            finding.transition(FindingStatus.CONFIRMED, actor="analyst",
                               reason="Skip all gates", now=NOW)

    def test_terminal_state_cannot_be_reopened(self):
        finding = Finding("APEX-003", "Test", "Summary")
        parked, _ = finding.transition(FindingStatus.PARKED, actor="analyst",
                                       reason="Insufficient priority", now=NOW)
        with self.assertRaises(FindingStateError):
            parked.transition(FindingStatus.LEAD, actor="analyst",
                              reason="Reopen", now=NOW)

    def test_invalid_severity_and_impact_types_rejected(self):
        with self.assertRaisesRegex(FindingStateError, "invalid severity"):
            Finding("APEX-005", "Test", "Summary", severity=["critical"])
        with self.assertRaisesRegex(FindingStateError, "impact must be"):
            Finding("APEX-006", "Test", "Summary", impact=123)
        with self.assertRaisesRegex(FindingStateError, "impact must be"):
            Finding("APEX-007", "Test", "Summary", impact="   ")

    def test_non_datetime_transition_timestamp_rejected(self):
        finding = Finding("APEX-008", "Test", "Summary")
        with self.assertRaisesRegex(FindingStateError, "must be a datetime"):
            finding.transition(
                FindingStatus.LEAD, actor="analyst", reason="Triage", now="2026-11-07",
            )

    def test_confirmed_transition_rejects_non_string_impact(self):
        finding = Finding("APEX-009", "Test", "Summary")
        finding, _ = finding.transition(FindingStatus.LEAD, actor="a", reason="triage", now=NOW)
        finding, _ = finding.transition(FindingStatus.TESTABLE, actor="a", reason="testable", now=NOW)
        finding, _ = finding.transition(
            FindingStatus.OBSERVED, actor="a", reason="observed",
            evidence_refs=("evidence://1",), now=NOW,
        )
        finding, _ = finding.transition(FindingStatus.VALIDATING, actor="a", reason="validate", now=NOW)
        with self.assertRaisesRegex(FindingStateError, "impact must be a non-empty string"):
            finding.transition(
                FindingStatus.CONFIRMED, actor="a", reason="confirm",
                severity="high", impact=123, confidence=0.9, now=NOW,
            )

    def test_confirmed_requires_confidence(self):
        finding = Finding("APEX-004", "Test", "Summary")
        finding, _ = finding.transition(FindingStatus.LEAD, actor="a", reason="triage", now=NOW)
        finding, _ = finding.transition(FindingStatus.TESTABLE, actor="a", reason="testable", now=NOW)
        finding, _ = finding.transition(FindingStatus.OBSERVED, actor="a", reason="observed",
                                        evidence_refs=("evidence://1",), now=NOW)
        finding, _ = finding.transition(FindingStatus.VALIDATING, actor="a", reason="validate", now=NOW)
        with self.assertRaisesRegex(FindingStateError, "confirmed_requires_confidence"):
            finding.transition(FindingStatus.CONFIRMED, actor="a", reason="confirm",
                               severity="medium", impact="Impact", now=NOW)


if __name__ == "__main__":
    unittest.main()
