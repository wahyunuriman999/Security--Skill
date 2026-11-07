import tempfile
import unittest
from pathlib import Path

from apex.core.findings import Finding, FindingStateError, FindingStatus
from apex.core.scope import EngagementManifest
from apex.core.store import SQLiteStore, StoreError


def sample_manifest(*, assets=None, request_budget=None):
    return EngagementManifest.from_dict({
        "schema_version": 1,
        "engagement_id": "eng-store-1",
        "program_name": "Store fixture",
        "authorization": {"authorized": True, "reference": "https://example.test/policy"},
        "issued_at": "2026-11-01T00:00:00Z",
        "expires_at": "2026-12-01T00:00:00Z",
        "assets": assets or [{"host": "example.test", "schemes": ["https"], "ports": [443]}],
        "request_budget": request_budget or {"max_total_requests": 10, "max_requests_per_host": 5},
    })


class TestSQLiteStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "apex.db")
        self.store.initialize()

    def tearDown(self):
        self.tmp.cleanup()

    def test_save_engagement_and_create_finding(self):
        digest = self.store.save_engagement(sample_manifest())
        self.assertEqual(len(digest), 64)
        self.store.create_finding("eng-store-1", Finding("APEX-STORE-1", "Title", "Summary"))
        finding = self.store.get_finding("APEX-STORE-1")
        self.assertEqual(finding.status, FindingStatus.IDEA)

    def test_evidence_metadata_and_finding_transition(self):
        self.store.save_engagement(sample_manifest())
        self.store.create_finding("eng-store-1", Finding("APEX-STORE-2", "Title", "Summary"))
        self.store.transition_finding("APEX-STORE-2", FindingStatus.LEAD,
                                      actor="analyst", reason="Initial triage")
        self.store.transition_finding("APEX-STORE-2", FindingStatus.TESTABLE,
                                      actor="analyst", reason="Reproduction hypothesis")
        evidence_ref = self.store.add_evidence_metadata(
            evidence_id="EV-1", finding_id="APEX-STORE-2",
            sha256="a" * 64, media_type="text/plain", byte_size=128,
            storage_ref="local://evidence/EV-1", source="manual-capture", redacted=True,
        )
        finding = self.store.get_finding("APEX-STORE-2")
        self.assertIn(evidence_ref, finding.evidence_refs)
        self.store.transition_finding("APEX-STORE-2", FindingStatus.OBSERVED,
                                      actor="analyst", reason="Evidence recorded")
        self.store.transition_finding("APEX-STORE-2", FindingStatus.VALIDATING,
                                      actor="reviewer", reason="Independent review")
        confirmed = self.store.transition_finding(
            "APEX-STORE-2", FindingStatus.CONFIRMED, actor="reviewer",
            reason="Impact independently reproduced", severity="high",
            impact="Unauthorized access to another account's record", confidence=0.95,
        )
        self.assertEqual(confirmed.status, FindingStatus.CONFIRMED)
        self.assertEqual(len(self.store.list_finding_events("APEX-STORE-2")), 6)

    def test_invalid_transition_rolls_back(self):
        self.store.save_engagement(sample_manifest())
        self.store.create_finding("eng-store-1", Finding("APEX-STORE-3", "Title", "Summary"))
        with self.assertRaises(FindingStateError):
            self.store.transition_finding("APEX-STORE-3", FindingStatus.CONFIRMED,
                                          actor="analyst", reason="Skip evidence gates")
        self.assertEqual(self.store.get_finding("APEX-STORE-3").status, FindingStatus.IDEA)
        self.assertEqual(len(self.store.list_finding_events("APEX-STORE-3")), 1)

    def test_unknown_engagement_rejected_by_foreign_key(self):
        with self.assertRaises(Exception):
            self.store.create_finding("missing", Finding("APEX-STORE-4", "Title", "Summary"))

    def test_invalid_evidence_hash_rejected(self):
        self.store.save_engagement(sample_manifest())
        self.store.create_finding("eng-store-1", Finding("APEX-STORE-5", "Title", "Summary"))
        with self.assertRaisesRegex(StoreError, "sha256"):
            self.store.add_evidence_metadata(
                evidence_id="EV-X", finding_id="APEX-STORE-5", sha256="bad",
                media_type="text/plain", byte_size=1, storage_ref="local://x",
                source="test", redacted=True,
            )

    def test_boolean_size_rejected(self):
        self.store.save_engagement(sample_manifest())
        self.store.create_finding("eng-store-1", Finding("APEX-STORE-6", "Title", "Summary"))
        with self.assertRaisesRegex(StoreError, "byte_size"):
            self.store.add_evidence_metadata(
                evidence_id="EV-X", finding_id="APEX-STORE-6", sha256="b" * 64,
                media_type="text/plain", byte_size=True, storage_ref="local://x",
                source="test", redacted=True,
            )

    def test_scope_checked_request_reservation_and_idempotency(self):
        policy = sample_manifest()
        self.store.save_engagement(policy)
        denied = self.store.reserve_request(policy, request_id="r-0",
                                            url="https://outside.test/")
        self.assertFalse(denied.decision.allowed)
        self.assertIsNone(denied.request_id)
        first = self.store.reserve_request(policy, request_id="r-1",
                                           url="https://example.test/path")
        self.assertTrue(first.decision.allowed)
        self.assertFalse(first.replayed)
        replay = self.store.reserve_request(policy, request_id="r-1",
                                            url="https://example.test/path")
        self.assertTrue(replay.replayed)

    def test_idempotency_key_cannot_be_reused_for_another_url(self):
        policy = sample_manifest()
        self.store.save_engagement(policy)
        self.store.reserve_request(policy, request_id="same-key",
                                   url="https://example.test/one")
        with self.assertRaisesRegex(StoreError, "idempotency_key_conflict"):
            self.store.reserve_request(policy, request_id="same-key",
                                       url="https://example.test/two")

    def test_request_budget_is_persistent_and_enforced(self):
        policy = sample_manifest(request_budget={
            "max_total_requests": 2, "max_requests_per_host": 1,
        })
        self.store.save_engagement(policy)
        self.store.reserve_request(policy, request_id="budget-1",
                                   url="https://example.test/one")
        with self.assertRaisesRegex(StoreError, "per_host_request_budget_exhausted"):
            self.store.reserve_request(policy, request_id="budget-2",
                                       url="https://example.test/two")

    def test_request_reservation_requires_exact_persisted_manifest(self):
        original = sample_manifest()
        self.store.save_engagement(original)
        changed = sample_manifest(assets=[
            {"host": "other.example.test", "schemes": ["https"], "ports": [443]},
        ])
        with self.assertRaisesRegex(StoreError, "manifest_does_not_match"):
            self.store.reserve_request(changed, request_id="mismatch",
                                       url="https://other.example.test/")


if __name__ == "__main__":
    unittest.main()
