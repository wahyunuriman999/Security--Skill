import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from apex.core.findings import Finding, FindingStateError, FindingStatus
from apex.core.scope import EngagementManifest
from apex.core.observations import Observation
from apex.core.evidence_store import LocalEvidenceStore
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

    def test_evidence_object_can_be_registered_as_finding_metadata(self):
        self.store.save_engagement(sample_manifest())
        self.store.create_finding("eng-store-1", Finding("APEX-OBJECT-1", "Title", "Summary"))
        objects = LocalEvidenceStore(Path(self.tmp.name) / "evidence")
        stored = objects.put(b"redacted screenshot metadata", redacted=True)
        evidence_ref = self.store.add_evidence_metadata(
            evidence_id="EV-OBJECT-1", finding_id="APEX-OBJECT-1",
            sha256=stored.sha256, media_type="text/plain", byte_size=stored.byte_size,
            storage_ref=stored.storage_ref, source="local-evidence-store", redacted=True,
        )
        self.assertTrue(objects.verify(stored.sha256))
        self.assertIn(stored.sha256, evidence_ref)

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

    def test_remote_evidence_storage_reference_rejected(self):
        self.store.save_engagement(sample_manifest())
        self.store.create_finding("eng-store-1", Finding("APEX-STORE-7", "Title", "Summary"))
        with self.assertRaisesRegex(StoreError, "storage_ref_must_be_a_local_non_sensitive_reference"):
            self.store.add_evidence_metadata(
                evidence_id="EV-REMOTE", finding_id="APEX-STORE-7", sha256="e" * 64,
                media_type="text/plain", byte_size=1,
                storage_ref="https://collector.invalid/evidence",
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

    def test_concurrent_reservations_cannot_exceed_budget(self):
        policy = sample_manifest(request_budget={
            "max_total_requests": 1, "max_requests_per_host": 1,
        })
        self.store.save_engagement(policy)

        def reserve(index):
            try:
                self.store.reserve_request(
                    policy, request_id=f"concurrent-{index}",
                    url=f"https://example.test/{index}",
                )
                return "reserved"
            except StoreError as exc:
                return str(exc)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, (1, 2)))
        self.assertEqual(results.count("reserved"), 1)
        self.assertEqual(results.count("per_host_request_budget_exhausted"), 1)

    def test_request_reservation_requires_exact_persisted_manifest(self):
        original = sample_manifest()
        self.store.save_engagement(original)
        changed = sample_manifest(assets=[
            {"host": "other.example.test", "schemes": ["https"], "ports": [443]},
        ])
        with self.assertRaisesRegex(StoreError, "manifest_does_not_match"):
            self.store.reserve_request(changed, request_id="mismatch",
                                       url="https://other.example.test/")

    def test_observed_finding_requires_evidence_attached_to_same_finding(self):
        self.store.save_engagement(sample_manifest())
        self.store.create_finding("eng-store-1", Finding("APEX-EV-1", "Title", "Summary"))
        self.store.transition_finding("APEX-EV-1", FindingStatus.LEAD,
                                      actor="analyst", reason="Triage")
        self.store.transition_finding("APEX-EV-1", FindingStatus.TESTABLE,
                                      actor="analyst", reason="Test plan")
        with self.assertRaisesRegex(StoreError, "evidence_reference_not_attached"):
            self.store.transition_finding(
                "APEX-EV-1", FindingStatus.OBSERVED, actor="analyst",
                reason="Fake evidence reference",
                evidence_refs=("evidence://sha256/" + "a" * 64,),
            )
        self.assertEqual(self.store.get_finding("APEX-EV-1").status, FindingStatus.TESTABLE)

    def test_unredacted_evidence_cannot_advance_finding_to_observed(self):
        self.store.save_engagement(sample_manifest())
        self.store.create_finding("eng-store-1", Finding("APEX-EV-4", "Title", "Summary"))
        self.store.transition_finding("APEX-EV-4", FindingStatus.LEAD,
                                      actor="analyst", reason="Triage")
        self.store.transition_finding("APEX-EV-4", FindingStatus.TESTABLE,
                                      actor="analyst", reason="Test plan")
        evidence_ref = self.store.add_evidence_metadata(
            evidence_id="EV-UNREDACTED", finding_id="APEX-EV-4",
            sha256="d" * 64, media_type="text/plain", byte_size=12,
            storage_ref="local://evidence/EV-UNREDACTED", source="fixture", redacted=False,
        )
        with self.assertRaisesRegex(StoreError, "evidence_must_be_redacted"):
            self.store.transition_finding(
                "APEX-EV-4", FindingStatus.OBSERVED, actor="analyst",
                reason="Unredacted evidence must not be used", evidence_refs=(evidence_ref,),
            )

    def test_evidence_metadata_is_append_only(self):
        self.store.save_engagement(sample_manifest())
        self.store.create_finding("eng-store-1", Finding("APEX-EV-2", "Title", "Summary"))
        self.store.add_evidence_metadata(
            evidence_id="EV-IMM-1", finding_id="APEX-EV-2", sha256="c" * 64,
            media_type="text/plain", byte_size=5, storage_ref="local://evidence/1",
            source="fixture", redacted=True,
        )
        with self.assertRaisesRegex(Exception, "evidence_metadata_is_immutable"):
            with self.store._connection() as db:
                db.execute("UPDATE evidence_metadata SET source='changed' WHERE evidence_id='EV-IMM-1'")
        with self.assertRaisesRegex(Exception, "evidence_metadata_is_immutable"):
            with self.store._connection() as db:
                db.execute("DELETE FROM evidence_metadata WHERE evidence_id='EV-IMM-1'")

    def test_finding_event_history_is_append_only(self):
        self.store.save_engagement(sample_manifest())
        self.store.create_finding("eng-store-1", Finding("APEX-EV-3", "Title", "Summary"))
        with self.assertRaisesRegex(Exception, "finding_events_are_immutable"):
            with self.store._connection() as db:
                db.execute("UPDATE finding_events SET reason='rewritten' WHERE finding_id='APEX-EV-3'")

    def test_observation_persists_and_verifies_canonical_details_hash(self):
        self.store.save_engagement(sample_manifest())
        observation = Observation(
            observation_id="OBS-1", engagement_id="eng-store-1",
            observation_type="manual_review", target_ref="asset://example.test",
            summary="Observed response header metadata",
            actor="analyst", details={"status_code": 200, "headers": {"content-type": "text/plain"}},
            captured_at=datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc),
        )
        digest = self.store.add_observation(observation)
        restored = self.store.get_observation("OBS-1")
        self.assertEqual(digest, restored.details_sha256)
        self.assertEqual(restored.details, observation.details)
        self.assertEqual(len(self.store.list_observations("eng-store-1")), 1)

    def test_observation_records_are_append_only(self):
        self.store.save_engagement(sample_manifest())
        observation = Observation(
            observation_id="OBS-2", engagement_id="eng-store-1",
            observation_type="note", target_ref="asset://example.test",
            summary="A local note", actor="analyst", details={"note": "reviewed"},
            captured_at=datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc),
        )
        self.store.add_observation(observation)
        with self.assertRaisesRegex(Exception, "observations_are_immutable"):
            with self.store._connection() as db:
                db.execute("UPDATE observations SET summary='rewritten' WHERE observation_id='OBS-2'")
        with self.assertRaisesRegex(Exception, "observations_are_immutable"):
            with self.store._connection() as db:
                db.execute("DELETE FROM observations WHERE observation_id='OBS-2'")

    def test_observation_rejects_non_finite_json(self):
        with self.assertRaisesRegex(ValueError, "finite JSON"):
            Observation(
                observation_id="OBS-3", engagement_id="eng-store-1",
                observation_type="note", target_ref="asset://example.test",
                summary="Invalid data", actor="analyst", details={"score": float("nan")},
                captured_at=datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc),
            )

    def test_schema_v2_migrates_to_v4(self):
        with self.store._connection() as db:
            db.execute("DROP TRIGGER evidence_metadata_no_update")
            db.execute("DROP TRIGGER evidence_metadata_no_delete")
            db.execute("DROP TRIGGER finding_events_no_update")
            db.execute("DROP TRIGGER finding_events_no_delete")
            db.execute("DROP TRIGGER observations_no_update")
            db.execute("DROP TRIGGER observations_no_delete")
            db.execute("DROP TABLE observations")
            db.execute("PRAGMA user_version = 2")
        self.store.initialize()
        with self.store._connection() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            observation_table = db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='observations'"
            ).fetchone()
        self.assertEqual(version, 4)
        self.assertIsNotNone(observation_table)


if __name__ == "__main__":
    unittest.main()
