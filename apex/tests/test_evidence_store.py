import tempfile
import unittest
from pathlib import Path

from apex.core.evidence_store import EvidenceObjectError, LocalEvidenceStore


class TestLocalEvidenceStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = LocalEvidenceStore(Path(self.tmp.name) / "objects", max_bytes=1024)

    def tearDown(self):
        self.tmp.cleanup()

    def test_put_get_and_verify_content_addressed_object(self):
        payload = b"redacted evidence fixture"
        stored = self.store.put(payload, redacted=True)
        self.assertEqual(len(stored.sha256), 64)
        self.assertEqual(stored.byte_size, len(payload))
        self.assertEqual(stored.storage_ref, "local://sha256/" + stored.sha256)
        self.assertEqual(self.store.get(stored.sha256), payload)
        self.assertTrue(self.store.verify(stored.sha256))

    def test_put_is_idempotent_for_identical_content(self):
        first = self.store.put(b"same", redacted=True)
        second = self.store.put(b"same", redacted=True)
        self.assertEqual(first, second)

    def test_unredacted_evidence_rejected(self):
        with self.assertRaisesRegex(EvidenceObjectError, "must_be_redacted"):
            self.store.put(b"possibly sensitive", redacted=False)

    def test_empty_and_oversized_evidence_rejected(self):
        with self.assertRaisesRegex(EvidenceObjectError, "empty_evidence"):
            self.store.put(b"", redacted=True)
        with self.assertRaisesRegex(EvidenceObjectError, "size_limit"):
            self.store.put(b"x" * 1025, redacted=True)

    def test_tampered_object_detected(self):
        stored = self.store.put(b"original", redacted=True)
        path = Path(self.tmp.name) / "objects" / stored.sha256[:2] / stored.sha256
        path.write_bytes(b"tampered")
        with self.assertRaisesRegex(EvidenceObjectError, "integrity_failure"):
            self.store.get(stored.sha256)

    def test_invalid_digest_rejected(self):
        with self.assertRaisesRegex(EvidenceObjectError, "invalid_sha256"):
            self.store.get("../not-a-digest")


if __name__ == "__main__":
    unittest.main()
