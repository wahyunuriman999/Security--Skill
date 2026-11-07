from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from apex.core.audit import AuditIntegrityError, AuditLedger


class TestAuditLedger(unittest.TestCase):
    def test_append_and_verify_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = AuditLedger(Path(tmp) / "events.jsonl")
            first = ledger.append("engagement.created", {"id": "eng-1"})
            second = ledger.append("scope.checked", {"host": "example.test"})
            verified = ledger.verify()
            self.assertEqual(len(verified), 2)
            self.assertEqual(first["sequence"], 1)
            self.assertEqual(second["sequence"], 2)
            self.assertEqual(second["previous_hash"], first["hash"])

    def test_sensitive_keys_are_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = AuditLedger(Path(tmp) / "events.jsonl")
            event = ledger.append("credential.seen", {
                "api_key": "do-not-store",
                "nested": {"Cookie": "session=secret", "status": 200},
            })
            self.assertEqual(event["payload"]["api_key"], "[REDACTED]")
            self.assertEqual(event["payload"]["nested"]["Cookie"], "[REDACTED]")
            self.assertEqual(event["payload"]["nested"]["status"], 200)

    def test_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            ledger = AuditLedger(path)
            ledger.append("finding.created", {"finding_id": "F-1"})
            record = json.loads(path.read_text(encoding="utf-8"))
            record["payload"]["finding_id"] = "F-2"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(AuditIntegrityError, "content hash mismatch"):
                ledger.verify()

    def test_truncated_line_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text('{"sequence":1}', encoding="utf-8")
            with self.assertRaises(AuditIntegrityError):
                AuditLedger(path).verify()

    def test_payload_must_be_json_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = AuditLedger(Path(tmp) / "events.jsonl")
            with self.assertRaises(ValueError):
                ledger.append("bad", {"value": object()})

    def test_non_finite_numbers_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = AuditLedger(Path(tmp) / "events.jsonl")
            with self.assertRaises(ValueError):
                ledger.append("bad", {"score": float("nan")})
            with self.assertRaises(ValueError):
                ledger.append("bad", {"score": float("inf")})

    def test_non_string_object_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = AuditLedger(Path(tmp) / "events.jsonl")
            with self.assertRaisesRegex(ValueError, "keys must be strings"):
                ledger.append("bad", {1: "ambiguous"})


if __name__ == "__main__":
    unittest.main()
