"""SQLite persistence for engagement metadata, findings, evidence metadata, and transitions.

Raw evidence bytes are deliberately not stored in this database. Store only a
content hash and a controlled storage reference; protect the referenced object
store separately.
"""
from __future__ import annotations

import hashlib
import json
import contextlib
import os
import re
import sqlite3
from dataclasses import dataclass
from urllib.parse import urlsplit
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apex.core.findings import Finding, FindingStatus
from apex.core.observations import Observation
from apex.core.evidence_store import LocalEvidenceStore, EvidenceObjectError
from apex.core.scope import (AuthorizationDecision, EngagementManifest, authorize_url, normalize_host)


_SCHEMA_VERSION = 4
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class StoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReservationResult:
    decision: AuthorizationDecision
    request_id: str | None
    replayed: bool


class SQLiteStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @contextlib.contextmanager
    def _connection(self):
        db = self._connect()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > _SCHEMA_VERSION:
                raise StoreError(f"database schema {version} is newer than supported {_SCHEMA_VERSION}")
            if version == 0:
                db.executescript("""
                    CREATE TABLE engagements (
                        engagement_id TEXT PRIMARY KEY,
                        program_name TEXT NOT NULL,
                        manifest_json TEXT NOT NULL,
                        manifest_sha256 TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE findings (
                        finding_id TEXT PRIMARY KEY,
                        engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
                        title TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        status TEXT NOT NULL,
                        evidence_refs_json TEXT NOT NULL,
                        severity TEXT,
                        impact TEXT,
                        confidence REAL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE TABLE finding_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        finding_id TEXT NOT NULL REFERENCES findings(finding_id),
                        from_status TEXT,
                        to_status TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        event_at TEXT NOT NULL
                    );
                    CREATE TABLE evidence_metadata (
                        evidence_id TEXT PRIMARY KEY,
                        finding_id TEXT NOT NULL REFERENCES findings(finding_id),
                        sha256 TEXT NOT NULL,
                        media_type TEXT NOT NULL,
                        byte_size INTEGER NOT NULL CHECK(byte_size >= 0),
                        storage_ref TEXT NOT NULL,
                        captured_at TEXT NOT NULL,
                        source TEXT NOT NULL,
                        redacted INTEGER NOT NULL CHECK(redacted IN (0, 1)),
                        UNIQUE(finding_id, sha256)
                    );
                    CREATE INDEX idx_findings_engagement ON findings(engagement_id);
                    CREATE INDEX idx_finding_events_finding ON finding_events(finding_id, event_id);
                    CREATE TABLE request_reservations (
                        request_id TEXT PRIMARY KEY,
                        engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
                        host TEXT NOT NULL,
                        url_sha256 TEXT NOT NULL,
                        reserved_at TEXT NOT NULL
                    );
                    CREATE INDEX idx_request_reservations_engagement
                        ON request_reservations(engagement_id, host);
                    PRAGMA user_version = 2;
                """)
                version = 2
            elif version == 1:
                db.executescript("""
                    CREATE TABLE request_reservations (
                        request_id TEXT PRIMARY KEY,
                        engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
                        host TEXT NOT NULL,
                        url_sha256 TEXT NOT NULL,
                        reserved_at TEXT NOT NULL
                    );
                    CREATE INDEX idx_request_reservations_engagement
                        ON request_reservations(engagement_id, host);
                    PRAGMA user_version = 2;
                """)
                version = 2
            if version == 2:
                db.executescript("""
                    CREATE TRIGGER evidence_metadata_no_update
                    BEFORE UPDATE ON evidence_metadata
                    BEGIN SELECT RAISE(ABORT, 'evidence_metadata_is_immutable'); END;
                    CREATE TRIGGER evidence_metadata_no_delete
                    BEFORE DELETE ON evidence_metadata
                    BEGIN SELECT RAISE(ABORT, 'evidence_metadata_is_immutable'); END;
                    CREATE TRIGGER finding_events_no_update
                    BEFORE UPDATE ON finding_events
                    BEGIN SELECT RAISE(ABORT, 'finding_events_are_immutable'); END;
                    CREATE TRIGGER finding_events_no_delete
                    BEFORE DELETE ON finding_events
                    BEGIN SELECT RAISE(ABORT, 'finding_events_are_immutable'); END;
                    PRAGMA user_version = 3;
                """)
                version = 3
            if version == 3:
                db.executescript("""
                    CREATE TABLE observations (
                        observation_id TEXT PRIMARY KEY,
                        engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
                        observation_type TEXT NOT NULL,
                        target_ref TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        details_sha256 TEXT NOT NULL,
                        captured_at TEXT NOT NULL
                    );
                    CREATE INDEX idx_observations_engagement
                        ON observations(engagement_id, captured_at);
                    CREATE TRIGGER observations_no_update
                    BEFORE UPDATE ON observations
                    BEGIN SELECT RAISE(ABORT, 'observations_are_immutable'); END;
                    CREATE TRIGGER observations_no_delete
                    BEFORE DELETE ON observations
                    BEGIN SELECT RAISE(ABORT, 'observations_are_immutable'); END;
                    PRAGMA user_version = 4;
                """)
                version = 4
        if os.name == "posix" and self.path.exists():
            self.path.chmod(0o600)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _manifest_document(manifest: EngagementManifest) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "engagement_id": manifest.engagement_id,
            "program_name": manifest.program_name,
            "authorization_reference": manifest.authorization_reference,
            "issued_at": manifest.issued_at.isoformat(),
            "expires_at": manifest.expires_at.isoformat(),
            "assets": [
                {
                    "host": ("*." if rule.wildcard else "") + rule.host,
                    "schemes": sorted(rule.schemes),
                    "ports": sorted(rule.ports) if rule.ports is not None else None,
                }
                for rule in manifest.assets
            ],
            "request_budget": {
                "max_total_requests": manifest.max_total_requests,
                "max_requests_per_host": manifest.max_requests_per_host,
            },
        }

    @classmethod
    def _manifest_digest(cls, manifest: EngagementManifest) -> str:
        canonical = json.dumps(cls._manifest_document(manifest), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def save_engagement(self, manifest: EngagementManifest) -> str:
        self.initialize()
        data = self._manifest_document(manifest)
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        with self._connection() as db:
            db.execute(
                "INSERT INTO engagements VALUES (?, ?, ?, ?, ?)",
                (manifest.engagement_id, manifest.program_name, canonical, digest, self._now()),
            )
        return digest

    def reserve_request(
        self, manifest: EngagementManifest, *, request_id: str, url: str,
        now: datetime | None = None,
    ) -> "ReservationResult":
        """Authorize and durably reserve a request budget unit; never sends traffic.

        Call once per outbound URL, including each redirect destination. Reusing
        a request_id for the same URL is idempotent; reusing it for another URL
        is rejected.
        """
        if not isinstance(request_id, str) or not request_id.strip() or len(request_id) > 128:
            raise StoreError("request_id must be a non-empty string of at most 128 characters")
        decision = authorize_url(manifest, url, now=now)
        if not decision.allowed:
            return ReservationResult(decision, None, False)
        parsed = urlsplit(url)
        host = normalize_host(parsed.hostname or "")
        url_digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        expected_manifest_digest = self._manifest_digest(manifest)

        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            saved = db.execute(
                "SELECT manifest_sha256 FROM engagements WHERE engagement_id = ?",
                (manifest.engagement_id,),
            ).fetchone()
            if saved is None:
                raise StoreError("engagement_not_persisted")
            if saved["manifest_sha256"] != expected_manifest_digest:
                raise StoreError("manifest_does_not_match_persisted_authorization")

            existing = db.execute(
                "SELECT engagement_id, host, url_sha256 FROM request_reservations WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if existing is not None:
                if (existing["engagement_id"], existing["host"], existing["url_sha256"]) != (
                    manifest.engagement_id, host, url_digest
                ):
                    raise StoreError("idempotency_key_conflict")
                return ReservationResult(decision, request_id, True)

            total = db.execute(
                "SELECT COUNT(*) FROM request_reservations WHERE engagement_id = ?",
                (manifest.engagement_id,),
            ).fetchone()[0]
            per_host = db.execute(
                "SELECT COUNT(*) FROM request_reservations WHERE engagement_id = ? AND host = ?",
                (manifest.engagement_id, host),
            ).fetchone()[0]
            if total >= manifest.max_total_requests:
                raise StoreError("total_request_budget_exhausted")
            if per_host >= manifest.max_requests_per_host:
                raise StoreError("per_host_request_budget_exhausted")
            db.execute(
                "INSERT INTO request_reservations VALUES (?, ?, ?, ?, ?)",
                (request_id, manifest.engagement_id, host, url_digest, self._now()),
            )
        return ReservationResult(decision, request_id, False)

    def create_finding(self, engagement_id: str, finding: Finding) -> None:
        if finding.status is not FindingStatus.IDEA:
            raise StoreError("new findings must begin in IDEA state")
        now = self._now()
        with self._connection() as db:
            db.execute(
                """INSERT INTO findings
                   (finding_id, engagement_id, title, summary, status, evidence_refs_json,
                    severity, impact, confidence, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding.finding_id, engagement_id, finding.title, finding.summary,
                 finding.status.value, json.dumps(list(finding.evidence_refs)),
                 finding.severity, finding.impact, finding.confidence, now, now),
            )
            db.execute(
                """INSERT INTO finding_events
                   (finding_id, from_status, to_status, actor, reason, event_at)
                   VALUES (?, NULL, ?, ?, ?, ?)""",
                (finding.finding_id, FindingStatus.IDEA.value, "system", "finding_created", now),
            )

    def get_finding(self, finding_id: str) -> Finding:
        with self._connection() as db:
            row = db.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
        if row is None:
            raise StoreError("finding_not_found")
        return Finding(
            finding_id=row["finding_id"], title=row["title"], summary=row["summary"],
            status=FindingStatus(row["status"]),
            evidence_refs=tuple(json.loads(row["evidence_refs_json"])),
            severity=row["severity"], impact=row["impact"], confidence=row["confidence"],
        )

    def transition_finding(
        self, finding_id: str, target: FindingStatus, *, actor: str, reason: str,
        evidence_refs: tuple[str, ...] | None = None, severity: str | None = None,
        impact: str | None = None, confidence: float | None = None,
    ) -> Finding:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
            if row is None:
                raise StoreError("finding_not_found")
            current = Finding(
                finding_id=row["finding_id"], title=row["title"], summary=row["summary"],
                status=FindingStatus(row["status"]),
                evidence_refs=tuple(json.loads(row["evidence_refs_json"])),
                severity=row["severity"], impact=row["impact"], confidence=row["confidence"],
            )
            updated, event = current.transition(
                target, actor=actor, reason=reason, evidence_refs=evidence_refs,
                severity=severity, impact=impact, confidence=confidence,
            )
            if target in {FindingStatus.OBSERVED, FindingStatus.VALIDATING, FindingStatus.CONFIRMED}:
                for evidence_ref in updated.evidence_refs:
                    prefix = "evidence://sha256/"
                    if not evidence_ref.startswith(prefix):
                        raise StoreError("invalid_evidence_reference")
                    digest = evidence_ref[len(prefix):]
                    if not _SHA256.fullmatch(digest):
                        raise StoreError("invalid_evidence_reference")
                    stored = db.execute(
                        "SELECT redacted FROM evidence_metadata WHERE finding_id=? AND sha256=?",
                        (finding_id, digest),
                    ).fetchone()
                    if stored is None:
                        raise StoreError("evidence_reference_not_attached_to_finding")
                    if stored["redacted"] != 1:
                        raise StoreError("evidence_must_be_redacted_before_finding_use")
            timestamp = event.timestamp.isoformat().replace("+00:00", "Z")
            db.execute(
                """UPDATE findings SET status=?, evidence_refs_json=?, severity=?, impact=?,
                   confidence=?, updated_at=? WHERE finding_id=?""",
                (updated.status.value, json.dumps(list(updated.evidence_refs)),
                 updated.severity, updated.impact, updated.confidence, timestamp, finding_id),
            )
            db.execute(
                """INSERT INTO finding_events
                   (finding_id, from_status, to_status, actor, reason, event_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (finding_id, event.from_status.value, event.to_status.value,
                 event.actor, event.reason, timestamp),
            )
            return updated

    def add_evidence_metadata(
        self, *, evidence_id: str, finding_id: str, sha256: str, media_type: str,
        byte_size: int, storage_ref: str, source: str, redacted: bool,
        object_store: LocalEvidenceStore | None = None,
    ) -> str:
        if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
            raise StoreError("evidence sha256 must be 64 lowercase hexadecimal characters")
        if not isinstance(byte_size, int) or isinstance(byte_size, bool) or byte_size < 0:
            raise StoreError("evidence byte_size must be a non-negative integer")
        if not all(isinstance(v, str) and v.strip() for v in (evidence_id, media_type, storage_ref, source)):
            raise StoreError("evidence metadata fields must be non-empty strings")
        parsed_storage_ref = urlsplit(storage_ref)
        if (parsed_storage_ref.scheme != "local" or not parsed_storage_ref.netloc
                or parsed_storage_ref.username is not None or parsed_storage_ref.password is not None
                or parsed_storage_ref.query or parsed_storage_ref.fragment):
            raise StoreError("storage_ref_must_be_a_local_non_sensitive_reference")
        if any(ch in media_type or ch in source for ch in (chr(10), chr(13))):
            raise StoreError("evidence metadata must not contain line breaks")
        if not isinstance(redacted, bool):
            raise StoreError("redacted must be a boolean")
        if storage_ref != f"local://sha256/{sha256}":
            raise StoreError("storage_ref_must_match_content_address")
        if not isinstance(object_store, LocalEvidenceStore):
            raise StoreError("verified_local_evidence_store_required")
        try:
            verified_bytes = object_store.get(sha256)
        except EvidenceObjectError as exc:
            raise StoreError("evidence_object_missing_or_integrity_failure") from exc
        if len(verified_bytes) != byte_size:
            raise StoreError("evidence_object_size_mismatch")
        evidence_ref = f"evidence://sha256/{sha256}"
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT evidence_refs_json FROM findings WHERE finding_id = ?",
                             (finding_id,)).fetchone()
            if row is None:
                raise StoreError("finding_not_found")
            db.execute(
                """INSERT INTO evidence_metadata
                   (evidence_id, finding_id, sha256, media_type, byte_size, storage_ref,
                    captured_at, source, redacted)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (evidence_id, finding_id, sha256, media_type, byte_size, storage_ref,
                 self._now(), source, int(redacted)),
            )
            refs = json.loads(row["evidence_refs_json"])
            if evidence_ref not in refs:
                refs.append(evidence_ref)
                db.execute("UPDATE findings SET evidence_refs_json=?, updated_at=? WHERE finding_id=?",
                           (json.dumps(refs), self._now(), finding_id))
        return evidence_ref

    def add_observation(self, observation: Observation) -> str:
        if not isinstance(observation, Observation):
            raise StoreError("observation must be an Observation instance")
        details_json = json.dumps(
            observation.details, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        )
        captured = observation.captured_at_utc.isoformat().replace("+00:00", "Z")
        with self._connection() as db:
            db.execute(
                """INSERT INTO observations
                   (observation_id, engagement_id, observation_type, target_ref,
                    summary, actor, details_json, details_sha256, captured_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (observation.observation_id, observation.engagement_id,
                 observation.observation_type, observation.target_ref,
                 observation.summary, observation.actor, details_json,
                 observation.details_sha256, captured),
            )
        return observation.details_sha256

    def get_observation(self, observation_id: str) -> Observation:
        with self._connection() as db:
            row = db.execute(
                "SELECT * FROM observations WHERE observation_id=?", (observation_id,)
            ).fetchone()
        if row is None:
            raise StoreError("observation_not_found")
        details = json.loads(row["details_json"])
        digest = hashlib.sha256(row["details_json"].encode("utf-8")).hexdigest()
        if digest != row["details_sha256"]:
            raise StoreError("observation_integrity_check_failed")
        timestamp = datetime.fromisoformat(row["captured_at"].replace("Z", "+00:00"))
        return Observation(
            observation_id=row["observation_id"], engagement_id=row["engagement_id"],
            observation_type=row["observation_type"], target_ref=row["target_ref"],
            summary=row["summary"], actor=row["actor"], details=details,
            captured_at=timestamp,
        )

    def list_observations(self, engagement_id: str) -> list[Observation]:
        with self._connection() as db:
            rows = db.execute(
                "SELECT observation_id FROM observations WHERE engagement_id=? ORDER BY captured_at, observation_id",
                (engagement_id,),
            ).fetchall()
        return [self.get_observation(row["observation_id"]) for row in rows]

    def list_finding_events(self, finding_id: str) -> list[dict[str, Any]]:
        with self._connection() as db:
            rows = db.execute(
                """SELECT from_status, to_status, actor, reason, event_at
                   FROM finding_events WHERE finding_id=? ORDER BY event_id""",
                (finding_id,),
            ).fetchall()
        return [dict(row) for row in rows]
