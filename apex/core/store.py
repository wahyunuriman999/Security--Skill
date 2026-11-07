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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apex.core.findings import Finding, FindingStatus
from apex.core.scope import EngagementManifest


_SCHEMA_VERSION = 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class StoreError(RuntimeError):
    pass


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
                    PRAGMA user_version = 1;
                """)
        if os.name == "posix" and self.path.exists():
            self.path.chmod(0o600)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def save_engagement(self, manifest: EngagementManifest) -> str:
        self.initialize()
        data: dict[str, Any] = {
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
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        with self._connect() as db:
            db.execute(
                "INSERT INTO engagements VALUES (?, ?, ?, ?, ?)",
                (manifest.engagement_id, manifest.program_name, canonical, digest, self._now()),
            )
        return digest

    def create_finding(self, engagement_id: str, finding: Finding) -> None:
        if finding.status is not FindingStatus.IDEA:
            raise StoreError("new findings must begin in IDEA state")
        now = self._now()
        with self._connect() as db:
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
        with self._connect() as db:
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
        with self._connect() as db:
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
    ) -> str:
        if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
            raise StoreError("evidence sha256 must be 64 lowercase hexadecimal characters")
        if not isinstance(byte_size, int) or isinstance(byte_size, bool) or byte_size < 0:
            raise StoreError("evidence byte_size must be a non-negative integer")
        if not all(isinstance(v, str) and v.strip() for v in (evidence_id, media_type, storage_ref, source)):
            raise StoreError("evidence metadata fields must be non-empty strings")
        if not isinstance(redacted, bool):
            raise StoreError("redacted must be a boolean")
        evidence_ref = f"evidence://sha256/{sha256}"
        with self._connect() as db:
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

    def list_finding_events(self, finding_id: str) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                """SELECT from_status, to_status, actor, reason, event_at
                   FROM finding_events WHERE finding_id=? ORDER BY event_id""",
                (finding_id,),
            ).fetchall()
        return [dict(row) for row in rows]
