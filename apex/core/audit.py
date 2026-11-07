"""Append-only, hash-chained local audit events for APEX.

The chain is tamper-evident, not tamper-proof. It does not replace OS-level
access controls, backups, remote immutable storage, or multi-process locking.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_GENESIS = "0" * 64
_MAX_EVENT_BYTES = 64 * 1024
_SENSITIVE_KEY = re.compile(
    r"(authorization|cookie|password|passwd|secret|token|api.?key|private.?key)",
    re.IGNORECASE,
)
_LOCK = threading.Lock()


class AuditIntegrityError(ValueError):
    """Raised when an audit file is malformed or its hash chain is broken."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("audit payload object keys must be strings")
        return {
            key: "[REDACTED]" if _SENSITIVE_KEY.search(key) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise ValueError(f"unsupported audit payload type: {type(value).__name__}")


def _event_hash(event_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(event_without_hash)).hexdigest()


class AuditLedger:
    """Local JSONL audit ledger with sequence numbers and SHA-256 hash chaining."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("event_type must be a non-empty string")
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        safe_payload = _redact(payload)
        with _LOCK:
            events = self.verify()
            previous_hash = events[-1]["hash"] if events else _GENESIS
            event = {
                "sequence": len(events) + 1,
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "event_type": event_type.strip(),
                "payload": safe_payload,
                "previous_hash": previous_hash,
            }
            digest = _event_hash(event)
            record = {**event, "hash": digest}
            encoded = _canonical(record) + b"\n"
            if len(encoded) > _MAX_EVENT_BYTES:
                raise ValueError("audit event exceeds 64 KiB")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(self.path, flags, 0o600)
            try:
                with os.fdopen(fd, "ab", closefd=True) as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
            except Exception:
                raise
            if os.name == "posix":
                os.chmod(self.path, 0o600)
            return record

    def verify(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        previous_hash = _GENESIS
        try:
            with self.path.open("rb") as stream:
                for line_number, raw in enumerate(stream, start=1):
                    if not raw.endswith(b"\n") or len(raw) > _MAX_EVENT_BYTES:
                        raise AuditIntegrityError(f"invalid or oversized record at line {line_number}")
                    try:
                        record = json.loads(
                            raw, object_pairs_hook=_unique_pairs,
                            parse_constant=_reject_json_constant,
                        )
                    except (json.JSONDecodeError, ValueError) as exc:
                        raise AuditIntegrityError(
                            f"invalid JSON at line {line_number}: {exc}"
                        ) from exc
                    if not isinstance(record, dict):
                        raise AuditIntegrityError(f"record {line_number} is not an object")
                    digest = record.pop("hash", None)
                    if record.get("sequence") != line_number:
                        raise AuditIntegrityError(f"sequence mismatch at line {line_number}")
                    if record.get("previous_hash") != previous_hash:
                        raise AuditIntegrityError(f"previous hash mismatch at line {line_number}")
                    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                        raise AuditIntegrityError(f"invalid hash at line {line_number}")
                    if _event_hash(record) != digest:
                        raise AuditIntegrityError(f"content hash mismatch at line {line_number}")
                    record["hash"] = digest
                    events.append(record)
                    previous_hash = digest
        except (OSError, json.JSONDecodeError) as exc:
            raise AuditIntegrityError(f"cannot read audit ledger: {exc}") from exc
        return events
