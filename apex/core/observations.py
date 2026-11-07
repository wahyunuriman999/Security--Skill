"""Immutable, locally captured observations for APEX research records."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class ObservationError(ValueError):
    pass


@dataclass(frozen=True)
class Observation:
    observation_id: str
    engagement_id: str
    observation_type: str
    target_ref: str
    summary: str
    actor: str
    details: dict[str, Any]
    captured_at: datetime

    def __post_init__(self) -> None:
        for name in ("observation_id", "engagement_id", "observation_type",
                     "target_ref", "summary", "actor"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ObservationError(f"{name} is required")
        if not isinstance(self.details, dict):
            raise ObservationError("details must be a JSON object")
        if not isinstance(self.captured_at, datetime):
            raise ObservationError("captured_at must be a datetime")
        if self.captured_at.tzinfo is None or self.captured_at.utcoffset() is None:
            raise ObservationError("captured_at must be timezone-aware")
        try:
            encoded = json.dumps(
                self.details, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ObservationError("details must contain finite JSON data") from exc
        if len(encoded) > 256 * 1024:
            raise ObservationError("details exceed 256 KiB")

    @property
    def details_sha256(self) -> str:
        encoded = json.dumps(
            self.details, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @property
    def captured_at_utc(self) -> datetime:
        return self.captured_at.astimezone(timezone.utc)
