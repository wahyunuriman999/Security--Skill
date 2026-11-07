"""Immutable, locally captured observations for APEX research records."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class ObservationError(ValueError):
    pass


@dataclass(frozen=True, init=False)
class Observation:
    observation_id: str
    engagement_id: str
    observation_type: str
    target_ref: str
    summary: str
    actor: str
    _details_json: str
    captured_at: datetime

    def __init__(
        self, *, observation_id: str, engagement_id: str, observation_type: str,
        target_ref: str, summary: str, actor: str, details: dict[str, Any],
        captured_at: datetime,
    ) -> None:
        for name, value in (
            ("observation_id", observation_id), ("engagement_id", engagement_id),
            ("observation_type", observation_type), ("target_ref", target_ref),
            ("summary", summary), ("actor", actor),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ObservationError(f"{name} is required")
        if not isinstance(details, dict):
            raise ObservationError("details must be a JSON object")
        if not isinstance(captured_at, datetime):
            raise ObservationError("captured_at must be a datetime")
        if captured_at.tzinfo is None or captured_at.utcoffset() is None:
            raise ObservationError("captured_at must be timezone-aware")
        try:
            encoded = json.dumps(
                details, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ObservationError("details must contain finite JSON data") from exc
        if len(encoded.encode("utf-8")) > 256 * 1024:
            raise ObservationError("details exceed 256 KiB")

        for name, value in (
            ("observation_id", observation_id), ("engagement_id", engagement_id),
            ("observation_type", observation_type), ("target_ref", target_ref),
            ("summary", summary), ("actor", actor), ("_details_json", encoded),
            ("captured_at", captured_at),
        ):
            object.__setattr__(self, name, value)

    @property
    def details(self) -> dict[str, Any]:
        """Return a fresh copy so callers cannot mutate the observation."""
        return json.loads(self._details_json)

    @property
    def details_sha256(self) -> str:
        return hashlib.sha256(self._details_json.encode("utf-8")).hexdigest()

    @property
    def captured_at_utc(self) -> datetime:
        return self.captured_at.astimezone(timezone.utc)
