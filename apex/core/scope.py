"""Fail-closed engagement manifest parsing and URL scope authorization.

This module performs local policy checks only. It never resolves DNS, opens sockets,
sends HTTP requests, follows redirects, or invokes legacy tools.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class ScopePolicyError(ValueError):
    """Raised when a manifest or target cannot be safely authorized."""


_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ALLOWED_SCHEMES = frozenset({"http", "https"})


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ScopePolicyError(f"{field} must be a non-empty ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScopePolicyError(f"{field} is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ScopePolicyError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def normalize_host(value: str) -> str:
    """Return a canonical lower-case IDNA hostname or compressed IP literal."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ScopePolicyError("host must be a non-empty trimmed string")
    host = value.rstrip(".")
    if not host or "%" in host or any(ch in host for ch in "/\\@?#"):
        raise ScopePolicyError("host contains forbidden characters")
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopePolicyError("host is not valid IDNA") from exc
    if len(ascii_host) > 253:
        raise ScopePolicyError("hostname exceeds 253 characters")
    labels = ascii_host.split(".")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ScopePolicyError("hostname contains an invalid DNS label")
    return ascii_host


@dataclass(frozen=True)
class AssetRule:
    host: str
    wildcard: bool
    schemes: frozenset[str]
    ports: frozenset[int] | None

    def matches(self, host: str, scheme: str, port: int) -> bool:
        host_match = (
            host.endswith("." + self.host) and host != self.host
            if self.wildcard else host == self.host
        )
        return (
            host_match
            and scheme in self.schemes
            and (self.ports is None or port in self.ports)
        )


@dataclass(frozen=True)
class EngagementManifest:
    engagement_id: str
    program_name: str
    authorization_reference: str
    issued_at: datetime
    expires_at: datetime
    assets: tuple[AssetRule, ...]
    max_total_requests: int
    max_requests_per_host: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EngagementManifest":
        if not isinstance(data, dict):
            raise ScopePolicyError("manifest root must be an object")
        if data.get("schema_version") != 1:
            raise ScopePolicyError("schema_version must equal 1")

        engagement_id = _required_text(data, "engagement_id")
        program_name = _required_text(data, "program_name")
        auth = data.get("authorization")
        if not isinstance(auth, dict) or auth.get("authorized") is not True:
            raise ScopePolicyError("explicit authorization is required")
        authorization_reference = _required_text(auth, "reference")

        issued_at = _parse_time(data.get("issued_at"), "issued_at")
        expires_at = _parse_time(data.get("expires_at"), "expires_at")
        if expires_at <= issued_at:
            raise ScopePolicyError("expires_at must be later than issued_at")

        raw_assets = data.get("assets")
        if not isinstance(raw_assets, list) or not raw_assets:
            raise ScopePolicyError("assets must be a non-empty array")
        assets: list[AssetRule] = []
        seen: set[tuple[str, bool, tuple[str, ...], tuple[int, ...] | None]] = set()
        for index, raw in enumerate(raw_assets):
            if not isinstance(raw, dict):
                raise ScopePolicyError(f"assets[{index}] must be an object")
            raw_host = _required_text(raw, "host")
            wildcard = raw_host.startswith("*.")
            if "*" in raw_host and not wildcard:
                raise ScopePolicyError(f"assets[{index}].host has invalid wildcard")
            host = normalize_host(raw_host[2:] if wildcard else raw_host)
            raw_schemes = raw.get("schemes", ["https"])
            if not isinstance(raw_schemes, list) or not raw_schemes:
                raise ScopePolicyError(f"assets[{index}].schemes must be a non-empty array")
            schemes = frozenset(
                str(item).lower() for item in raw_schemes
                if isinstance(item, str) and str(item).lower() in _ALLOWED_SCHEMES
            )
            if len(schemes) != len(raw_schemes):
                raise ScopePolicyError(f"assets[{index}] contains an unsupported scheme")
            raw_ports = raw.get("ports")
            ports: frozenset[int] | None
            if raw_ports is None:
                ports = None
            else:
                if not isinstance(raw_ports, list) or not raw_ports:
                    raise ScopePolicyError(f"assets[{index}].ports must be a non-empty array")
                if any(type(port) is not int or not 1 <= port <= 65535 for port in raw_ports):
                    raise ScopePolicyError(f"assets[{index}] contains an invalid port")
                ports = frozenset(raw_ports)
            key = (host, wildcard, tuple(sorted(schemes)), tuple(sorted(ports)) if ports else None)
            if key in seen:
                raise ScopePolicyError(f"assets[{index}] duplicates an earlier rule")
            seen.add(key)
            assets.append(AssetRule(host, wildcard, schemes, ports))

        budget = data.get("request_budget")
        if not isinstance(budget, dict):
            raise ScopePolicyError("request_budget must be an object")
        total = budget.get("max_total_requests")
        per_host = budget.get("max_requests_per_host")
        if type(total) is not int or not 1 <= total <= 100000:
            raise ScopePolicyError("max_total_requests must be an integer from 1 to 100000")
        if type(per_host) is not int or not 1 <= per_host <= total:
            raise ScopePolicyError("max_requests_per_host must be between 1 and max_total_requests")

        return cls(
            engagement_id, program_name, authorization_reference,
            issued_at, expires_at, tuple(assets), total, per_host,
        )

    @classmethod
    def load(cls, path: str | Path) -> "EngagementManifest":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ScopePolicyError(f"cannot read manifest: {exc}") from exc
        return cls.from_dict(data)


def _required_text(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ScopePolicyError(f"{key} must be a non-empty string")
    return value.strip()


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: str
    engagement_id: str


def authorize_url(
    manifest: EngagementManifest,
    url: str,
    *,
    now: datetime | None = None,
) -> AuthorizationDecision:
    """Check one URL against explicit scope. Call again for every redirect."""
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ScopePolicyError("now must be timezone-aware")
    current = current.astimezone(timezone.utc)
    if current < manifest.issued_at:
        return AuthorizationDecision(False, "engagement_not_yet_valid", manifest.engagement_id)
    if current >= manifest.expires_at:
        return AuthorizationDecision(False, "engagement_expired", manifest.engagement_id)
    if not isinstance(url, str) or not url:
        return AuthorizationDecision(False, "invalid_url", manifest.engagement_id)
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in _ALLOWED_SCHEMES or not parsed.netloc:
            return AuthorizationDecision(False, "unsupported_or_relative_url", manifest.engagement_id)
        if parsed.username is not None or parsed.password is not None:
            return AuthorizationDecision(False, "url_credentials_forbidden", manifest.engagement_id)
        if parsed.fragment:
            return AuthorizationDecision(False, "url_fragment_forbidden", manifest.engagement_id)
        raw_host = parsed.hostname
        if not raw_host:
            return AuthorizationDecision(False, "missing_host", manifest.engagement_id)
        host = normalize_host(raw_host)
        port = parsed.port or (443 if scheme == "https" else 80)
    except (ValueError, ScopePolicyError):
        return AuthorizationDecision(False, "malformed_url", manifest.engagement_id)

    if not any(rule.matches(host, scheme, port) for rule in manifest.assets):
        return AuthorizationDecision(False, "target_not_in_scope", manifest.engagement_id)
    return AuthorizationDecision(True, "authorized_by_manifest", manifest.engagement_id)


class RequestBudget:
    """In-memory request counter. It does not send requests or provide persistence."""

    def __init__(self, manifest: EngagementManifest):
        from threading import Lock
        self._manifest = manifest
        self._total = 0
        self._per_host: dict[str, int] = {}
        self._lock = Lock()

    def consume(self, host: str) -> None:
        canonical = normalize_host(host)
        with self._lock:
            host_count = self._per_host.get(canonical, 0)
            if self._total >= self._manifest.max_total_requests:
                raise ScopePolicyError("total_request_budget_exhausted")
            if host_count >= self._manifest.max_requests_per_host:
                raise ScopePolicyError("per_host_request_budget_exhausted")
            self._total += 1
            self._per_host[canonical] = host_count + 1

    @property
    def usage(self) -> dict[str, Any]:
        with self._lock:
            return {"total": self._total, "per_host": dict(self._per_host)}
