"""Policy-only request gateway preparation.

This module reserves authorization and request budget but never sends traffic.
There is intentionally no default HTTP transport or automatic redirect handler.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from apex.core.scope import EngagementManifest
from apex.core.store import SQLiteStore, StoreError


class GatewayDenied(PermissionError):
    pass


@dataclass(frozen=True)
class PreparedRequest:
    request_id: str
    engagement_id: str
    method: str
    url: str
    reserved: bool


class RequestGateway:
    """Prepare an authorized, budget-reserved request descriptor; never performs I/O."""

    _METHODS = frozenset({"GET", "HEAD"})
    _REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

    def __init__(self, store: SQLiteStore):
        if not isinstance(store, SQLiteStore):
            raise TypeError("RequestGateway requires an initialized SQLiteStore")
        self._store = store

    def prepare(
        self, manifest: EngagementManifest, *, request_id: str,
        method: str, url: str,
    ) -> PreparedRequest:
        if not isinstance(method, str) or method.upper() not in self._METHODS:
            raise GatewayDenied("method_not_permitted")
        if not isinstance(url, str) or not url:
            raise GatewayDenied("invalid_url")
        reservation = self._store.reserve_request(
            manifest, request_id=request_id, url=url,
        )
        if not reservation.decision.allowed:
            raise GatewayDenied(reservation.decision.reason)
        if reservation.replayed:
            raise GatewayDenied("request_id_already_reserved_no_replay")
        return PreparedRequest(
            request_id=request_id,
            engagement_id=manifest.engagement_id,
            method=method.upper(),
            url=url,
            reserved=True,
        )

    def prepare_redirect(
        self, manifest: EngagementManifest, *, response_status: int,
        location: str, request_id: str, method: str = "GET",
        allow_redirects: bool = False,
    ) -> PreparedRequest:
        """Authorize one redirect destination explicitly; never resolves relative URLs."""
        if response_status not in self._REDIRECT_CODES:
            raise GatewayDenied("response_is_not_a_redirect")
        if allow_redirects is not True:
            raise GatewayDenied("redirects_disabled")
        parsed = urlsplit(location)
        if not parsed.scheme or not parsed.netloc:
            raise GatewayDenied("absolute_redirect_url_required")
        return self.prepare(
            manifest, request_id=request_id, method=method, url=location,
        )
