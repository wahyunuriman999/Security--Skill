import tempfile
import unittest
from pathlib import Path

from apex.core.findings import FindingStatus
from apex.core.gateway import GatewayDenied, RequestGateway
from apex.core.scope import EngagementManifest
from apex.core.store import SQLiteStore


def manifest():
    return EngagementManifest.from_dict({
        "schema_version": 1,
        "engagement_id": "eng-gateway-1",
        "program_name": "Gateway fixture",
        "authorization": {"authorized": True, "reference": "https://example.test/policy"},
        "issued_at": "2026-11-01T00:00:00Z",
        "expires_at": "2026-12-01T00:00:00Z",
        "assets": [{"host": "example.test", "schemes": ["https"], "ports": [443]}],
        "request_budget": {"max_total_requests": 5, "max_requests_per_host": 5},
    })


class TestRequestGateway(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.tmp.name) / "apex.db")
        self.store.initialize()
        self.policy = manifest()
        self.store.save_engagement(self.policy)
        self.gateway = RequestGateway(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def test_prepare_only_returns_descriptor_and_reserves_budget(self):
        prepared = self.gateway.prepare(
            self.policy, request_id="req-1", method="get", url="https://example.test/",
        )
        self.assertEqual(prepared.method, "GET")
        self.assertTrue(prepared.reserved)
        self.assertEqual(prepared.engagement_id, self.policy.engagement_id)

    def test_mutating_methods_are_denied(self):
        for method in ("POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"):
            with self.subTest(method=method):
                with self.assertRaisesRegex(GatewayDenied, "method_not_permitted"):
                    self.gateway.prepare(
                        self.policy, request_id="req-" + method,
                        method=method, url="https://example.test/",
                    )

    def test_replayed_request_id_cannot_be_prepared_for_second_dispatch(self):
        self.gateway.prepare(
            self.policy, request_id="req-once", method="GET",
            url="https://example.test/once",
        )
        with self.assertRaisesRegex(GatewayDenied, "request_id_already_reserved"):
            self.gateway.prepare(
                self.policy, request_id="req-once", method="GET",
                url="https://example.test/once",
            )

    def test_out_of_scope_target_is_denied(self):
        with self.assertRaisesRegex(GatewayDenied, "target_not_in_scope"):
            self.gateway.prepare(
                self.policy, request_id="req-out", method="GET",
                url="https://outside.test/",
            )

    def test_redirects_are_disabled_by_default(self):
        with self.assertRaisesRegex(GatewayDenied, "redirects_disabled"):
            self.gateway.prepare_redirect(
                self.policy, response_status=302, location="https://example.test/next",
                request_id="req-redirect",
            )

    def test_each_explicit_redirect_is_independently_authorized_and_reserved(self):
        first = self.gateway.prepare(
            self.policy, request_id="req-first", method="GET",
            url="https://example.test/start",
        )
        second = self.gateway.prepare_redirect(
            self.policy, response_status=302, location="https://example.test/next",
            request_id="req-second", allow_redirects=True,
        )
        self.assertEqual(first.request_id, "req-first")
        self.assertEqual(second.request_id, "req-second")
        self.assertEqual(second.url, "https://example.test/next")

    def test_redirect_outside_scope_is_denied(self):
        with self.assertRaisesRegex(GatewayDenied, "target_not_in_scope"):
            self.gateway.prepare_redirect(
                self.policy, response_status=302, location="https://outside.test/",
                request_id="req-bad-redirect", allow_redirects=True,
            )

    def test_relative_redirect_is_denied(self):
        with self.assertRaisesRegex(GatewayDenied, "absolute_redirect_url_required"):
            self.gateway.prepare_redirect(
                self.policy, response_status=302, location="/next",
                request_id="req-relative", allow_redirects=True,
            )

    def test_non_string_redirect_location_is_denied(self):
        with self.assertRaisesRegex(GatewayDenied, "invalid_redirect_location"):
            self.gateway.prepare_redirect(
                self.policy, response_status=302, location=None,
                request_id="req-none", allow_redirects=True,
            )


if __name__ == "__main__":
    unittest.main()
