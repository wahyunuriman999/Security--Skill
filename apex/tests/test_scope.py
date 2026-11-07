from __future__ import annotations

import unittest
from datetime import datetime, timezone

from apex.core.scope import (
    EngagementManifest, RequestBudget, ScopePolicyError, authorize_url, authorize_and_reserve, normalize_host,
)


NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)


def manifest(**overrides):
    data = {
        "schema_version": 1,
        "engagement_id": "eng-test-001",
        "program_name": "Local fixture program",
        "authorization": {"authorized": True, "reference": "https://example.test/policy"},
        "issued_at": "2026-11-01T00:00:00Z",
        "expires_at": "2026-12-01T00:00:00Z",
        "assets": [
            {"host": "example.com", "schemes": ["https"], "ports": [443]},
            {"host": "*.example.net", "schemes": ["https"], "ports": [443]},
        ],
        "request_budget": {"max_total_requests": 3, "max_requests_per_host": 2},
    }
    data.update(overrides)
    return EngagementManifest.from_dict(data)


class TestManifestValidation(unittest.TestCase):
    def test_valid_manifest(self):
        self.assertEqual(manifest().engagement_id, "eng-test-001")

    def test_requires_explicit_authorization(self):
        with self.assertRaises(ScopePolicyError):
            manifest(authorization={"authorized": False, "reference": "policy"})

    def test_requires_timezone(self):
        with self.assertRaises(ScopePolicyError):
            manifest(issued_at="2026-11-01T00:00:00")

    def test_rejects_invalid_ports(self):
        with self.assertRaises(ScopePolicyError):
            manifest(assets=[{"host": "example.com", "ports": [0]}])

    def test_rejects_unsupported_schemes(self):
        with self.assertRaises(ScopePolicyError):
            manifest(assets=[{"host": "example.com", "schemes": ["ftp"]}])

    def test_normalizes_idna(self):
        self.assertEqual(normalize_host("BÜCHER.example"), "xn--bcher-kva.example")

    def test_single_trailing_dot_is_normalized(self):
        self.assertEqual(normalize_host("example.com."), "example.com")

    def test_multiple_trailing_dots_rejected(self):
        with self.assertRaises(ScopePolicyError):
            normalize_host("example.com..")

    def test_wildcard_ip_literal_rejected(self):
        with self.assertRaises(ScopePolicyError):
            manifest(assets=[{"host": "*.127.0.0.1"}])


class TestScopeAuthorization(unittest.TestCase):
    def setUp(self):
        self.policy = manifest()

    def test_exact_host_allowed(self):
        d = authorize_url(self.policy, "https://example.com/account", now=NOW)
        self.assertTrue(d.allowed)

    def test_wildcard_subdomain_allowed(self):
        d = authorize_url(self.policy, "https://api.example.net/v1", now=NOW)
        self.assertTrue(d.allowed)

    def test_wildcard_does_not_match_apex(self):
        d = authorize_url(self.policy, "https://example.net/", now=NOW)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "target_not_in_scope")

    def test_suffix_confusion_rejected(self):
        d = authorize_url(self.policy, "https://example.com.attacker.test/", now=NOW)
        self.assertFalse(d.allowed)

    def test_scheme_mismatch_rejected(self):
        d = authorize_url(self.policy, "http://example.com/", now=NOW)
        self.assertFalse(d.allowed)

    def test_port_mismatch_rejected(self):
        d = authorize_url(self.policy, "https://example.com:8443/", now=NOW)
        self.assertFalse(d.allowed)

    def test_zero_port_rejected(self):
        d = authorize_url(self.policy, "https://example.com:0/", now=NOW)
        self.assertFalse(d.allowed)

    def test_unspecified_ports_default_to_scheme_port(self):
        policy = manifest(assets=[{"host": "example.org", "schemes": ["https"]}])
        self.assertTrue(authorize_url(policy, "https://example.org/", now=NOW).allowed)
        self.assertFalse(authorize_url(policy, "https://example.org:8443/", now=NOW).allowed)

    def test_url_credentials_rejected(self):
        d = authorize_url(self.policy, "https://user:pass@example.com/", now=NOW)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "url_credentials_forbidden")

    def test_empty_explicit_port_rejected(self):
        d = authorize_url(self.policy, "https://example.com:/", now=NOW)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "malformed_url")

    def test_fragment_rejected(self):
        d = authorize_url(self.policy, "https://example.com/#section", now=NOW)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "url_fragment_forbidden")

    def test_empty_fragment_marker_rejected(self):
        d = authorize_url(self.policy, "https://example.com/#", now=NOW)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "url_fragment_forbidden")

    def test_control_characters_and_backslashes_rejected(self):
        for target in (" https://example.com/", "https://example.com/\\\\path",
                       "https://example.com/\\nheader"):
            with self.subTest(target=repr(target)):
                self.assertFalse(authorize_url(self.policy, target, now=NOW).allowed)

    def test_malformed_url_rejected(self):
        self.assertFalse(authorize_url(self.policy, "https://exa mple.com", now=NOW).allowed)

    def test_expired_manifest_rejected(self):
        d = authorize_url(self.policy, "https://example.com/", now=datetime(2027, 1, 1, tzinfo=timezone.utc))
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "engagement_expired")

    def test_not_yet_valid_manifest_rejected(self):
        d = authorize_url(self.policy, "https://example.com/", now=datetime(2026, 10, 1, tzinfo=timezone.utc))
        self.assertFalse(d.allowed)


class TestRequestBudget(unittest.TestCase):
    def test_total_and_per_host_budgets(self):
        budget = RequestBudget(manifest())
        budget.consume("example.com")
        budget.consume("example.com")
        with self.assertRaisesRegex(ScopePolicyError, "per_host"):
            budget.consume("example.com")
        budget.consume("api.example.net")
        with self.assertRaisesRegex(ScopePolicyError, "total"):
            budget.consume("other.example.net")
        self.assertEqual(budget.usage["total"], 3)

    def test_scope_gate_reserves_only_authorized_requests(self):
        policy = manifest()
        budget = RequestBudget(policy)
        denied = authorize_and_reserve(policy, budget, "https://outside.test/", now=NOW)
        self.assertFalse(denied.allowed)
        self.assertEqual(budget.usage["total"], 0)
        allowed = authorize_and_reserve(policy, budget, "https://example.com/", now=NOW)
        self.assertTrue(allowed.allowed)
        self.assertEqual(budget.usage["total"], 1)

    def test_scope_gate_fails_when_budget_is_exhausted(self):
        policy = manifest(request_budget={"max_total_requests": 1, "max_requests_per_host": 1})
        budget = RequestBudget(policy)
        authorize_and_reserve(policy, budget, "https://example.com/", now=NOW)
        with self.assertRaisesRegex(ScopePolicyError, "total_request_budget_exhausted"):
            authorize_and_reserve(policy, budget, "https://api.example.net/", now=NOW)


if __name__ == "__main__":
    unittest.main()
