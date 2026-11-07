import unittest

from apex.core.capabilities import (
    Capability, CapabilityDenied, CapabilityRegistry, RiskLevel,
)


class TestCapabilityRegistry(unittest.TestCase):
    def test_default_registry_exposes_only_local_capabilities(self):
        registry = CapabilityRegistry()
        snapshot = registry.snapshot()
        self.assertGreaterEqual(len(snapshot), 1)
        self.assertTrue(all(item["network_access"] is False for item in snapshot))
        self.assertTrue(all(item["risk"] != "prohibited" for item in snapshot))

    def test_unknown_capability_is_denied(self):
        with self.assertRaisesRegex(CapabilityDenied, "unknown_capability"):
            CapabilityRegistry().require("legacy.execute")

    def test_network_capability_is_denied_even_if_enabled(self):
        registry = CapabilityRegistry((
            Capability("network.fetch", "not available", RiskLevel.MODERATE,
                       enabled=True, network_access=True),
        ))
        with self.assertRaisesRegex(CapabilityDenied, "network_capabilities"):
            registry.require("network.fetch")

    def test_prohibited_capability_is_denied(self):
        registry = CapabilityRegistry((
            Capability("c2.execute", "prohibited", RiskLevel.PROHIBITED),
        ))
        with self.assertRaisesRegex(CapabilityDenied, "capability_disabled"):
            registry.require("c2.execute")

    def test_approval_is_required_when_declared(self):
        registry = CapabilityRegistry((
            Capability("active.test", "requires approval", RiskLevel.HIGH,
                       requires_user_approval=True),
        ))
        with self.assertRaisesRegex(CapabilityDenied, "explicit_user_approval"):
            registry.require("active.test")
        self.assertEqual(registry.require("active.test", user_approved=True).capability_id,
                         "active.test")

    def test_duplicate_ids_rejected(self):
        item = Capability("same", "duplicate", RiskLevel.LOW)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            CapabilityRegistry((item, item))


if __name__ == "__main__":
    unittest.main()
