"""Default-deny capability registry.

The registry describes local APEX capabilities only. It does not load Python
plugins, import legacy scripts, or execute arbitrary commands.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CapabilityDenied(PermissionError):
    pass


class RiskLevel(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    PROHIBITED = "prohibited"


@dataclass(frozen=True)
class Capability:
    capability_id: str
    description: str
    risk: RiskLevel
    enabled: bool = True
    requires_user_approval: bool = False
    network_access: bool = False


_DEFAULT_CAPABILITIES = (
    Capability("manifest.validate", "Validate a local engagement manifest", RiskLevel.LOW),
    Capability("scope.authorize", "Check a URL against a local scope manifest", RiskLevel.LOW),
    Capability("gateway.prepare", "Prepare a request descriptor and reserve local budget without sending traffic", RiskLevel.LOW),
    Capability("audit.append", "Append a local hash-chained audit event", RiskLevel.LOW),
    Capability("knowledge.read", "Read existing knowledge files without executing them", RiskLevel.LOW),
)


class CapabilityRegistry:
    """Explicit allowlist; unknown, disabled, network, and prohibited capabilities fail."""

    def __init__(self, capabilities: tuple[Capability, ...] = _DEFAULT_CAPABILITIES):
        self._capabilities: dict[str, Capability] = {}
        for capability in capabilities:
            if capability.capability_id in self._capabilities:
                raise ValueError(f"duplicate capability: {capability.capability_id}")
            self._capabilities[capability.capability_id] = capability

    def require(self, capability_id: str, *, user_approved: bool = False) -> Capability:
        capability = self._capabilities.get(capability_id)
        if capability is None:
            raise CapabilityDenied("unknown_capability")
        if not capability.enabled or capability.risk is RiskLevel.PROHIBITED:
            raise CapabilityDenied("capability_disabled")
        if capability.network_access:
            raise CapabilityDenied("network_capabilities_not_available_in_this_release")
        if capability.requires_user_approval and not user_approved:
            raise CapabilityDenied("explicit_user_approval_required")
        return capability

    def snapshot(self) -> list[dict[str, object]]:
        return [
            {
                "capability_id": item.capability_id,
                "description": item.description,
                "risk": item.risk.value,
                "enabled": item.enabled,
                "requires_user_approval": item.requires_user_approval,
                "network_access": item.network_access,
            }
            for item in sorted(self._capabilities.values(), key=lambda x: x.capability_id)
        ]
