# Phase 0 Exit Decision — Safe APEX Build Boundary

**Decision:** Phase 0 is closed for the purpose of starting an independently authored, dependency-free APEX core. This is a bounded exit, not a certification of the legacy repository.

## Why a bounded exit is acceptable

The purpose of Phase 0 is to establish what can safely enter the APEX runtime. The audit has established a strict boundary:

1. Existing knowledge corpus remains preserved and read-only.
2. Existing scripts and tools are not automatically registered as capabilities.
3. All nine files under `tools/` have a file-level safety disposition; high-risk tools are prohibited from the APEX runtime.
4. The `security/` executable inventory is recorded, and active network tools, subprocess tools, sensitive-data tools, and local dashboards have explicit restrictions.
5. No BountyForge files are bulk-imported; byte-identical files do not imply redistribution rights.
6. New APEX core code will use Python standard library only until a dependency is separately approved and pinned.
7. All active target-directed traffic must be impossible without a valid engagement manifest and a future centralized request gateway.

## Residual risks that remain open

- The full legacy knowledge corpus has not received a manual line-by-line safety review.
- Not every legacy executable has received a complete manual code review.
- Dependency provenance for the legacy tool collection is incomplete.
- The existing `tools/tests/test_rat_tools.py` suite has not been executed.
- The repository has no root license declaration; no new license is inferred or applied.

These are not silently accepted as safe. They are contained by excluding legacy tools from APEX runtime, treating the knowledge corpus as non-executable reference material, and making the new core independent of legacy dependencies.

## Phase 1 constraints

- No import or execution of legacy `tools/` or `security/` code from APEX core.
- No outbound network client in the initial core.
- Scope parsing and authorization are pure local operations.
- Every active capability is deny-by-default and unavailable until separately reviewed.
- No secrets or raw credentials in logs.
- Tests use deterministic local fixtures only.
- Preserve the full legacy skill tree and routing manifest byte-for-byte.

## Exit evidence

- Baseline CI passed: [run 42391343731](https://github.com/wahyunuriman999/Security--Skill/actions/runs/42391343731).
- Existing skill/routing validation passed.
- Python, JavaScript, and shell syntax checks passed.
- Static review and executable inventory are recorded in the linked Phase 0 audit documents.

## Decision boundary

This decision authorizes Phase 1 work on the isolated APEX core only. It does **not** authorize active testing against third-party systems, integration of quarantined tools, public release of the legacy corpus, or claiming the entire repository is secure.
