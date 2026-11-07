# APEX — Focused Static Code Review Findings

**Date:** 2026-11-07  
**Status:** Preliminary static review; no runtime tests executed.

## APEX-010 — TLS certificate verification disabled
- **Source:** BountyForge `tools/hunt.py`, lines 132 and 176.
- **Evidence:** curl commands include `-sk`; `-k` disables certificate verification.
- **Impact:** TLS peer identity is not verified; evidence integrity can be undermined.
- **Required action:** verified TLS by default and explicit CA bundle support.
- **Gate:** release blocker.

## APEX-011 — No mandatory pre-request scope gate demonstrated
- **Source:** BountyForge `tools/hunt.py`, lines 793-880.
- **Evidence:** CLI accepts a target, loads recon hosts, then executes checks without a visibly mandatory engagement manifest or central request authorization.
- **Related source:** `tools/agent_isolation.py`, lines 294-327; finding-level scope checks use substring matching.
- **Impact:** post-hoc checks do not prevent out-of-scope requests; substring matching is not safe hostname boundary validation.
- **Required action:** fail-closed authorization before every outbound request and redirect; canonical host/IP/port parsing and exact/wildcard boundary semantics.
- **Gate:** release blocker.

## APEX-012 — Isolation checker is not a runtime sandbox
- **Source:** BountyForge `tools/agent_isolation.py`, lines 212-228 and 294-371.
- **Evidence:** code loads a scope list and evaluates finding/permission metadata.
- **Impact:** a finding checker cannot constrain subprocess, filesystem, or network behavior at execution time.
- **Required action:** central execution gateway plus least-privilege process/network sandbox.
- **Gate:** release blocker for autonomous active testing.

## APEX-013 — OPSEC/evasion features are coupled to default hunting
- **Source:** BountyForge `tools/hunt.py`, lines 814-817; `tools/opsec.py`, lines 121-210, 215-256, 279-293.
- **Evidence:** OPSEC rotator is initialized unless `--no-opsec`; module supports UA/header rotation, jitter, Tor proxy, and TLS fingerprint variation.
- **Impact:** can obscure attribution and conflict with program rules.
- **Required action:** exclude from default APEX; use transparent identity, scope-aware request budgets, and compliant backoff.
- **Gate:** excluded from default workflow.

## APEX-014 — Security--Skill validator coverage gaps
- **Source:** `scripts/validate.py`, lines 20-66.
- **Evidence:** checks frontmatter presence/fields, duplicate names, directory agreement, relative Markdown links, manifest names and total count.
- **Gap:** does not validate each manifest path, domain taxonomy, trigger quality, complete frontmatter schema, asset references, or routing fixtures.
- **Required action:** extend with path equality, schema validation, reference graph, taxonomy, and deterministic routing tests.
- **Gate:** Phase 1 prerequisite.

## APEX-015 — Limited test/CI coverage
- **Sources:** BountyForge `tests/test_leads.py`, `tests/test_observation.py`; Security--Skill `tools/tests/test_rat_tools.py`.
- **Evidence:** only these test modules were found; no root-level CI workflow was found. BountyForge has a nested third-party Pashov version-bump workflow.
- **Gap:** no visible comprehensive tests for scope enforcement, request authorization, network execution safety, agent adapters, or end-to-end workflows.
- **Required action:** root CI with no-network deterministic fixtures, isolated state, static checks, and dependency scanning.
- **Gate:** Phase 1 prerequisite.

## Review constraints

- Findings are based on static inspection at the referenced repository snapshots.
- They are not claims of exploitability against a live target.
- Tests have not been executed.
- No BountyForge implementation code is approved for direct import.
- APEX Phase 0 remains open.
