# APEX — Migration Plan

**Status:** Proposed. Phase 0 remains open.

## Phase 0 — Deep Repository Audit
- Inventory both repositories and capture immutable tree references.
- Map exact duplicate blobs and shared skill names.
- Review provenance and licenses.
- Review all executable tools, dependencies, and side effects.
- Run baseline validation and tests in a controlled checkout.
- Freeze architecture and quality gates.

**Exit:** reviewed Phase 0 report and no unresolved critical provenance/safety blocker.

## Phase 1 — Canonical Core and Baseline Repair
- Add root vendor-neutral `SKILL.md` entrypoint.
- Define canonical schemas for engagement, scope, asset, hypothesis, observation, lead, finding, and evidence.
- Improve manifest validator to verify paths, metadata, links, and routing integrity.
- Add CI for deterministic validation and regression tests.
- Do not rewrite the 1,001-skill corpus.

## Phase 2 — Knowledge Registry
- Build taxonomy and retrieval index.
- Add provenance fields and per-skill quality status.
- Introduce relevance ranking and ambiguity handling.
- Keep original skill paths stable.

## Phase 3 — Research State and Orchestration
- Implement lead/finding state machine.
- Add observation/control comparison and evidence ledger.
- Add specialist task contracts and sequential fallback.
- Add agent adapters only after capability tests.

## Phase 4 — Domain Packs
- Web/API
- Web3 and smart contracts
- Mobile
- Cloud and identity / Active Directory
- AI/LLM and agentic systems
- Network, IoT, and infrastructure
- Malware, forensics, incident response, and detection

Each pack has its own safe test fixtures and domain-specific validators.

## Phase 5 — Adversarial Validation and Reporting
- Independent refutation.
- Demonstrated/inferred/unproven classification.
- Duplicate and chain analysis.
- Evidence redaction and replay instructions.
- Program-specific severity and reporting rules.

## Phase 6 — Benchmark and Release
- Run all positive, negative, ambiguous, scope, chain, regression, and compatibility cases.
- Publish transparent metrics and known limitations.
- Release only after all blocking quality gates pass.

## Migration invariants

1. No bulk deletion or renaming of existing skills.
2. No direct import of unlicensed upstream code.
3. No active third-party testing as part of build or CI.
4. Every change has a test and rollback path.
5. Keep the default branch unchanged until explicit phase approval.
