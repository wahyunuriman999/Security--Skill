# Phase 1 — Canonical Core Implementation

**Status:** IN PROGRESS
**Branch:** `apex/phase-0-audit-2026-11-07`
**Phase 0 decision:** Bounded exit for isolated core development; legacy corpus and tools remain quarantined from execution.

## Implemented

- `apex/core/scope.py`: strict JSON manifest parsing, explicit authorization, timezone validity, IDNA normalization, exact and subdomain-only wildcard matching, scheme/port checks, malformed URL rejection, and in-memory request budgets.
- `authorize_and_reserve`: performs local scope authorization before reserving a request budget unit. It does not send network traffic.
- `apex/core/capabilities.py`: default-deny registry; unknown, disabled, prohibited, and network capabilities are denied.
- `apex/core/audit.py`: local JSONL audit ledger with sequence numbers, SHA-256 hash chain, verification, and sensitive-key redaction.
- `apex/core/findings.py`: immutable finding model and guarded lifecycle; confirmation requires evidence references, severity, impact, and confidence.
- `apex/core/store.py`: SQLite schema v5 with migrations from v1/v2/v3; persisted engagement manifests, finding records, immutable observation records, append-only event history/evidence metadata, durable request reservations, idempotency, transaction-serialized budget enforcement, and append-only request lifecycle events.
- `apex/core/observations.py`: immutable, validated observation model with finite-JSON and size bounds.
- `apex/core/evidence_store.py`: local content-addressed evidence storage; requires caller-attested redaction, applies a configurable size cap, uses immutable atomic writes, and verifies SHA-256 on every read. SQLite metadata registration verifies the object and size before linking it to a finding.
- `apex/core/gateway.py`: transport-free request preparation; GET/HEAD only, durable budget reservation, redirects disabled by default, and explicit per-destination authorization when redirects are manually enabled.
- `apex/tests/test_runtime_boundary.py`: CI guard against network and legacy-tool imports in the APEX runtime.
- `apex/cli.py`: local manifest validation and URL authorization commands.
- `apex/examples/engagement.example.json`: illustrative manifest using reserved example domains.
- `apex/tests/`: 83 deterministic unit tests covering scope, budgets, capability, audit, finding lifecycle, SQLite persistence/migrations, evidence linkage, append-only history, gateway policy, and runtime boundaries. Latest CI run [#25](https://github.com/wahyunuriman999/Security--Skill/actions/runs/42394169451) passed with the object store, evidence registration, concurrent budget test, and hardened runtime-boundary tests.
- CI now runs APEX unit tests in addition to the repository's static checks.

## Current safety properties

- No APEX HTTP client, DNS resolver, subprocess runner, or active scanner exists; the gateway only prepares local request descriptors and reserves budget.
- No legacy tool is imported or invoked.
- Scope authorization is local and deterministic.
- Wildcards do not match the apex domain.
- Unspecified ports default to scheme-standard ports only.
- Out-of-scope URLs do not consume request budget.
- Audit chain tampering is detected by verification.

## Known limitations

- Reservations have a durable state machine and single-use dispatch claim. Cancellation does not refund budget. Stale DISPATCHED request reconciliation/expiry and broader multi-process stress tests remain open.
- The audit ledger is hash-chained but not tamper-proof; multi-process locking and external immutable storage are not implemented.
- Redirects are disabled by default. A manually supplied absolute redirect destination must be independently authorized and reserve a new budget unit. There is no automatic redirect handling or DNS/IP rebinding defense.
- Engagement/finding/evidence metadata, immutable observations, and finding transitions persist in SQLite. Raw evidence bytes are stored locally by content hash; the storage root must be owned by the APEX user and redaction is caller-attested, not automatically detected.
- Capability registry is an allowlist descriptor, not an operating-system sandbox.
- Manifest approval reference is a user-supplied string; external proof validation is not automated.
- No runtime plugin/agent adapter system exists yet.

## Required next work

1. Add stronger canonicalization/property tests and broader migration fixtures.
2. Add backup/retention controls and independent review for the local content-addressed evidence store.
3. Add reservation reconciliation, expiry, cancellation, and concurrency stress tests.
4. Add DNS/IP rebinding-resistant destination pinning design and tests before any transport exists.
5. Add independent review and benchmark fixtures. No active transport until separately approved.

## Exit rule

Phase 1 is not complete until core models, persistence, scope tests, audit integrity tests, and regression checks are documented and pass. This phase does not authorize active target testing.
