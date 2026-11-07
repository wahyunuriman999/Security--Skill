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
- `apex/core/store.py`: SQLite schema v3 with migrations from v1/v2; persisted engagement manifests, finding records, immutable event history/evidence metadata, durable request reservations, idempotency, and transaction-serialized budget enforcement.
- `apex/tests/test_runtime_boundary.py`: CI guard against network and legacy-tool imports in the APEX runtime.
- `apex/cli.py`: local manifest validation and URL authorization commands.
- `apex/examples/engagement.example.json`: illustrative manifest using reserved example domains.
- `apex/tests/`: 55 deterministic unit tests covering scope, budgets, capability, audit, finding lifecycle, SQLite persistence/migrations, evidence linkage, append-only history, and runtime boundaries. Latest CI run [#19](https://github.com/wahyunuriman999/Security--Skill/actions/runs/42392728802) passed.
- CI now runs APEX unit tests in addition to the repository's static checks.

## Current safety properties

- No APEX HTTP client, DNS resolver, subprocess runner, or active scanner exists.
- No legacy tool is imported or invoked.
- Scope authorization is local and deterministic.
- Wildcards do not match the apex domain.
- Unspecified ports default to scheme-standard ports only.
- Out-of-scope URLs do not consume request budget.
- Audit chain tampering is detected by verification.

## Known limitations

- Durable reservations are persisted, but cancellation/expiry/reconciliation semantics and multi-process stress tests are not complete.
- The audit ledger is hash-chained but not tamper-proof; multi-process locking and external immutable storage are not implemented.
- No redirect handling or DNS/IP rebinding defense exists because there is no network gateway yet.
- Engagement/finding/evidence metadata and finding transitions persist in SQLite. There is no separate immutable observation model or raw evidence object store yet.
- Capability registry is an allowlist descriptor, not an operating-system sandbox.
- Manifest approval reference is a user-supplied string; external proof validation is not automated.
- No runtime plugin/agent adapter system exists yet.

## Required next work

1. Add stronger canonicalization/property tests and migration fixtures.
2. Add immutable observation records and a controlled raw evidence storage design.
3. Add reservation reconciliation, expiry, cancellation, and concurrency stress tests.
4. Implement a request gateway interface with no default transport; every redirect destination must be independently authorized and reserved.
5. Add independent review and benchmark fixtures. No active transport until separately approved.

## Exit rule

Phase 1 is not complete until core models, persistence, scope tests, audit integrity tests, and regression checks are documented and pass. This phase does not authorize active target testing.
