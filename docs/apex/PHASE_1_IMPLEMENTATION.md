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
- `apex/tests/test_runtime_boundary.py`: CI guard against network and legacy-tool imports in the APEX runtime.
- `apex/cli.py`: local manifest validation and URL authorization commands.
- `apex/examples/engagement.example.json`: illustrative manifest using reserved example domains.
- `apex/tests/`: deterministic unit tests for scope, budget, capability, audit, finding lifecycle, and runtime boundary behavior.
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

- Request budgets are in-memory and reset when the process exits.
- The audit ledger is hash-chained but not tamper-proof; multi-process locking and external immutable storage are not implemented.
- No redirect handling or DNS/IP rebinding defense exists because there is no network gateway yet.
- No persistent engagement, observation, lead, finding, or evidence database exists.
- Capability registry is an allowlist descriptor, not an operating-system sandbox.
- Manifest approval reference is a user-supplied string; external proof validation is not automated.
- No runtime plugin/agent adapter system exists yet.

## Required next work

1. Add manifest schema versioning and stronger canonicalization/property tests.
2. Implement a persistent SQLite engagement and event store with migrations.
3. Implement a request gateway interface that has no default transport and rejects all redirects unless re-authorized.
4. Add durable budgets, cancellation, and idempotency.
5. Add evidence and finding state models with immutable provenance.
6. Add independent review and benchmark fixtures before exposing any active transport.

## Exit rule

Phase 1 is not complete until core models, persistence, scope tests, audit integrity tests, and regression checks are documented and pass. This phase does not authorize active target testing.
