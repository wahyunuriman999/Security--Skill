# APEX Core

APEX is an authorized security-research workspace. The initial core is deliberately local-only and dependency-free.

## Current implementation

- Strict JSON engagement manifest parser.
- Explicit authorization flag and validity window.
- Exact-host and strict subdomain-wildcard matching.
- IDNA hostname normalization and IP literal normalization.
- Scheme and port allowlists; omitted ports mean standard scheme ports only.
- URL credentials and fragments rejected.
- Per-engagement and per-host in-memory request budget primitive.
- Default-deny capability registry; network, unknown, disabled, and prohibited capabilities are denied.
- Local JSONL audit ledger with sequence numbers, SHA-256 hash chaining, integrity verification, strict finite-JSON canonicalization, and sensitive-key redaction.
- SQLite schema v4 for persisted engagements, finding lifecycle events, immutable observations, evidence metadata, and durable idempotent request-budget reservations with append-only lifecycle events and single-use dispatch claims; cancellation does not refund budget.
- Local content-addressed evidence object store with redaction attestation, size bounds, atomic immutable writes, and SHA-256 verification on reads.
- Append-only database triggers for observation records, evidence metadata, and finding event history; evidence must be local-reference-only and redacted before it can support an observed/confirmed finding.
- Evidence-gated finding lifecycle with explicit legal transitions and confirmation requirements.
- CLI for local manifest validation and URL authorization.
- Deterministic unit tests; no outbound network calls.

## Safety boundary

The current version does not contain an HTTP client, DNS resolver, scanner, subprocess runner, or legacy-tool adapter. It cannot send requests. The authorization function must be called for every URL, including every redirect target, when a future gateway is implemented.

Legacy files under `tools/` and `security/` are not imported or invoked. The knowledge corpus remains unchanged and is not treated as executable authorization.

## Knowledge registry

Search the preserved 1,001-skill corpus without executing any skill:

```powershell
python -m apex.cli knowledge-search "bug bounty" --root . --limit 10
python -m apex.cli knowledge-show bug-bounty --root .
```

Returned skill text is untrusted instruction data. It must not bypass APEX scope, capability, approval, or audit controls.

## Quick start

From the repository root:

```powershell
python -m apex.cli validate-manifest apex/examples/engagement.example.json
python -m apex.cli authorize-url apex/examples/engagement.example.json https://example.com/
python -m unittest discover -s apex/tests -v
```

The example manifest is illustrative only. Replace it with a program's actual written scope and authorization reference before any future authorized testing. The example domain is not an authorization to test any real system.

## Manifest rules

- `schema_version` must be `1`.
- `authorization.authorized` must be the literal boolean `true`.
- `authorization.reference` must identify the written program scope/approval.
- `issued_at` and `expires_at` must be timezone-aware ISO-8601 timestamps.
- `assets` must contain at least one exact hostname or `*.example.com` wildcard.
- Wildcards match subdomains only, never the apex domain.
- Supported schemes are HTTP and HTTPS. Default scheme is HTTPS.
- If `ports` is omitted, only 443 for HTTPS or 80 for HTTP is permitted.
- Request budgets are mandatory and bounded.

## Current limitations

This is a policy primitive, not yet an active execution gateway. Redirect handling, DNS/IP rebinding defenses, request signing, raw evidence object storage, reservation cancellation/reconciliation, concurrency stress validation, and process isolation are not implemented. The audit ledger is local and hash-chained, but it is not tamper-proof and does not provide multi-process locking. Do not connect an active scanner until those controls exist and have independent tests.
