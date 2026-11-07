# APEX — Test Coverage Inventory (Static Inventory)

**Date:** 2026-11-07  
**Status:** Inventory complete; tests not executed.

## Discovered test modules

| Repository | Test module | Test methods discovered |
|---|---|---:|
| Security--Skill | `tools/tests/test_rat_tools.py` | 8 |
| BountyForge | `tests/test_leads.py` | 25 |
| BountyForge | `tests/test_observation.py` | 27 |
| **Total** | **3 modules** | **60** |

Counts are based on test method declarations matching Python `def test_...` in the retrieved source snapshots. This is a static count, not a test-run result.

## Coverage strengths visible from test names and fixtures

### BountyForge lead ledger — 25 tests
- Lead persistence and reload.
- State transitions and promotion.
- Trigger/impact evidence requirements.
- Refutation guards and parking.
- Preconditions and mutation tracking.
- Chain partner discovery.

### BountyForge observation/oracle — 27 tests
- Candidate/control comparisons.
- Status, body, header, timing, redirect divergence.
- Ambiguous observation handling and deterministic follow-up.
- LLM advisory boundary.
- Provenance, tamper-evident hash, and persistence.
- Probe URL encoding.

### Security--Skill RAT tools — 8 tests
- Header collection.
- Decompression.
- DNS-over-HTTPS parsing.
- Digest challenge parsing and supported algorithms.
- Import and output formatting.

## Critical coverage gaps

No discovered tests directly establish:
- Mandatory authorization before every outbound request.
- Exact hostname/wildcard scope matching, IDNA, IP literals, ports, redirects, or DNS rebinding defenses.
- TLS verification defaults.
- Request concurrency/rate/time/data budgets.
- Credential redaction and secret handling across logs/artifacts.
- Filesystem/network sandbox guarantees for subprocesses.
- Agent adapter compatibility and sequential fallback.
- End-to-end no-network orchestration.
- Domain-wide benchmark precision/recall and severity calibration.

## Required baseline execution

Run only in a disposable, network-disabled checkout:
1. BountyForge: `python3 -m unittest discover -s tests -v`
2. Security--Skill: `python3 -m unittest discover -s tools/tests -v`
3. Security--Skill validator: `python3 scripts/validate.py`

Capture interpreter version, dependency lock state, exact commit SHA, command, exit code, stdout/stderr, and duration. Do not report a pass until commands have actually executed. Keep generated `state/` and temporary files isolated and clean them only inside the disposable test workspace.

## APEX baseline policy

The existing 60 tests are upstream regression assets, not an APEX quality benchmark. APEX must add negative tests for authorization failures, boundary-hostname confusion, redirect escape, invalid TLS, budget exhaustion, state corruption, and evidence provenance. CI must not send requests to live third-party systems.
