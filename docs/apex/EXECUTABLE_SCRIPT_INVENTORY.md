# APEX Executable Script Inventory

**Status:** Preliminary static inventory; not a Phase 0 sign-off.
**Branch:** `apex/phase-0-audit-2026-11-07`
**Review date:** 2026-11-07
**Method:** Repository tree inventory plus targeted source inspection and pattern-based review. No scripts were executed.

## Summary

The reviewed branch contains executable Python, JavaScript, and shell scripts across `scripts/`, `security/`, and `tools/`. The original nine-file `tools/` review is documented separately in [EXECUTABLE_TOOL_SAFETY_REVIEW.md](EXECUTABLE_TOOL_SAFETY_REVIEW.md).

This inventory classifies purpose and the most important control gaps visible from source inspection. It does not certify correctness, absence of vulnerabilities, or safe runtime behavior.

## Preliminary file inventory

| Path | Observed role | Risk / required disposition |
|---|---|---|
| `scripts/validate.py` | Local skill/frontmatter/link/manifest validator | Keep as baseline; extend schema, path equality, taxonomy, routing fixtures, and safe parsing. |
| `security/bounty-hunt-pipeline/scripts/rat_oob.py` | External webhook callback registration/send/poll/wait | Require explicit engagement authorization, user-owned token, bounded polling, redaction, and mock transport. |
| `security/credential-exposure-audit/scripts/cekbocor.py` | Local password hash + HIBP range check; email breach lookup | Sensitive-data workflow. Password plaintext is locally hashed, but email is sent to HIBP. Require explicit consent, no secrets in logs/history, strict data minimization, and mocked tests. |
| `security/fizz/scripts/ensure_foundry.sh` | Foundry environment setup | Review shell commands, download sources, checksums/signatures, and idempotency before automated invocation. |
| `security/fizz/scripts/estimate_cost.js` | Local cost estimation | Low-risk offline utility; add deterministic unit tests. |
| `security/fizz/scripts/extract_abis.js` | Local Solidity ABI/source extraction | Local file parser; add malformed-input and path-boundary tests. |
| `security/fizz/scripts/fizz_sync.js` | Local metadata/handler synchronization | **Review required:** builds a shell command string from paths/options and calls `execSync`; replace with argument-array process invocation and validate paths before release. |
| `security/fizz/scripts/generate_handlers.js` | Local generated Solidity handler files | File-writing generator; constrain output paths to project root, prevent unintended overwrite, and test atomic writes. |
| `security/fizz/scripts/generate_suite.js` | Local test-suite generation | File-writing generator; validate output roots and generated code determinism. |
| `security/fizz/scripts/lib/log-viewer.js` | Local log-viewer server/client helper | Review bind address, authentication, path traversal, and exposure of sensitive logs. |
| `security/fizz/scripts/run_echidna.js` | Starts local Echidna process | Explicit local fuzzing tool; require user-selected project, bounded duration/resources, safe subprocess argument arrays, and no implicit remote target. |
| `security/fizz/scripts/run_medusa.js` | Starts local Medusa process | Same local fuzzing controls; validate project directory and process termination behavior. |
| `security/fizz/scripts/select_functions.js` | Local selection UI and helper process/browser launch | Review local server binding, browser-launch argument handling, and write endpoint access control. |
| `security/fizz/scripts/setup_fuzz_profile.sh` | Local fuzz-profile setup | Review shell quoting, filesystem writes, and idempotency before automated use. |
| `security/fizz/scripts/test_generate_handlers.js` | Test harness that invokes generator through Node | Test-only executable; isolate temporary directories and verify cleanup/containment. |
| `security/github-topic-crawl/scripts/verify_clones.py` | Local Git clone verification | Subprocess-based local Git helper; constrain repository paths and subprocess arguments. |
| `security/offensive-osint/scripts/dashboard.py` | Local OSINT dashboard and HTTP API | Defaults to loopback but can bind externally; API exposes filesystem scanning and subprocess-backed queries. Do not expose beyond loopback without authentication, CSRF protections, path restrictions, and explicit deployment review. |
| `security/offensive-osint/scripts/h1_reference.py` | Public HackerOne GraphQL disclosure lookup | External read-only research calls; enforce bounded pages, timeouts, response-size limits, and public-data-only handling. |
| `security/offensive-osint/scripts/secret_scan.py` | Offline local secret-pattern scanner | Keep as local-only defensive utility; redact matches by default and avoid copying secrets into reports/logs. |
| `security/security-toolkit-audit/scripts/reconcile_flags.py` | Local subprocess-based tool flag reconciliation | Restrict executable names/paths and use argument arrays; no shell interpolation. |
| `security/subsystem-audit-discipline/scripts/argv_split_probe.sh` | Shell argument-splitting test probe | Lab/test-only; do not point at production data or run unreviewed input as shell code. |
| `security/web2-recon/scripts/probe-host.sh` | Host probing helper | Active network operation; require scope manifest and gateway before APEX integration. |
| `security/web2-recon/scripts/subs-brute.py` | Concurrent DNS/subdomain enumeration | Active network operation with concurrency; require scope allowlist, rate/request budget, DNS controls, and cancellation. |
| `security/x-ray/scripts/analyze_git_security.py` | Local Git repository security analysis | Local repository inspection; constrain subprocess execution to Git and selected repository path; test hostile repository metadata. |
| `security/x-ray/scripts/enumerate.sh` | Recon enumeration orchestration | Active external discovery; not available to APEX autonomous execution until scope-aware gateway integration. |
| `security/x-ray/scripts/generate_svg.py` | Local SVG/report generation | Local file parser/writer; validate input schema and output path, escape all generated SVG text/attributes. |

## Cross-cutting findings to carry forward

- Active network tools must not call targets directly when orchestrated by APEX; all requests must pass through the central scope gateway.
- Local subprocess tools must use argument arrays, explicit executable allowlists, timeouts, bounded output, and controlled working directories. Avoid shell command concatenation.
- Local dashboards must bind to loopback by default and require authentication/CSRF protection before any non-loopback deployment.
- File generators and scanners must constrain input/output paths and avoid overwriting unrelated files.
- Sensitive data workflows need consent, data minimization, redaction, and clear external data-sharing disclosures.
- Third-party services (HIBP, HackerOne, webhook.site, DNS-over-HTTPS) require explicit data-flow documentation and mockable transports.
- CI must be network-disabled for unit tests and use temporary directories; integration tests that call external services must be opt-in and never run on pull requests by default.

## Important limitations

- The table is a preliminary classification, not a complete line-by-line security review of every script.
- Some files were inspected by targeted excerpts and static pattern searches. Full manual review is still required for path handling, argument parsing, error handling, data retention, and edge cases.
- No dependency lockfiles or root-level Python/Node dependency manifest were identified in the repository tree snapshot. Transitive dependency provenance and reproducible installation remain unresolved.
- No tests were executed in this review.
- The existing 1,001-skill corpus has not been changed.

## Phase 0 remaining work

1. Complete manual review of each executable script and its skill-level invocation instructions.
2. Inventory dependency sources, versions, licenses, hashes, and install scripts.
3. Run baseline validator and unit tests in a controlled, network-disabled checkout.
4. Record baseline outputs and test failures without changing existing knowledge files.
5. Freeze the capability allowlist and APEX execution boundary.
