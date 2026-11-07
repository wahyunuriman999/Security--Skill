# APEX Executable Tool Safety Review

**Status:** Partial static review — not a runtime verification.
**Branch:** `apex/phase-0-audit-2026-11-07`
**Review date:** 2026-11-07
**Scope:** All nine files under `tools/` at the reviewed branch snapshot.

## Executive decision

The existing `tools/` directory is not a safe default execution surface for an autonomous bug-bounty agent. Several tools implement command-and-control, remote command execution, file access, persistence checks, service exhaustion, payload mutation, traffic disguise, or bypass selection. APEX must not automatically expose these tools to its planner or agent adapters.

This review does **not** delete or modify existing tools. The immediate disposition is quarantine-by-policy: do not register them as APEX capabilities, do not invoke them from automated workflows, and do not treat a README warning as an execution control. Any future reintroduction requires a separate threat model, explicit authorization, isolated lab-only execution where applicable, and independent review.

## File-level disposition

| File | Static evidence observed | APEX disposition |
|---|---|---|
| `hiv_beacon.py` | C2 polling over HTTP/DNS, User-Agent disguise, TLS certificate verification disabled, shell execution, file read/write, port scanning, persistence checks, task execution | **Prohibited from APEX runtime.** Retain only as historical source pending owner decision; do not execute or adapt into an agent capability. |
| `hiv_cd4_flood.py` | Explicit WAF/SIEM alert flooding, threshold gaming, noise mixing, rotating User-Agent and forged X-Forwarded-For values, concurrent request workers | **Prohibited.** Service-exhaustion and alert-fatigue behavior is incompatible with safe bug-bounty validation. |
| `hiv_mutator.py` | Repeated XSS/SQLi/SSRF payload mutation and network submission; User-Agent rotation | **Excluded from default runtime.** Replace only with bounded, deterministic, policy-approved test cases and a mandatory request gateway if needed. |
| `hiv_score.py` | Scoring workflow recommends flood and mutator campaigns; writes JSON output | **Needs redesign.** Preserve only neutral, evidence-based prioritization concepts; remove recommendations for flooding/evasion from any APEX-facing output. |
| `hiv_waf_fp.py` | Bypass selector includes IP reputation rotation, browser fingerprint mimicry, request smuggling, slow-drip and parser-confusion techniques | **Excluded from automated execution.** A defensive WAF identification checklist may be independently authored without bypass automation or unsupported success-rate claims. |
| `rat_digest.py` | Local HTTP Digest parsing/hash computation and offline verification against supplied password candidates | **Conditional utility.** Keep only as an offline parser/test helper after provenance review, input bounds, and tests; never use for credential acquisition or online guessing. |
| `rat_ghost.py` | Browser impersonation headers, human timing, cookie/referer tracking, payload mutation, calls HTTP/3 client | **Excluded from default runtime.** Traffic disguise and filter-bypass behavior must not be an APEX capability. |
| `rat_h3.py` | Direct HTTP/3/QUIC requests, DNS-over-HTTPS edge discovery, retries, concurrent streams, raw request/response capture; no engagement-scope gateway is visible in the inspected path | **Not safe for direct agent exposure.** May be reconsidered only behind a mandatory authorization gateway, fixed request budgets, redirect controls, and deterministic tests. |
| `rat_oob.py` | Generates, sends, polls, and waits for external webhook callbacks; uses a third-party callback service and environment token | **Conditional integration.** Require explicit engagement authorization, user-controlled callback tenant/token, secret redaction, bounded polling, and a mocked test mode. |

## Cross-cutting findings

1. **No demonstrated central pre-request authorization.** The inspected network-capable tools do not share a mandatory engagement manifest and request gateway.
2. **TLS posture is inconsistent.** `hiv_beacon.py` explicitly sets `CERT_NONE` and disables hostname verification. APEX must require certificate verification.
3. **No capability isolation contract.** Shell, filesystem, network, and persistence capabilities must not be granted by descriptive agent metadata alone.
4. **No reliable default request budget.** Every active request path needs centrally enforced per-host, per-method, per-engagement limits and a stop mechanism.
5. **Evidence can contain secrets.** Raw headers, cookies, callback metadata, request bodies, and host data require redaction and retention controls.
6. **Tool names and comments are not proof of safety.** Classification is based on inspected implementation paths; this is not a sandbox assessment or execution test.

## Required APEX controls

- Default-deny capability registry. A tool is unavailable unless explicitly registered and approved.
- Engagement manifest validation before any DNS, HTTP, QUIC, callback, or other target-directed request.
- Canonical host matching with IDNA normalization, explicit ports/schemes, IP literal handling, and strict wildcard boundaries.
- Re-check authorization on redirects and every request, not only on final findings.
- A single request gateway that enforces budgets, timeouts, concurrency caps, transparent identification, audit events, and safe stop.
- Separate passive analysis from active testing; active testing requires explicit user confirmation and valid program scope.
- No C2, persistence, remote shell, credential theft, exfiltration, flooding, stealth, anti-forensics, or detection-evasion capability in APEX.
- Secret-safe evidence storage with bounded body sizes, redaction, and configurable retention.
- Network-disabled CI and mock transports for tests.

## Review limitations

- Static source inspection only; no tool was executed.
- This review covers `tools/` only. The repository also contains executable Python, JavaScript, and shell scripts under `security/`; those require a separate file-by-file review before Phase 0 can close.
- Dependencies and license provenance have not been fully verified.
- No claim is made that the existing tool suite is safe, tested, or suitable for production.

## Exit criteria for this review

- [ ] Every executable under `security/` has a static risk classification.
- [ ] Dependency manifests and transitive dependency provenance are inventoried.
- [ ] Existing tests run in an isolated, network-disabled environment.
- [ ] Default APEX capability registry excludes prohibited and unreviewed tools.
- [ ] Request gateway and scope tests prove fail-closed behavior before active execution.
