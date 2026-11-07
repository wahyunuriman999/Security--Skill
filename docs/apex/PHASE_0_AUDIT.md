# APEX Bug Bounty Intelligence — Phase 0 Audit Checkpoint

**Status:** IN PROGRESS — source inventory and preliminary code review completed; full verification is not yet complete.  
**Audit date:** 2026-11-07  
**Primary repository:** `wahyunuriman999/Security--Skill`  
**Reference repository:** `Gabson0x/bountyforge`  
**Primary branch baseline:** `main`

## 1. Decisions

- Keep Security--Skill as the canonical repository and project identity.
- Maintain vendor/agent-agnostic architecture.
- Cover Web/API, Web3, mobile, cloud, enterprise/AD, AI/LLM, network, forensics, detection, and other existing domains.
- Integrate selectively; do not bulk-copy or replace existing knowledge.
- Keep the current `main` branch unchanged during Phase 0. Work on `apex/phase-0-audit-2026-11-07`.
- No active testing against third-party targets is part of this repository audit.

## 2. Repository snapshots

| Metric | Security--Skill | BountyForge |
|---|---:|---:|
| Default branch | main | main |
| Tree SHA | `9a7f090bcba13bf02cb253dca88b2e4850f32416` | `068399d6309b58d413daeb5b14ac691301302373` |
| Files (blob entries) | 1,482 | 543 |
| Directories (tree entries) | 1,120 | 117 |
| `SKILL.md` files | 1,001 | 29 nested + 1 root entrypoint |
| Root license metadata | None detected | None detected |
| GitHub Actions workflows | None found | None found |
| Test modules | One nested tool test file | 2 top-level test modules |

Repository metadata reported Security--Skill last pushed 2026-10-27 and BountyForge last pushed 2026-09-16. BountyForge metadata was updated 2026-11-04; metadata update time is not equivalent to a source commit.

## 3. Key findings

### APEX-001 — Existing knowledge coverage is substantial
Security--Skill has 1,001 indexed `SKILL.md` files. The repository README divides this into 130 skills under `security/`, 870 under `security-atlas/`, and one atlas roadmap skill. Preserve this corpus as a non-regression requirement.

### APEX-002 — Routing manifest is large and central
`routing.json` is approximately 657 KB and declares 1,001 skills. Its entries include name, path, domain, description, triggers, and line count. The current validator compares the manifest's skill names and total count with discovered skill files, but does not fully validate every manifest path, trigger quality, domain taxonomy, runtime routing decision, or skill execution contract.

### APEX-003 — Root entrypoint and universal contract are missing
The root has README, ROUTER, INDEX, routing.json, and scripts, but no root `SKILL.md`. Add a canonical vendor-neutral entrypoint only after the adapter contract and compatibility tests are designed.

### APEX-004 — 392 identical Git blobs already exist across repositories
The compared main-branch trees contain 392 exact blob-SHA matches:
- smart-contract-audit: 312
- Fizz: 50
- Solidity auditor: 18
- X-Ray: 7
- HackenProof triage: 4
- Bug bounty knowledge: 1

This is evidence of existing overlap, not proof of complete licensing provenance. Avoid duplicate imports and preserve source attribution.

### APEX-005 — Root licensing/provenance is incomplete
Both repository metadata responses report no root license. Security--Skill README describes upstream license families, and BountyForge contains licenses in some subtrees, but these do not establish blanket permission for every file. Do not copy BountyForge implementation code without explicit licensing/permission review.

### APEX-006 — Tooling safety requires a default-deny boundary
Security--Skill includes tools and tradecraft oriented toward flooding, payload mutation for WAF signature evasion, traffic disguise, anti-forensics, and stealth. BountyForge includes OPSEC/fingerprint rotation and infrastructure/callback tooling. These components must not be automatically available to the default bug-bounty workflow. Quarantine for review; retain only safe, scope-bounded, auditable testing behavior.

### APEX-007 — BountyForge has valuable research-state primitives
BountyForge's lead ledger, observation/oracle validation, adversarial refutation, agent isolation, trust mapping, and methodology references are high-value design references. Port the concepts through independently authored interfaces and tests, subject to provenance review.

### APEX-008 — Current test coverage is narrow
BountyForge exposes two top-level test modules for lead-state and observation validation. Security--Skill has a nested tool test module but no top-level test suite or GitHub Actions workflow was found. Neither repository snapshot proves end-to-end quality or agent compatibility.

### APEX-009 — Transport and execution defaults need review
BountyForge's hunt engine builds curl invocations using `-k`, which disables TLS certificate verification. This should not be a default in a trustworthy research engine. The execution path also needs a centralized scope/permission gate, request budget, audit logging, and safe-stop behavior before tools can be orchestrated.

### APEX-010 — Documentation claims must be separated from verified behavior
README/changelog claims, skill instructions, code implementation, and passing tests are different evidence levels. The final audit must classify each claim as documented, implemented, tested, or independently verified.

## 4. Preliminary recommendations

1. Preserve all existing skill files and their paths during the first integration stages.
2. Add a root universal entrypoint and stable machine-readable contracts.
3. Replace keyword-only routing as the sole decision mechanism with domain classification, confidence, ambiguity handling, and explicit fallback.
4. Introduce typed scope manifests and execution permissions before active tool use.
5. Adopt a persistent lead/finding state model, observation records, evidence provenance, and independent refutation.
6. Add deterministic unit tests, fixture-based integration tests, compatibility tests, and benchmark tasks.
7. Keep high-risk evasion, flooding, stealth, exfiltration, persistence, and anti-forensics out of the default workflow.
8. Complete file-level license/provenance review before moving upstream material.

## 5. Verification limitations

This checkpoint is based on GitHub tree/blob retrieval and static source inspection. Code has not been executed in a local checkout; the existing validator and test suites have not been run. No claim of passing tests is made. Phase 0 remains open until the remaining scripts, skill metadata, provenance, and benchmark baseline are verified.

## 6. Phase 0 exit criteria

- Complete file and component inventory.
- Per-source provenance and license decision.
- Full static review of executable tooling and dependencies.
- Run existing validation and test commands in a controlled checkout.
- Identify broken links, stale references, invalid frontmatter, and manifest drift.
- Freeze architecture, contracts, safety model, and migration plan.
- Obtain a reviewed Phase 0 completion report before implementation begins.


## 7. Focused static code review addendum (2026-11-07)

### APEX-010 — TLS verification disabled in BountyForge HTTP execution
**Evidence:** `tools/hunt.py`, lines 132 and 176, builds curl commands with `-sk`. The `-k` option disables certificate verification in both ordinary and observation request paths.
**Risk:** TLS peer identity is not verified; observation and evidence integrity can be undermined.
**Required remediation:** verified TLS by default; explicit CA bundle support; no insecure flag in normal mode.
**Disposition:** release blocker.

### APEX-011 — No mandatory pre-request scope gate demonstrated
**Evidence:** `tools/hunt.py`, lines 793-880, accepts a target, loads recon hosts, and executes quick checks, IDOR checks, and optional active injection. This entrypoint does not visibly require a validated engagement manifest or centralized authorization before requests.
**Related evidence:** `tools/agent_isolation.py`, lines 294-327, checks scope on finding records after they exist. Its explicit scope check uses substring membership (`d in str(endpoint)`) rather than canonical hostname boundary matching.
**Risk:** post-hoc review is not equivalent to preventing an unauthorized request. Substring matching can misclassify hosts.
**Required remediation:** enforce authorization before every outbound request and redirect; canonicalize IDNA hostnames, ports, schemes, and IP literals; apply explicit allow/deny rules. Missing, malformed, expired, or ambiguous scope must fail closed.
**Disposition:** release blocker.

### APEX-012 — Agent isolation is not a complete runtime sandbox
**Evidence:** `tools/agent_isolation.py`, lines 212-228 and 294-371, loads scope data and evaluates finding records, HTTP methods, payload fields, and agent permission metadata.
**Risk:** checking a report object after execution cannot stop an agent or subprocess from issuing a prohibited network request. Permission labels do not provide OS/network isolation.
**Required remediation:** separate policy decision, request authorization, and runtime sandboxing. Every outbound request must pass through a controlled gateway; tool processes need least privilege and bounded filesystem/network capabilities.
**Disposition:** release blocker for autonomous active testing.

### APEX-013 — Evasion-oriented OPSEC is coupled to the normal hunt path
**Evidence:** `tools/hunt.py`, lines 814-817 initializes `OpsecRotator` unless `--no-opsec` is supplied. `tools/opsec.py`, lines 121-210, 215-256, and 279-293 implements User-Agent/header rotation, timing jitter, Tor proxy support, and TLS fingerprint variation.
**Risk:** these features can obscure test attribution and conflict with program rules or coordinated disclosure requirements.
**Required remediation:** exclude these capabilities from APEX's default workflow. Prefer stable identification, explicit request budgets, policy-compliant backoff, and transparent source attribution.
**Disposition:** excluded from default APEX workflow.

### APEX-014 — Existing Security--Skill validator is useful but incomplete
**Evidence:** `scripts/validate.py`, lines 20-66 checks frontmatter fields, duplicate names, directory-name agreement, relative Markdown links, routing names, and total count.
**Coverage gaps:** it does not verify every manifest path exists and points to the expected file; validate trigger quality or domain taxonomy; parse frontmatter with a YAML parser; validate non-Markdown assets; or test routing decisions against fixtures.
**Required remediation:** retain this validator as a baseline, then add deterministic checks for manifest path equality, frontmatter schema, reference graph, taxonomy, routing fixtures, and generated-index reproducibility.
**Disposition:** Phase 1 prerequisite.

### APEX-015 — Test and CI evidence is limited
**Evidence:** BountyForge has `tests/test_leads.py` and `tests/test_observation.py`; Security--Skill has `tools/tests/test_rat_tools.py`. No root-level CI workflow was found in either repository. BountyForge contains a nested Pashov version-bump workflow at `skills/pashov/.github/workflows/version-bump.yml`, not repository-wide validation.
**Risk:** visible automated tests do not cover the full execution pipeline, scope authorization, tool safety, agent compatibility, or end-to-end workflows.
**Required remediation:** root-level CI with isolated temporary state, deterministic unit/integration fixtures, static analysis, dependency checks, and explicit no-network defaults. Never run live-target tests in CI.
**Disposition:** Phase 1 prerequisite.

## 8. Audit corrections and precision notes

- Exact blob files: 1,482 for Security--Skill and 543 for BountyForge. Recursive tree entries: 2,602 and 660 respectively (blobs plus directory entries).
- Skill entrypoints: 1,001 for Security--Skill and 30 for BountyForge (one root `SKILL.md` plus 29 nested skill files).
- Neither repository has a root license file or GitHub root license metadata. BountyForge has nested license files at `skills/pashov/LICENSE` and `skills/web3/LICENSE`; these do not license the whole repository.
- Neither repository has a root-level `.github/workflows/` CI workflow. BountyForge does contain a nested Pashov version-bump workflow.
- The 392 exact blob matches are byte-identical content, not proof of license compatibility or permission to redistribute.
- Static review is not runtime verification. No test pass is claimed.

## 9. Current Phase 0 decision

**Phase 0 remains OPEN.** APEX-010, APEX-011, and APEX-012 are release blockers for any autonomous active-testing release. No Phase 1 implementation is authorized by this audit addendum.


## 10. Executable tool safety review addendum

A separate file-level static review of all nine files under `tools/` is recorded in [EXECUTABLE_TOOL_SAFETY_REVIEW.md](EXECUTABLE_TOOL_SAFETY_REVIEW.md).

Key finding: the existing tool directory is not a safe default execution surface. It contains C2 polling, shell execution, file read/write, persistence checks, WAF/SIEM flooding, payload mutation, traffic disguise, and WAF bypass selection. These tools are not to be registered as APEX agent capabilities by default. The review does not delete or modify them.

The repository tree also contains executable Python, JavaScript, and shell files under `security/`. Their static review, dependency provenance, and isolated test execution remain outstanding. Therefore this addendum does not close Phase 0 and does not authorize Phase 1.


## 11. Executable script inventory addendum

A preliminary inventory of Python, JavaScript, and shell scripts under `security/` is recorded in [EXECUTABLE_SCRIPT_INVENTORY.md](EXECUTABLE_SCRIPT_INVENTORY.md). The inventory identifies active network tools, local subprocess wrappers, file generators, local dashboards, sensitive-data workflows, and third-party service integrations.

A concrete review item is `security/fizz/scripts/fizz_sync.js`: it constructs a shell command string from path/options and invokes `execSync`. This requires conversion to an argument-array process invocation plus path validation before automated use. The local OSINT dashboard also warns that non-loopback binding exposes filesystem scanning/query APIs; loopback-only must remain the default and non-loopback deployment requires authentication and request protections.

The inventory is preliminary, not a complete line-by-line audit. No tests or scripts have been executed. Dependency provenance and reproducible install manifests remain unresolved. Phase 0 remains OPEN.
