# APEX Bug Bounty Intelligence — Architecture Blueprint

**Status:** Proposed architecture for review; not yet implemented.

## Design goals

- Agent-agnostic core with thin runtime adapters.
- Preserve the existing 1,001-skill knowledge corpus.
- Load only the knowledge needed for the current task.
- Make scope, authorization, evidence, and state explicit.
- Support sequential execution when an agent cannot spawn subagents.
- Support parallel specialists when the runtime safely supports them.
- Make every conclusion traceable to evidence and reproducible tests.

## Logical layers

| Layer | Component | Contract |
|---|---|---|
| L0 | Runtime adapters | Translate platform-specific inputs/outputs into canonical events |
| L1 | Core orchestrator | State machine, scheduling, delegation, cancellation |
| L2 | Knowledge registry | Skill manifest, taxonomy, provenance, retrieval |
| L3 | Engagement intelligence | Program policy, scope manifest, asset inventory, technology map |
| L4 | Trust and attack-surface model | Actors, objects, permissions, data flows, trust boundaries |
| L5 | Hypothesis engine | Falsifiable hypotheses with prerequisites and confidence |
| L6 | Research planner | Select next safe experiment by expected information gain |
| L7 | Execution gateway | Allowlisted tools, request budgets, rate limits, human approval |
| L8 | Observation and evidence | Candidate/control observations, provenance, redaction, reproducibility |
| L9 | Lead and finding ledger | Persistent state transitions, deduplication, chain relationships |
| L10 | Adversarial validation | Independent refutation, scope/policy checks, demonstrated-vs-inferred |
| L11 | Severity and reporting | Impact assessment, CVSS mapping, platform-specific report generation |
| L12 | Audit and learning | Append-only activity log, regression fixtures, benchmark outcomes |

## Canonical data objects

### Engagement
- engagement_id
- program_name
- policy_source
- policy_snapshot_hash
- authorized_assets
- excluded_assets
- allowed_methods
- prohibited_methods
- rate_limits
- testing_window
- approval_record
- expiration

### Asset
- asset_id
- canonical_identifier
- asset_type
- scope_status
- ownership_evidence
- discovered_from
- confidence

### Hypothesis
- hypothesis_id
- asset_id
- vulnerability_class
- trust_boundary
- expected_control
- suspected_failure
- prerequisites
- test_plan
- falsification_plan
- status

### Observation
- observation_id
- hypothesis_id
- candidate_request
- control_request
- response_metadata
- body_hash
- timestamp
- tool_version
- redaction_status
- evidence_reference

### Lead / Finding
- record_id
- status
- trigger_verdict
- impact_verdict
- prerequisites
- evidence_ids
- chain_edges
- confidence
- severity
- refutation_record
- transition_history

## State model

`IDEA → LEAD → TESTABLE → OBSERVED → VALIDATING → CONFIRMED`

Alternative transitions:
- `PARKED`: unresolved under current prerequisites; may be reconsidered if new evidence appears.
- `REFUTED`: a specific hypothesis is disproven with evidence.
- `DUPLICATE`: same root cause as an existing finding.
- `OUT_OF_SCOPE`: excluded by engagement policy.
- `REJECTED`: fails validation or has no demonstrated security impact.

A lead must not become a confirmed finding solely because an agent asserts it. A finding must not be killed solely because an agent cannot currently reproduce it; distinguish refuted from unresolved.

## Agent-agnostic compatibility

Canonical core files must not require a proprietary subagent API. Runtime adapters may map:
- skill discovery and invocation,
- task delegation,
- tool permissions,
- structured outputs,
- cancellation and timeout,
- memory persistence.

If parallel agents are unavailable, the orchestrator executes the same specialist tasks sequentially. Capability detection must be explicit rather than inferred from a model name.

## Safety and authorization boundary

- Passive analysis is the default.
- Active testing requires a validated engagement manifest and explicit authorization.
- Requests must be restricted to exact allowlisted assets and approved methods.
- Enforce concurrency, request-rate, time, and data-volume budgets.
- Stop on scope ambiguity, unexpected third-party redirection, service instability, or policy conflict.
- Use minimal proof and controlled test accounts; do not collect real-user data beyond the minimum needed.
- Do not enable stealth, anti-forensics, credential theft, persistence, destructive actions, uncontrolled flooding, or bulk data exfiltration.
- OOB validation must use a controlled callback endpoint and minimal non-sensitive canary data.
- Human approval is required for high-impact or state-changing tests.

## Knowledge retrieval

1. Parse user task and engagement context.
2. Resolve domain and subdomain.
3. Retrieve a small candidate set from `routing.json`.
4. Rank by specificity, evidence quality, freshness, and scope compatibility.
5. Load the best skill plus only its referenced dependencies.
6. If confidence is low or candidates conflict, ask for clarification or run a passive classification step.
7. Record which skill/version influenced each hypothesis.

## Non-goals

- Guaranteeing Critical findings or bounty acceptance.
- Maximizing payload count or scan volume.
- Running tools against arbitrary URLs without scope verification.
- Treating model-generated narratives as evidence.
