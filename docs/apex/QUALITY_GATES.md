# APEX — Quality Gates

**Status:** Proposed release criteria.

| Gate | Area | Pass criteria |
|---|---|---|
| QG-00 | Repository baseline | Snapshot SHAs, inventory, and baseline test results recorded |
| QG-01 | Provenance | Every retained upstream component has a source and license decision |
| QG-02 | Knowledge integrity | Existing skill paths and content preserved unless a reviewed migration says otherwise |
| QG-03 | Manifest integrity | Every manifest path exists; names, paths, domains, triggers, and counts reconcile |
| QG-04 | Skill quality | Frontmatter schema, links, references, instructions, and output contracts validate |
| QG-05 | Scope safety | Active tools require a valid engagement manifest and exact allowlist |
| QG-06 | Execution safety | No unsafe default flags, unbounded concurrency, destructive behavior, or secret leakage |
| QG-07 | Evidence quality | Observations preserve candidate/control context, provenance, redaction, and replay instructions |
| QG-08 | Finding state | State transitions are deterministic, persisted, auditable, and regression-tested |
| QG-09 | Adversarial validation | Independent refutation distinguishes demonstrated, inferred, unproven, and refuted claims |
| QG-10 | Severity | Severity is grounded in demonstrated impact and the program's policy |
| QG-11 | Agent compatibility | Same fixture tasks work sequentially and through supported runtime adapters |
| QG-12 | Domain coverage | Representative benchmark cases exist for every supported domain pack |
| QG-13 | Regression | Existing validator, tests, and baseline fixtures pass after every change |
| QG-14 | Efficiency | Token, tool-call, latency, and request budgets are measured and bounded |
| QG-15 | Release | Documentation, attribution, migration notes, rollback path, and changelog are complete |

## Required benchmark categories

- Positive cases: known, reproducible vulnerabilities in intentionally vulnerable labs.
- Negative cases: benign behavior that resembles a vulnerability.
- Ambiguous cases: missing prerequisites, inconsistent responses, or incomplete impact evidence.
- Scope cases: in-scope, out-of-scope, wildcard ambiguity, redirect to third party, expired authorization.
- Chain cases: two independent primitives where only a fully demonstrated chain can be promoted.
- Regression cases: previously fixed false positives and previously confirmed findings.
- Compatibility cases: sequential execution and each supported agent adapter.

## Scoring dimensions

Report separately:
- routing precision and recall,
- hypothesis relevance,
- evidence completeness,
- reproduction success,
- false-positive rate,
- false-negative rate on benchmark fixtures,
- severity calibration,
- scope-policy compliance,
- duplicate detection,
- token/tool cost and time.

Do not combine these into a single opaque "AI accuracy" score. Publish sample size and confidence intervals where meaningful.

## Release blockers

Any scope violation, secret leakage, unbounded destructive request, unsupported license import, fabricated evidence, or untraceable confirmed finding blocks release.
