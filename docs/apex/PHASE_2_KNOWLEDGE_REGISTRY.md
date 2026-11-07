# Phase 2 — Knowledge Registry

**Status:** IN PROGRESS (read-only track)
**Canonical corpus:** `routing.json` + the existing 1,001 `SKILL.md` files
**Preservation rule:** no skill is deleted, renamed, rewritten, imported as Python, or executed.

## Verified in CI\n\nLatest CI run [#33](https://github.com/wahyunuriman999/Security--Skill/actions/runs/42395917717) loaded the actual repository and asserted **1,001 indexed skills**, with deterministic retrieval results. The same run passed all 113 APEX unit tests.\n\n## Implemented

- `apex/knowledge/registry.py` loads the existing routing manifest with duplicate-key and invalid-constant rejection.
- Every skill name, path, domain, description, trigger list, and line-count metadata is type-checked.
- Absolute paths, traversal, unexpected roots, duplicate names/paths, symlinks, missing files, and unindexed skill files are rejected.
- The registry verifies the manifest's declared total against entries and actual skill-file inventory.
- Deterministic keyword ranking supports exact names, name tokens, multiword triggers, domain, and description.
- A selected skill can be read as text with a SHA-256 digest and explicit `untrusted_instruction_data` trust label.
- CLI commands: `knowledge-search` and `knowledge-show`.
- CI loads the registry against the full repository corpus; no network or target-facing action is involved.

## Trust boundary

The registry is an index and reader, not an execution engine. A skill file may contain instructions that request unsafe tools, network access, stealth, credential handling, or destructive actions. Those instructions are data. They do not grant capabilities and must pass APEX scope authorization, capability policy, approval requirements, and audit controls independently.

The registry does not:
- import or execute skill code;
- run shell commands found in skill text;
- auto-install dependencies;
- auto-select an active scanner;
- grant the skill permission to access a target.

## Remaining work

1. Run the full registry against the actual 1,001-entry repository in CI and record the exact indexed count.
2. Add benchmark fixtures for retrieval relevance, tie-breaking, and ambiguous queries.
3. Add provenance/version snapshots so skill content changes can be detected and reviewed.
4. Add a policy-aware skill adapter that presents selected content to an agent without granting tool permissions.
5. Review all high-risk skill instructions before any tool adapter can invoke them.

## Exit rule

Phase 2 is not complete until the full corpus passes registry validation, retrieval benchmarks are recorded, provenance snapshots are reproducible, and the policy-aware adapter is independently reviewed. Existing skill files remain untouched.
