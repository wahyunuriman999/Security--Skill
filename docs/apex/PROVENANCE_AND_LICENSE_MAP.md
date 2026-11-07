# APEX — Provenance and License Review

**Status:** OPEN — preliminary inventory only.

## Repository-level status

| Source | Root license file | GitHub license metadata | Decision |
|---|---|---|---|
| wahyunuriman999/Security--Skill | Not present in root tree | None | Preserve file-level upstream notices; do not infer blanket license |
| Gabson0x/bountyforge | Not present in root tree | None | Do not copy source implementation without explicit permission or a verified license |

## Exact blob overlap

The main-branch trees contain 392 exact Git blob SHA matches. Matching content groups:

| Group | Exact shared blobs |
|---|---:|
| smart-contract-audit | 312 |
| Fizz | 50 |
| Solidity auditor | 18 |
| X-Ray | 7 |
| HackenProof triage | 4 |
| Bug bounty knowledge | 1 |
| **Total** | **392** |

An identical Git blob proves byte-identical content, not ownership, authorship, license compatibility, or redistribution rights.

## Required provenance record

Every imported or retained upstream component must record:

- Component identifier and repository path.
- Original upstream repository and immutable commit/tag.
- Original author/maintainer where known.
- Exact license text and SPDX identifier, or `NOASSERTION`.
- Whether modifications were made.
- Required attribution and notice files.
- Dependency and transitive-license obligations.
- Review decision: retain, reference-only, rewrite independently, quarantine, or remove.

## Integration policy

1. Never assume a repository-level license applies when none is declared.
2. Never strip copyright headers, notices, or original attribution.
3. Preserve subtree license files when retaining those components.
4. Do not copy BountyForge source code solely because both repositories contain similar concepts.
5. Prefer independently authored interfaces and architecture informed by public methodology, with attribution where appropriate.
6. Quarantine components whose provenance is unknown until reviewed.
7. Treat the existing Security--Skill README license summary as a lead for investigation, not a substitute for a per-file license audit.

## Immediate review targets

- `security/fizz/` and matching `skills/fizz/`
- `security/smart-contract-audit/` and matching BountyForge subtree
- `security/solidity-auditor/` and `skills/pashov/solidity-auditor/`
- `security/x-ray/` and matching Pashov subtree
- `security/hackenproof-triage-marketplace/`
- `security/bug-bounty/knowledge.md`

**No upstream implementation code is approved for bulk import by this document.**
