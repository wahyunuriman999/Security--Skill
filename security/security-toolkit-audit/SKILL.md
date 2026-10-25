---
name: security-toolkit-audit
description: Verify and repair a security skill's tools and runbook.
version: 0.1.0
author: serigalamalem + user, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, tooling, skill-maintenance, verification, tradecraft]
    related_skills: [hermes-agent-skill-authoring, engagement-learning-loop]
---

# Security Toolkit Audit

A security skill that ships executable tools plus a markdown runbook has two
independent failure modes: the runbook documents flags the tool never
implemented, and the tool's ranking/heuristic logic degrades into decorative
output. This skill is the procedure for finding and fixing both, written for the
case where a large bundle (100+ skills) was installed or patched and nobody ran
the individual tools.

## When to Use

- A skill bundle was unpacked, synced, or patched and you must prove it works
- A runbook's commands fail with `unrecognized arguments`
- Someone asks "does this skill actually run?" or "assess the quality of this skill"
- A shipped tool phones home, opens sockets, or writes files when run with no arguments
- A tool's score/rank/metric returns the same value for every input

Don't use for: hunting with the skill on a live target (use the hunt-* skills),
or writing brand-new toolkit content from scratch (that is plain implementation).

## Procedure

### 1. Inventory the tool surface

List every script in the bundle with `search_files(pattern='*.py', target='files', path='<skill tools dir>')` —
nothing gets skipped by eyeball.

Parse-check all of them in one pass. Packaging and copy steps routinely
introduce syntax errors, and a tool that cannot be imported is defect #1
regardless of how good its docstring is.

### 2. Extract the real CLI surface

Read `add_argument` calls out of the AST of every script rather than executing
them. You want the declared surface, and you want to notice scripts that
declare none — library-only tools must be documented as such, not as CLIs.

### 3. Reconcile the runbook against the real surface

Run `scripts/reconcile_flags.py <tools-dir> <runbook.md>...` (this skill's
helper). It joins continuation lines in the docs, extracts every `--flag` used
in `python <tool>.py` invocations, and prints the flags that do not exist. Each
hit is doc drift; before fixing, decide direction:

- **Flag is meaningful and cheap** → add it to the tool, keeping existing flags
  and legacy subcommands working (append to the parser, do not restructure).
- **Flag describes behaviour that does not exist and should not** → remove it
  from the doc and leave a one-line note saying which capability replaced it.

Never edit the doc to silently delete a capability. A future session reading a
runbook that quietly lost a step has no way to know it was ever there.

### 4. Gate every network-capable tool

A tool that fetches, beacons, or dials on invocation without a gate is a
hazard. For each network path: add an explicit gate (`--live`, `--c2`, or an
env var), keep the no-argument and no-gate invocations hermetic (zero sockets,
zero writes outside `--output`), and verify by running them. A tool that prints
a resolved IP but sends no packet is the correct default posture.

### 5. Check for degenerate output

Run each tool once on a representative input. If every ranked item gets the
same score, or every item passes, the metric is decoration. A useful evasion or
similarity score is weighted by whether the transformation survives decoding
back to its original meaning (percent-encoding, unicode escapes, entity
encoding, comment/keyword splitting) and penalises blind length inflation.

Give every detector a **negative control**: a fixture that must produce zero
findings — a routine `200` on a public route, a small benign body, a fully
consistent method matrix. Without one, a detector that flags every input looks
exactly as healthy as a detector that flags nothing, and the self-test cannot
tell the two apart.

A status-code difference is an OBSERVATION, not a finding. A differential detector
must not emit on the raw observation; it emits when the observation is
*actionable* — a body-serving method contradicted by a refused sibling on the
same path, or a body carrying a sensitive marker. Without that filter the first
run against a real target produces a wall of entries for every route that simply
works, and the signal is buried in noise a maintainer reads as a defect list.
Encode the filter in the analysis path, not in the printing path, so the JSON
verdict is as quiet as the console output.

**Fixture shapes carry two forms, and the analyzer must normalize them.** Hermetic
fixtures are often written as compact `{method: (status, bytes)}` tuples while
the live path produces `{"status": n, "bytes": n}` dicts, because the network
path also has to hold `body` and `headers` for the analysis steps to read. A
normalizer at the entry of the analysis function accepts either shape and emits
the dict form, so the self-test and the live run share one code path instead of
two subtly different ones. Where the tuple form has no body bytes, let the
fixture declare a `hermetic_bytes` map so the body-sensitive checks still see a
plausible length instead of silently reporting nothing.

Match the marker list to the transform applied to the input. A marker written
in camelCase can never match a body that was lowercased first: the defect is
invisible on review, and the self-test only passes because a *different* marker
happens to hit. Normalize the constant once, not at each call site, and have
the self-test assert the constant's members rather than one lucky substring.

Write file handles through a context manager (`with open(...)`) and run the
suite with warnings promoted (`-W error::ResourceWarning`) so an unclosed
handle fails the run instead of passing quietly.

### 6. Verify the worked examples with the tool itself

Recompute every arithmetic example in the runbook by feeding the same inputs to
the tool, and match the tool's actual rounding (truncation vs rounding) —
annotate the doc where they differ and state that the tool is the authority.
Correct the score tables where the prose breakdown does not sum to the stated
total, not the other way round.

### 7. Report verified state, not intent

End with what was actually executed: files parse-checked, `--help` runs,
dry-run exits, example recomputation, and the final count of unresolved flag
drift (target: zero). A claim that a bundle "passes" without per-tool evidence
is not a verdict.

## Pitfalls

- **Use `patch` on existing supporting files rather than `write_file`
  overwrites** — the overwrite is refused by the read-before-write guard, and a
  full-file write also discards fixes you cannot see from a paginated read.
- **Use literal native paths (`C:/...`) when invoking Windows-native Python** —
  MSYS `$HOME` and `/tmp` are shell-only; the interpreter raises on them and the
  failure looks like a tool bug rather than a path bug.
- **Do not treat a bundled test suite as proof** — a green run proves the
  test's fixture, not that each tool's CLI works. Smoke every tool's `--help`
  and one dry run from the deployed copy, not from the source snapshot.
- **Re-verify claimed fixes in the target tree before reporting them** — a
  changelog or fix-list entry is a statement of intent; open the file and
  confirm the change is present.
- **Keep legacy invocation paths working** — the runbook is not the only
  consumer; new orchestrator flags must not delete flags and subcommands other
  users already depend on.
- **Do not run network smoke tests against a real target to "prove" a tool
  works** — use a hermetic invocation or a host the operator has written
  authorization for; the gate in step 4 is verified without leaving the box.
- **A SKILL.md written without its `---` frontmatter delimiters still loads,
  and fails silently** — the registry publishes the literal `name:` line as the
  skill's description instead of the capability sentence, so the skill looks
  present and correctly listed while being untriggerable by its description.
  After adding a skill, read back the entry through the skill loader and confirm
  the description is the capability sentence before calling the bundle done.

## Verification

- `reconcile_flags.py` reports zero unknown flags across every runbook in the skill
- Every script parses, and every script with a CLI answers `--help`
- No-argument and no-gate invocations are hermetic
- Every detector has a negative control that produces zero findings
- The suite passes with `-W error::ResourceWarning`, not just bare
- Each newly added skill appears in the master index's category list with the
  skill count updated, and the loader reports its description as prose rather
  than a literal `name:` line
- Worked examples in the docs match the tool's output, or are annotated where rounding differs
