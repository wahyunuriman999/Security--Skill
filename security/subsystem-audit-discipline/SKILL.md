---
name: subsystem-audit-discipline
description: Use when auditing a subsystem of a repo for bugs.
---

# Subsystem bug-bounty audits

## Read the project's own tests before reporting a finding

A subsystem's test suite states the maintainers' intent in executable form. A
finding that contradicts a passing test is a finding you have misread. Run the
suite first (e.g. `test/shell`, `test/cli`, `test/all`), read the assertions
that encode intent, then decide whether the behaviour you found is a bug or the
feature.

Why: I reported the `cp -r` path in `bin/omarchy-theme-set` as an unfiltered
code-execution bug, CVSS 8.4, quoting a migration comment as proof the
maintainers considered it a half-fixed security hole. The repo's own test
`test/shell.d/theme-staging-test.sh` asserts the opposite intent in plain
language: "A theme the user wrote themselves is not filtered at all." One run
of the suite refuted the whole report.

Rule: before writing a report for any subsystem, find and run its tests. If a
test passes and contradicts your claim, the claim is wrong.

## "File was staged" is not "file was executed"

A PoC that shows a file landing in a directory proves placement, not
execution. Enumerate the consumers and how each resolves the path (exact path,
glob, recursive find, symlink) before claiming code execution. In omarchy every
theme consumer reads an exact top-level path or a `-maxdepth 1 -iname` glob, so
a subdirectory copy of `hyprland.lua` stages but never runs.

Rule: every impact claim needs the consumer chain written out, with the exact
resolution mechanism. If you cannot name the loader, say the file is present
but inert.

## Report the sandbox break, not the inflated version of it

A deny list that a malicious input defeats is a real control failure worth a
medium report even when nothing auto-executes today. The control exists so a
future consumer does not silently turn the file into execution. Saying that
plainly is credible; escalating it to RCE you cannot demonstrate is not, and
the program will close it.

## Migrations are backfill, not admission

A migration that re-stages state to drop previously-staged malicious files is
cleanup for installs made by older versions. It does not describe a live hole
in current code. Read the migration body, not just the comment's first line.

## Same-uid reachability is not a privilege boundary

Search the repo's own security posture docs for its scope carve-out (terms like
"same-user", "same-uid", "trusted", "out of scope") before writing a finding up
as a vulnerability. When the only path to a sink runs as the user with the
user's own privileges — a symlink the user must create, a config file the user
owns, a process the user launched — no boundary has been crossed, and the
report is informational at best.

Why: it is the fastest reliable way to close a lead that otherwise looks like a
privilege escalation. It also separates the two claims bounty programs treat
differently: attacker-*controlled* content (prompt injection, data in an LLM
prompt or a filename) versus attacker-*elevated* privilege. Only the second is
paid.

## Prove who runs the code — never infer EUID from a shebang or a metadata flag

A script carrying `#!/bin/bash -p`, a privileged-startup guard, and a
`requires-sudo=true` metadata line still runs as the **user** when another
script invokes it by path with no `sudo` prefix. Metadata declares intent; the
call site decides identity. Trace the chain to the actual invocation, read the
prefix there, then confirm by dropping a probe (`id -u`, `$HOME`, `$PATH`,
`pwd`) into the entrypoint and running the real caller.

Why: the whole severity of a "root executes user-controlled code" finding rests
on this one prefix, and one missing `sudo` at a call site inverts the verdict.
An inherited `$HOME` under `sudo` does not by itself make the callee root.

## Test shell behaviour with a real harness, not by eyeballing

Two traps that both look like proof and are not:

- To test whether an expansion splits into several argv words, iterate `"$@"`
  inside a function. Looping the **unquoted** string (`for w in $out`) performs
  ution you were trying to detect. Use `scripts/argv_split_probe.sh`.
- `$(<file)` strips **trailing** newlines only, so a leading newline survives
  into the value; and bash `=~` anchors `$` at end-of-string, not end-of-line,
  so a value containing a newline fails an otherwise-matching `^...$` check.
  Verify with the real payloads — leading newline, embedded `;id`, trailing
  junk — not with a clean input.

Why: both traps produce confident wrong answers in opposite directions, and
they are the difference between reporting an injection and reporting a real
single-argv expansion as safe.

### Extracting a shipped function into a harness

A script that builds its state in a top-level `if` cannot be sourced wholesale —
the guard fires and the harness runs the wrong branch, or the script's main
body executes. Locate the function's closing brace with
`grep -n '^}' script`, extract the exact line range
(`sed -n 'START,ENDp' script > harness_funcs.sh`), and `bash -n` it before
sourcing. Two harness traps that both produce silent false negatives:

- The function reads globals it does not declare (`declare -A THEME_COLORS`)
  must be declared **inside the harness**, not inside a later helper, or every
  lookup misses and the probe reports "safe" for an unsafe value.
- A function built on a `REPLY` return idiom prints nothing, so
  `$(the_function ref)` yields an empty string and looks like a validated
  fallback. Call the function, then read `$REPLY` in the **same shell** — and
  when output must be captured to a file, write the file from inside that same
  invocation.

Build the harness file with `write_file`, not an unquoted heredoc: a heredoc
that carries a backtick or `$` expands it before the file exists, and the
script fails with a syntax error that names the wrong line.

## Run the shipped function, not a mock

A PoC that reimplements a parser proves nothing about the parser. Source the
shipped script (or invoke its entrypoint) and call the real function with the
payload. Only the real output distinguishes validation from its absence, and
only it shows the details a paraphrase drops — e.g. a validator built on
`printf '#%02x%02x%02x'` always returns eight characters, so a downstream
`${value#\#}` is guaranteed six lowercase hex and needs no second check.

## Reject your own candidate before submitting it

Before writing the report, write the case AGAINST the finding first: what the
attacker controls, what they reach, what stops it, and the single line that
makes it unpaid. If the honest verdict is informational, report that verdict to
the user and name the two open surfaces instead of submitting a weak report.

Why: a hunt ends in one of two states — a report, or an honest "the remaining
reachable surface is inert or same-uid." The second is a complete answer, and it
is worth more than a submission that consumes the program's goodwill and the
user's reputation. The disqualifiers that recur: the payload is capped too small
to carry instructions, the chain needs a user click, the content is data rather
than executable, the reachable actor is the user themselves.

## Define the recovery path before delegating an audit sweep

Parallel audit subagents are a breadth tool, not a coverage tool: a subagent
that returns nothing has still consumed its context, and its findings survive
only in its live transcript log. Before dispatching, note where each
transcript lands, read those logs directly to recover partial findings, and
re-verify every recovered lead yourself before it counts.

Why: "the subagent found nothing" and "the subagent never answered" look
identical in the result and mean opposite things. Treat an empty delegated
result as unverified, never as a cleared surface.

## Audit the chain end to end: producers, consumers, and PATH under privilege

Do not stop at the sink. Walk upstream to every producer of its input and
downstream to every consumer of its output, and at each privileged hop ask how
*helpers resolve*: a root script that pins `PATH` to system directories closes
the class where a dev checkout's `bin/` shadows `install`, `mktemp` or `rm`.
Mark each producer trusted (root-owned, shipped) or stranger-writable (a cloned
repo, a downloaded artifact) — only the latter can carry an attacker.

Why: an isolated unit test of the validator can pass while the real chain
either closes earlier (the caller strips a prefix before the validator sees it)
or is unreachable (only root-owned files reach it).

## A breakout at the sink proves parsing, not reachability

Proving that a renderer, `eval`, or string-builder turns a payload into
executable syntax proves the sink parses. It does not prove the payload can
arrive. Walk the chain upstream hop by hop and test the payload against the
*nearest* validation, not the sink's behaviour — a charset on the producer's
value, an enum on a config field, a regex on a caller's argument. One validated
hop anywhere in the chain closes the class, no matter how broken the hops
downstream of it are.

Why: a template renderer that emits arbitrary Lua tokens
(`"#ff0000"});os.execute("id");t={"` — a genuine breakout, demonstrated on the
shipped function) is closed by one layer upstream at the value parser, whose
charset admits no quote, semicolon, brace, `$`, backtick, or newline. Test the
payload with each producer's own validator and the reachability question
answers itself, which is what separates a Medium report from a hardening note.

## Audit what a quoting function does NOT escape

A quoting helper escapes a finite set. The injection is always in the
complement, so enumerate what is left unescaped, then ask which of those
characters the *destination format* treats as structure. For any file written
one record per line — `/etc/*.conf`, `/etc/sudoers.d/*`, cron, `.ini`,
`.gitconfig` — the structural delimiter is the newline, and newline survives
nearly every ad-hoc escaper (`\`, `"`, `$`, and backtick are handled; `\n` is
not). Path validators are weak filters here: `realpath -e` accepts a newline
inside a path, so a directory name can carry it into a write.

Two things keep this from being reportable by default, and both must be checked
before writing it up: the payload's quote character usually arrives escaped, so
the injected line cannot close its own string to begin a valid directive; and
the destination often has a syntax gate (`visudo -cf`) that refuses malformed
content before it is installed. When both hold, log the lead as a hardening
note with the escaped-quote proof, not a finding.

## Number the closed surfaces so the next wave re-targets

A multi-wave hunt that reports only in prose re-audits the same surface twice.
Keep a numbered ledger of every surface examined with one evidence line each:
function and path, why it was reachable, and the verdict. Number continuously
across waves so a lead closed in one wave is not re-opened in another, and so a
duplicate report's closure lands against the entry that produced it.

Why: the ledger is the deliverable when a wave yields no bug. It converts "I
looked and found nothing" into "these N surfaces are closed, here is the proof
for each", which is what makes the next wave's scope decision a decision
rather than a guess.
