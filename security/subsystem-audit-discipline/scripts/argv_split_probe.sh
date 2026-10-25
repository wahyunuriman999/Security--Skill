#!/bin/bash
# argv_split_probe.sh -- does a bash expansion produce ONE argv word or several?
#
# The trap: testing with `for w in $out` performs the word-splitting you are
# trying to detect, so every payload "splits" and every expansion looks broken.
# The correct harness iterates "$@" inside a function, because "$@" reports the
# splitting the shell ACTUALLY performed at the call site.
#
# Usage: paste the expansion form under test onto LINE UNDER TEST below, written
# unquoted exactly as the audited script writes it, then run:
#   bash argv_split_probe.sh
#
# The case this settles, from ${var:+-c "$var"} passed to useradd -c:
#   value='; touch /tmp/pwned; echo'
#   argc=3  argv[1]=[-c]  argv[2]=[; touch /tmp/pwned; echo]  argv[3]=[targetuser]
#   -> one word: no injection, the qualifier expansion is a single token.

show_args() {
  local i=0 a
  printf 'argc=%d\n' "$#"
  for a in "$@"; do
    i=$((i + 1))
    printf 'argv[%d]=[%s]\n' "$i" "$a"
  done
}

# ---------- LINE UNDER TEST ------------------------------------------------
value='; touch /tmp/pwned; echo'
show_args ${value:+-c "$value"} "targetuser"
# ---------------------------------------------------------------------------

# Companion question this file does not settle but flags: $(<file) strips only
# TRAILING newlines, so a leading newline survives into the value, and bash =~
# anchors $ at end-of-string rather than end-of-line -- so a value holding a
# newline fails an otherwise-matching ^...$ check. Test those with the real
# payloads, not a clean input.
