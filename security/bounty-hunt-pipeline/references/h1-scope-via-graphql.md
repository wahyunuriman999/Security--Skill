# Program Intel Without a Browser (HackerOne)

HackerOne program pages are a client-rendered SPA — `curl` of
`hackerone.com/<handle>` returns a ~3.5 KB JS shell with no scope, no bounty
table, no policy. Read scope from the public GraphQL API instead; no login
and no browser required.

## Read the scope

```bash
S="$LOCALAPPDATA/hermes/profiles/hacking/cache/scratch"   # or any writable dir
cat > "$S/q.json" <<'EOF'
{"query":"query { team(handle:\"TARGET\") { handle name offers_bounties submission_state base_bounty currency structured_scopes(first: 100) { edges { node { asset_type asset_identifier eligible_for_bounty eligible_for_submission instruction max_severity } } } } }"}
EOF
curl -sS -m 30 -X POST https://hackerone.com/graphql \
  -H 'Content-Type: application/json' -A 'Mozilla/5.0' \
  -d @"$S/q.json" -o "$S/scope.json" -w 'HTTP %{http_code}\n'
```

Notes:
- Field is `structured_scopes` — a `structured_policy_scope` query returns a
  `Did you mean?` error naming the correct field. That suggestion is a free
  schema map; never guess field names.
- `structured_policy_scope` is absent; `structured_scopes` works unauthenticated.
- `curl -o` writes to the scratch dir, never a bare `/tmp` — on MSYS hosts the
  two are different filesystems and native tools can't read the wrong one.

## What to extract

| Field | Use |
|---|---|
| `asset_type` + `asset_identifier` | the exact asset string the submission form expects (`WILDCARD *.target.com`, `OTHER <url>`) |
| `eligible_for_bounty` | scope filter — False = do not report, even if exploitable |
| `max_severity` | program's ceiling; a finding above it is out of policy |
| `submission_state` | `open` vs `paused`/`invite_only` |
| `base_bounty` + `currency` | sanity-check the payout expectation before investing days |

## When the scope list is thin

Many programs list only a wildcard and a catch-all `Anything not in scope` /
`bounty=False` row. That row is a signal to read the extended policy
(out-of-scope lists, excluded bug classes) before hunting, not a signal that
the wildcard is unbounded. Check the program's linked policy repo when one
exists.

## Recording the target

Keep a per-target ledger (scope table, live hosts, 404 baselines, candidate
findings with their verdicts) rather than re-deriving it each session. Kill
signals recorded early (`dead service 503`, `introspection disabled`) save
the next session from re-testing the same dead ends.

