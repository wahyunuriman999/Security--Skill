---
name: hunt-differential
description: "Hunt method-mismatch and response-divergence bugs — one route, many HTTP methods (GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE) compared against each other, plus two-URL boundary comparison (anonymous vs authenticated context). Pays when a body-serving method contradicts a refused sibling on the same path, or when the response exposes configuration markers. Use when probing API routes, pre-auth endpoints, or anything you suspect has uneven auth enforcement."
version: 1.0.0
license: MIT
report_count: 0
sources: user_engagement
tool: _shared/tools/rat_diff.py
triggers: [hunt, differential]
---

# HUNT-DIFFERENTIAL — when the method is the bug

## The idea in one line

Ask the same path with seven different HTTP verbs. If one verb serves a body
and its siblings answer 401, the authorization check is attached to the
method, not the resource — and you have found a differential.

This is the class MethodCheck automates inside Caido. `rat_diff.py` is the
same engine, standalone, so it runs where Caido cannot.

## Why it pays

Most auth gates are written per-route, not per-method. A handler registered
for `GET /user/v1/config` with `@login_required`, while `POST /user/v1/config`
was added later by a different team with no decorator, is a real pattern. The
\endpoint looks protected because your browser only ever issues GET.

Sources of divergence worth probing:

| Surface | What differs | Typical impact |
|---|---|---|
| Method matrix | GET 200 vs POST 401 | unauth write / unauth read |
| Boundary pair | anonymous 200 vs authenticated 401 | pre-auth data exposure |
| Header trust | with `X-Original-URL` vs without | auth bypass |
| Content type | JSON vs form parsing | parser confusion |
| Method override | `X-HTTP-Method-Override: DELETE` | WAF/gate bypass |

## Step 1 — classify before you probe

Read the ask, set the frame:

- **In scope?** Written scope only. A route on an out-of-scope host is not
  a finding, it is a violation.
- **Read-only allowed?** If the program says "do not exploit," GET/HEAD/
  OPTIONS only. Never send a mutating verb to a live target you do not own.
- **Credentials?** Two accounts turn this skill from P3 into P1 — boundary
  pairs need both contexts. Without credentials you can still find method
  mismatches and header-trust divergence.

## Step 2 — build the route list

Heritage from every prior recon run, in priority order:

1. Route children of any `/v1/`, `/api/`, `/user/` prefix you already found.
2. Every route that returned 401/403 with GET — those are the candidates
   where a sibling method might have been left open.
3. Sibling pairs of anything that returned 200 — the 200 route's siblings
   are often the open ones.
4. Static/legacy paths (`.htm`, `.do`, `.json`) near the main app.

Put them one per line in `urls.txt`, `#` comments allowed, blanks skipped.

## Step 3 — run the tool

```bash
# single route, full method sweep (issues 1 request per verb)
python rat_diff.py --mode methods \
  --url "https://target.example/user/v1/config" \
  --methods GET,HEAD,OPTIONS,POST,PUT,PATCH,DELETE --live

# batch sweep over a route list
python rat_diff.py --mode matrix --file urls.txt --live --json > matrix.json

# boundary pair: same resource, two auth contexts
python rat_diff.py --mode anomaly \
  --url "https://target.example/user/v1/config" \
  --url2 "https://target.example/user/v1/anonymous-config" --live
```

`rat_diff.py` is hermetic by default — without `--live` it issues zero
requests and reports what it *would* do. Check the plan first, then add
`--live`.

Run `python rat_diff.py --mode selftest` before the first live sweep. It
exercises every detector against fixtures with no network attached — a clean
run proves the engine is intact in the *deployed* copy, which is where a
packaging or path-mangling step may have broken it. Re-run it after any edit to
the tool, its marker list, or its fixtures.

Extra headers are repeatable: `--header "X-Original-URL: /admin"`.

## Step 4 — read the verdicts

`mode methods` per route:

| Output | Meaning | Action |
|---|---|---|
| `contradicted_by=HEAD,OPTIONS` | a body method is refused by siblings | **candidate** |
| `sensitive_markers=[...]` | body contains config keywords | escalate if unauthenticated |
| `uniform` | no divergence | move on |

`mode anomaly` per pair:

| Verdict | Meaning |
|---|---|
| `divergent_status_and_body` | contexts see different things — the boundary is real |
| `same_status_different_body` | same gate, different content — check for IDOR shape |
| `identical` | no boundary here |

## Step 5 — hardening: does the finding survive?

A status-code difference is **observation, not vulnerability**. Before you
write a report, the finding must answer one of these:

1. **Does it leak?** The body must contain something a tenant should not
   see — another org's identifier, an internal hostname, a credential, a
   config flag that changes security posture. A 200 that returns
   `{"ok":true}` is noise.
2. **Does it write?** `POST/PUT/PATCH/DELETE` returning 2xx where GET returns
   401 is a different and far stronger finding than a read difference.
3. **Does it chain?** The divergence plus a second step equals unauthorized
   access or state change. Describe the chain, don't imply it.
4. **Would a maintainer change something?** If the vendor's answer is
   "intended behavior," the finding is closed. Test the assumption by
   comparing against the sibling routes: if every sibling is consistent and
   yours is not, the inconsistency is the bug.

## Step 6 — writing it up

VRT: `Server Security Misconfiguration → Improper Authentication` when the
method gate is the defect; `→ Other` when only differential behavior exists
without demonstrated impact.

Report shape:

```
Title: [Method] <METHOD> on <path> bypasses authentication enforced on
       sibling methods

Severity: <assigned with justification — VRT default often lands low>

Summary: one paragraph, the contradiction first.

Steps to reproduce:
  1. curl -X GET  <url>  -> <status>, <bytes>, <sha256>
  2. curl -X HEAD <url>  -> <status>
  3. curl -X OPTIONS <url> -> <status>

Impact: what the body contains and who should not see it.

Recommendation: enforce the auth check in middleware keyed on the route,
not on the handler method.
```

Attach the tool's `--json` output. It carries per-method status, byte count,
and body hash — enough for a triager to reproduce without trusting you.

## What does NOT pay

- **A 200 that serves a public asset.** Convention, not vulnerability.
- **OPTIONS 200 with an `Allow` header.** That is CORS working correctly.
- **404 vs 405 on a dead route.** Route not found.
- **Method override headers honored on a route that is public anyway.**
- Any of the above, disclosed without a leaked value.

## Rate discipline

One request per verb per route. Batch mode is sequential, no threads. If a
target starts returning 429, stop and resume later — a timeout is cheaper
than a ban. Log every response so the next run can skip what you already
probed.
