# Crypto.com Hunt Ledger — 2026-10-10 (SGT)

## Rig
- QUIC/HTTP3 direct to CF edge (UDP 443) — bypasses Kominfo TCP SNI middlebox
- rat_h3.py: H3 client (aioquic), get()/get_text()/fetch() with ip override
- DO NOT send content-length on POST via H3 to Rails hosts (CF re-chunks; Rails 400s)
- ratproxy.py TCP relay (8443) — works but WAF-fingerprint-blocked for automation

## Confirmed surface (all live via QUIC)
| Host | Finding |
|---|---|
| api.crypto.com/exchange/v1/public/* | JSON-RPC, live market data, GET+params OK |
| wapi.crypto.com/v1/* | SDK-auth API: 401 auth oracle, uniform errors (no user enum) |
| pay.crypto.com/graphql | Merchant GraphQL: introspection disabled, resolver-level auth on all fields, verbose validation errors |
| merchant.crypto.com | React dashboard; source map (65 files, no content); full GraphQL docs extracted from bundle |
| auth.crypto.com | Rails magic-link email flow; CSRF + session solid; redirect_uri validated ("Invalid Redirect"); no reset/signup enumeration surface |
| crypto.com/nft | SPA live; api-config.nft.crypto.com/config.json public feature flags (expected, harmless) |
| tax.crypto.com | SPA; config.json public (version v0.19.0 exposed — cosmetic) |
| js.crypto.com | Next.js app; bundle 3.5MB (Ledger wallet integrations) |
| tickets/experiences/og | Live SPAs, not yet deep-dived |
| api.crypto.com | Spring Boot (Whitelabel error pages) |

## Candidate findings (to validate)
1. **wapi HMAC signature scope** — SDK signs `timestamp+method+PATH-ONLY` (query string excluded). Structural: if server enforces same, query params can be tampered post-signature → signature bypass on GET endpoints. NEEDS: valid API key pair (account required).
2. **pay.crypto.com/graphql validation-error schema oracle** — verbose errors reveal field names/types (introspection substitute). LOW severity; info disclosure via error messages. H1 Crypto.com excludes "error messages without sensitive data" — likely rejected. KILL unless chained.
3. ~~ai-agent-api SSRF~~ — KILLED: service decommissioned (503 nginx, upstream gone).
4. ~~tax /api enumeration~~ — found: routes at /api/api/* (Express strips first segment). forgot-password+signin exist but captcha/credential-gated. users/me 401. Firebase nv-prod DB rules LOCKED (401 Permission denied). Clean.
5. ~~Source maps on production~~ — js.crypto.com exposes 1205 source files via .map. Info disclosure of code structure; H1 excludes directory/tech-stack disclosure. LOW — kill standalone; keep as amplifier.

## Auth flow notes (for future account-based testing)
- tax app: Firebase auth (nv-prod.firebaseio.com, locked), backend https://tax.crypto.com/api (routes: /api/api/users/signin, forgot-password [captcha], resend-verification, verify-then-request-otp, user-apis/coinbase|coinjar, reports, transactions...)
- OAuth client_id (NFT app): 6b5f15643ee1ba376431f279b9f96bfa2aaa3783d4b2a1013a0305b83649fad
- Login: POST /auth/connections {form[email], form[redirect_uri], authenticity_token} → magic link email
- Valid redirect_uri must come from server-pending state (authorization/new flow)
- app-assets.mona.co = static asset host for auth app
- H3 POST to Rails hosts: NEVER send content-length (CF re-chunks → Rails 400 "Bad Request" plain-text)
- merchant API key e11a03913c4c520f57cb6edbbcc5ec6c (32 hex) — analytics/logger init key, public by design, NOT a leak

## Confirmed findings (NEW — travel stack)
6. **slapi.travel.crypto.com tenant enumeration via x-tenant-id** — AWS API Gateway (no-SNI TCP reach). `/v1/orders` + `x-tenant-id: X`: unknown tenant → 400 "Tenant with name 'X' doesnt exist at the Cache" (echoed); EXISTING tenant → 401 Unauthorized. Confirmed existing: **cdc, moca, superlogic** (vendor's own tenant!). Case-sensitive. No injection (values safely echoed). NestJS backend, multi-tenant cache. Impact: internal tenant/partner names disclosure + architecture (booking/order system behind). Severity: LOW-MEDIUM (their policy may exclude "internal names" — frame as multi-tenant access-control surface + pair with x-tenant-id controlling tenant context = potential cross-tenant step when combined with valid JWT from one tenant).
7. **Keycloak exposure** — auth.travel.crypto.com (AWS, QUIC-unreachable but no-SNI works): realm cdc (public_key exposed - normal), **/realms/master/.well-known/openid-configuration → issuer auth.superlogic.com** — vendor (Superlogic) infrastructure disclosure; master realm reachable. redirect_uri validated; direct access grants disabled (unauthorized_client). Client 'oneof-next' valid (303 broker → cdc-oidc → auth.crypto.com chain confirmed).
8. **/v1/payments** → NestJS "Forbidden resource" (reached backend, policy-gated) — endpoint exists disclosure only.

## 🔥 REPORTABLE FINDING #1 (report drafted)
**CORS origin reflection + credentials on crypto.com/nft-api/graphql**
- Endpoint reflects ANY Origin (verified: evil-rattest.com, attacker.io, sub.crypto.com, http://crypto.com, null) as ACAO with **ACAC: true** on BOTH preflight and actual responses
- Preflight allows ALL methods (POST/GET/PUT/DELETE/PATCH)
- Schema has cookie-guarded account fields: me (bio/name/username/displayName/instagram/twitter), orders, bids, drops, assets, creations, ownedCollections → cross-origin account data theft for any logged-in NFT user
- PoC: poc_nft_cors.html (credentials:include fetch chain) + full report: REPORT_nft_cors.md
- Secondary observations (same endpoint): Fastify backend; introspection disabled but Did-you-mean schema suggestions leak field names; public fields: collectionBook(id!), creation(id!), drop(id!), asset(id!), checkout(id!)

## API CORS matrix (other endpoints, for context)
- api.crypto.com /exchange/v1/public/* : reflects origin (ACAO=evil) but ACAC absent on real responses — no credentialed impact; preflight lies (ACAC=true) — watch for changes
- pay.crypto.com/graphql: ACAO=* (no credentials) — safe pattern
- tax/merchant/auth: no reflection

## Next moves (ranked)
1. ~~ai-agent-api SSRF~~ DONE — dead (503)
2. ~~tax /api routes~~ DONE — mapped, gated cleanly
3. ~~tickets/experiences~~ DONE — mapped: Keycloak client 'oneof-next', slapi + api.experiences surface
4. Get account → wapi key pair → signature-scope test + merchant IDOR (accountId swap) — THE REMAINING HIGH-VALUE PATHS
5. slapi: with valid CDC JWT (from travel login), test cross-tenant access (x-tenant-id swap with cdc JWT → superlogic/moca tenant data?) — POTENTIAL CRITICAL
6. Keycloak broker chain (cdc-oidc → auth.crypto.com magic link): needs live login session
7. web.crypto.com app-level hunt (needs browser session)
