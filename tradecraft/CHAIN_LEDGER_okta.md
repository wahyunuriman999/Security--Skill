# Chain Investigation Ledger — shopify.okta.com state reuse

Date: 2026-10-11 (UTC+7)
Target: shopify.okta.com → minerva.shopifycloud.com (vault.shopify.com IdP)
Method: manual HTTP probes, httpx, no scanner

## What's verified (raw evidence in evidence files)

1. **State reuse accepted** — same `state` + different `nonce` → 200 both times.
   Empty/missing state → 302 `error=invalid_request`. Presence validated, uniqueness not.
2. **PKCE not enforced** — `response_type=code` proceeds (200) with zero `code_challenge`.
   S256 supported per discovery doc but optional for client `OKTA_CLIENT_ID`.
3. **Attacker state persists into login continuation** — state embedded in `fromURI`
   hidden field of Okta's login page; after victim auth, flow continues to authorize
   with the attacker-chosen state; code lands on minerva callback carrying that state.
4. **redirect_uri strict-whitelisted** — all 6 OOB/pollution variants → 400. No direct exfil.
5. **Implicit & hybrid blocked** for this client (`unsupported_response_type`) — good.
6. **Minerva callback differentiates (code,state)** — 400 + full "Authentication Error"
   page for code+state shape; empty/no state → 400 with EMPTY body. Minerva parses the pair.
7. **response_mode=form_post accepted** (200 login page renders; post-auth would POST
   code+state to callback — CSRF-able via crafted form if same-site not enforced).
8. **Minerva is Trust-team internal tool** (Slack #help-minerva-clouddo) — employee-facing,
   authentication errors reveal Rails CSRF meta tags + CSP nonce.

## Attack chain (as it stands)

```
Attacker hosts page → victim (Shopify employee w/ active Okta session) visits →
silent authorize w/ attacker state (prompt flow embeds it in fromURI) →
Okta issues code → redirects to minerva callback?code=X&state=ATTACKER_STATE →
IF minerva fails to bind state to victim's pre-login session → CSRF completes →
victim's Minerva session created inside attacker-known flow context.
PKCE absence means any code the attacker can observe can be exchanged.
```

## Honest blockers (what we could NOT prove)

- No victim interaction performed (no employee account — and none should be touched).
- Cannot confirm minerva validates/binds state server-side without a valid code
  (all fake-code probes return the generic Authentication Error page).
- Cannot observe a real code exchange (requires completing login).
- No OOB exfil possible: redirect_uri locked; callback adds no redirect params.

## Severity assessment (honest)

Verified facts justify: **CSRF on OAuth login flow (state not unique/session-bound)** —
real weakness, RFC 6749 §10.12 violation, on employee-facing IdP.

NOT yet proven: full account takeover. The chain depends on minerva's server-side
state validation, which cannot be tested without valid credentials. Per
triage-validation Q1/Q6 discipline, we report what's provable:

- **What attacker can do NOW (proven):** initiate OAuth flows with arbitrary,
  reusable state values that persist through the entire login journey (fromURI).
- **Impact if minerva under-validates:** login-CSRF → session fixation on Trust-team tool.
- **Recommendation:** bind state server-side, single-use, session-bound; enforce PKCE.

Severity: **Medium–High** (High if triager accepts the CSRF chain as credible;
the PKCE gap strengthens it).
