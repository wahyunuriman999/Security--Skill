# Advanced Server Access (ScaleFT) — attack reference

Depth for the ASA / ScaleFT surface on the Okta Bugcrowd program. Load when the engagement reaches `app.scaleft.com` / `app.trex.scaleft.io`, or when a similar tenant-namespaced web app exposes a pre-auth validation endpoint.

## Reading a Bugcrowd engagement scope without login

Engagement pages are client-rendered, but the Rails app still emits the header props server-side in a `data-props` attribute on the brief component:

```bash
# 1. engagement page → data-props blob
curl -s https://bugcrowd.com/engagements/<handle> | grep -o 'data-props="[^"]*"' | head -1
# HTML-decode the attribute, then read: code, state, statusLabel, rewardAllocation,
# startsAt, endsAt, scopeRank, description

# 2. public JSON endpoints that need no auth
/engagements/<handle>/statistics      # rewardedVulnerabilities, averagePayout, validationWithin
/engagements/<handle>/scope_ranks     # {"scopeRank":N}
/engagements/<handle>/announcements   # large HTML shell; sometimes embeds target lists
/engagements/<handle>/hide_reasons
```

The full in/out-of-scope **target list usually is not in that payload** — it renders after login. Two other sources, in order of authority:

1. **The vendor's own security page.** Okta's `/security` page links `https://bugcrowd.com/okta` and `https://bugcrowd.com/auth0-okta` directly, and the short handle (no `/engagements/` prefix) returns 200 as well. The vendor's page is authoritative about *which* programs are live.
2. **Public scope mirrors** (`bug-bounties.as93.net/<program>`, `bbscope.com`) republish target lists verbatim. Always re-verify a mirror's boundary against the live engagement before relying on it — republishers lag program changes by months and will happily show you a stale in-scope list.

A related trap: `bugcrowd.com/<handle>/brief.json` and `/target_groups` return a 200 **HTML shell**, not JSON. A 200 status is not evidence of content — check the body before concluding a scope endpoint exists.

## Where the skills attach

The ASA web app is a React SPA. The API tree is **not** documented publicly — recover it from the bundles on `assets.scaleft.com`:

```bash
# 1. read the app shell to find the bundle hashes
curl -s https://app.scaleft.com/ | grep -o 'assets.scaleft.com/js/[a-z0-9.]*\.js'

# 2. pull the dashboard bundle and the vendor webpack chunk
curl -s https://assets.scaleft.com/js/dashboard.<hash>.js
curl -s https://assets.scaleft.com/js/<vendor-chunk>.js

# 3. harvest route literals
rg -o '"(/v1/[a-zA-Z0-9_\-/{}\.$]{2,70})"' dashboard.js
rg -o '\.(GET|POST|PATCH|PUT|DELETE)\(\s*[`"'"']([^`"'"']{1,90})' dashboard.js
```

Route literals are sparse — the client composes most of them from the session-creation flow. Recover the flow instead: grep for `sessionToken.complete.listen`, `createSession.start`, `currentStep` and `step_type` to learn which endpoints the auth state machine drives (`browser`, `password`, `password_force_update` step types).

The bundles also embed a **hostname → AWS-account-id map** for the ASA fleet (`app.scaleft.com`, `app.trex.scaleft.io`, `pam.okta.com`, `pam.oktapreview.com`, `pam.trexcloud.com`, `dev.sudo.wtf`). That map is infrastructure disclosure on its own and tells you which sibling environments exist to compare against.

## The enumeration oracle — full classification recipe

`POST /v1/teamname-validate` with `Content-Type: application/json` and body `{"team_name": "<x>"}`. **No Authorization header, no cookie.**

| Input class | HTTP | Discriminating body text | Meaning |
|---|---|---|---|
| registered tenant | 400 | `Attempted to use existing team name.` | **EXISTS** |
| internal-only name | 400 | `Attempted to use reserved team name.` | **RESERVED** |
| random control | 200 | *(empty body)* | available |
| short | 400 | `too short, must be at least 3 characters` | schema |
| non-alnum | 400 | `may only contain alphanumeric characters` | schema |
| wrong type | 400 | `not a string` | schema |
| no body | 400 | `Request body required for this API` | schema |

Probe set that maximizes signal per request — always include the controls, because a run with no AVAILABLE rows has not proven anything:

```
known brand / org names        bugcrowd, okta, google, aws
internal infra words           admin, www, api, app, login, support, status, scaleft
random controls (must be free) zzqqxxwwvvuu, qqwweerrttyyuu
```

Interpretation:

- Brand names returning EXISTS confirm the oracle tracks the **real** tenant namespace, not a mock.
- Infra words returning RESERVED leak the blocklist — record it verbatim, it is straight disclosure of operator-meaningful hostnames.
- Random controls returning AVAILABLE are the control group that makes the EXISTS rows meaningful. Without them the finding is unproven.

### Proving determinism

Repeat a single input 3–5×. The JSON contains a rotating `requestId`, so a byte comparison of full bodies fails; compare the **classification**, not the raw body. A stable classification across repeats is what makes the finding reproducible.

### Cross-environment mapping

Run the identical probe set against `app.trex.scaleft.io`. Tenants that report EXISTS on `app.scaleft.com` and AVAILABLE on `app.trex.scaleft.io` demonstrate the oracle resolves the **tenant→environment** mapping — which is precisely the prerequisite for targeting one org rather than spraying both.

## What was already ruled out (do not re-attempt)

| Attempt | Result | Why it closed |
|---|---|---|
| `alg:none` JWT | 401 `Invalid authentication token` | signature verified |
| empty signature JWT | 401 `Invalid authentication token` | signature verified |
| HS256-shaped JWT | 401 `Invalid authentication token` | key not derivable |
| 600-byte garbage bearer | 401 `Invalid authentication token` | parser rejects pre-verify |
| `Basic`/`Token` scheme | 401 `Invalid Authorization header, Bearer token...` | scheme pinned |
| PUT/PATCH/DELETE/OPTIONS | 404 | single-method route |
| TRACE | 405 (envoy) | method not allowed |
| non-JSON content types | 415 `unsupported_content_type` | content type pinned |
| tenant oracle via `POST /v1/teams/{t}/sessions` | identical 400 for existent and non-existent teams | no differential |
| tenant oracle via `/l/{team}/login/*` | same SPA shell for both | client-side routing only |

Schema error verbosity (`json: cannot unmarshal, not an object`, `invalid character 'o' in literal null`) is real but low value — parser internals on a pre-auth endpoint, no tenant or user state. Not a report on its own.

## Program rules that constrain this surface

- **No automated scanning** — the enumeration must be a bounded classification pass (order of a dozen to two dozen probes, spaced), not a wordlist run. Write the delay into the reproducer so the artifact itself demonstrates restraint.
- **No DoS** — none of this is state-changing anyway; keep it read-only.
- **Complete PoC required** — a payload-shape observation with no demonstrated impact gets closed as theoretical. Lead with the classification table, not with the observation.


## Severity framing that survives triage

The honest framing is *unauthenticated tenant-namespace disclosure on a P1-band asset*, **information disclosure severity**, with an explicit paragraph naming what is **not** proven (no account takeover, no session, no credential tested, no data read) and naming the specific downstream decision that would upgrade it. Overclaiming this as P1 is the fastest way to lose the triager for the whole engagement.
