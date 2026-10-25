---
name: hunt-cache-deception
description: "Hunt web-cache deception and cacheable-authenticated-response bugs — responses that carry configuration or credential markers without Cache-Control no-store/no-cache/private, then confirm a shared/proxy cache would actually replay them to an unauthenticated requester. Distinguishes a risk from a finding by verifying the cache behavior, not the header text. Use when probing authenticated API routes, config endpoints, or anything returning sensitive JSON."
version: 1.0.0
license: MIT
report_count: 0
sources: user_engagement
tool: _shared/tools/rat_diff.py
---

# HUNT-CACHE-DECEPTION — the header is the lead, not the verdict

## The idea in one line

A response is cacheable when the origin says so. If an *authenticated*
response is cacheable, the cache layer becomes an unauthorized reader —
everyone who hits the same URL gets the first user's body. The bug is not
the missing header; it is that you can get another user's content back.

## The distinction that decides everything

| | |
|---|---|
| **Cache risk** | sensitive-looking body, no `no-store`/`no-cache`/`private` |
| **Cache deception** | an attacker makes the cache store an authenticated response, then reads it unauthenticated |

Risk is a header note. Deception is a submitted bug. Most triage rejections
at "cache risk" stage come from submitting the first as the second.

## Step 1 — verify the body actually deserves protection

Do not flag the header before you have content worth protecting. The marker
list in `rat_diff.py` is the floor, not the ceiling:

```
password  secret  token  api_key  apikey  private
isrunningascloudsaas  minimumlength
```

The tool refuses to flag a body under 64 bytes or with no markers. That is
correct — a 12-byte `{"ok":true}` with no cache header is not a report.

What to look for in the body yourself:

- another tenant's identifier (org id, account id, email, tenant GUID)
- an internal hostname or IP
- a session token, cookie value, or API key
- a config flag that changes security posture (`ssoEnabled`,
  `passwordComplexity.enabled`, `mfaRequired`)

If the body is only your own public config, there is nothing to deceive
anyone with.

## Step 2 — read the cache trio

Three headers decide the case. Read all three, not one:

```
Cache-Control:  no-store            -> never cache, case closed
                no-cache            -> cache but revalidate, may still be a bug
                private             -> shared cache must not store it
                <absent>            -> the CDN's own policy applies — check it
Vary:           what the cache keys on
Age / X-Cache:  whether anything is actually in front
```

`no-cache` alone is **not** a fix for this bug — it permits storage with
revalidation, and revalidation is where the bypass lives when the cached
entry is keyed on a URL the attacker controls.

The dangerous shape is: **`Cache-Control` absent + `Vary: Cookie` absent +
an `Age` header present.** That combination means a shared cache is storing
the response and not varying it on anything.

## Step 3 — prove the cache behavior

Header reading is a hypothesis. Proof requires one of these sequences,
**against a target you own a test account on**:

**Path-confusion form (the classic):**

```
GET /account/settings.css   -> cache stores it; origin serves authenticated body
GET /account/settings.css   (attacker, unauthenticated) -> cache returns the body
```

**Extension-confusion form:**

```
GET /account/settings/x.css
GET /account/settings/x.js
GET /account/settings/%2e%2e  or  /account/settings/nonexistent.css
```

**Header-injection form:**

```
GET /account/settings  +  X-Forwarded-Host: evil.example
```

If the second, unauthenticated request returns the first user's body — the
finding is real and the severity follows from what that body contains.

If the second request is a miss or a 401, you have a header observation, not
a vulnerability. Record it, move on.

## Step 4 — rate discipline

Cache probes are stateful — you poison the cache, then read it back. Two
rules:

1. **Use a unique path per test** (`/x-<random>`) so you never cache-static
   a URL a real user hits.
2. **Never probe a path belonging to another user.** That is unauthorized
   access, not testing, and it is the fastest way to have the engagement
   terminated.

## Step 5 — writing it up

VRT: `Sensitive Data Exposure → Cacheable HTTPS Response` when you proved the
replay; `Server Security Misconfiguration → Other` when you have the header
but not the replay.

Report must state, in this order:

1. the authenticated request and the cacheable response header
2. the unauthenticated follow-up request
3. what came back, byte-identical to the first response
4. what the body contained and whose it was

Attach both responses. One response is not a cache finding.

## What does NOT pay

- A missing `Cache-Control` on a response that is genuinely public.
- `Cache-Control: no-store` misinterpreted as absent — read the value.
- Static assets (`.css`, `.js`, images) that are *supposed* to be cached.
- A single response with no second, unauthenticated read.
- Cache poisoning without a way to get a victim to fetch your poisoned URL.
  Without delivery, there is no impact.

## Using the tool

```bash
# classify a response: does the body deserve protection, is the header safe
python rat_diff.py --mode methods --url "<AUTHED_URL>" \
  --methods GET --live --header "Cookie: session=YOUR_OWN_TOKEN"

# the tool prints: cache_ok (strict header present) or cache_risk + markers
```

`cache_ok` means the header is fine — close that route.
`cache_risk` means you have a lead — go to Step 3 and prove or kill it.

Before the first live sweep, run `python rat_diff.py --mode selftest`. It
exercises the cache classifier against fixtures with no network attached, and
proves the deployed copy of the tool is intact — a packaging or path-mangling
step can break a script that works fine in its source tree.
