---
name: hunt-spa-api
description: Discover a single-page-app's hidden backend API from its public JS bundle, then test that API for broken access control / missing authentication. One of the highest-yield web plays in modern recon — SPAs ship their entire backend route map to the browser, and the API behind them is frequently missing the auth middleware the login page implies. Built from an authorized engagement where this play found an unauthenticated financial API that an ASM scan reporting hundreds of "Criticals" completely missed. Use whenever a target serves a JS-heavy SPA (React/Vue/Angular/Next), an "app"/"console"/"dashboard"/"portal" subdomain, or any `*api*` host shows up in recon. Leaked build artifacts (source maps / .env / .git / asset-manifest) are owned by hunt-source-leak; API version-inventory and behavioral diffing by hunt-shadow-api; this skill owns mapping a live SPA's backend routes from its JS bundle and testing them for broken access control / missing auth.
sources: authorized-engagement
report_count: 1
---

## When to use this skill

Trigger when:
- A target host returns a tiny HTML shell + big `/static/js/*.js` or `/_next/static/*` bundles (React/Vue/Angular/Next/Svelte SPA)
- You see a subdomain named `console`, `app`, `dashboard`, `portal`, `admin`, `panel`, `manage`, `internal`
- Recon surfaces any `*api*`, `*-api*`, `api.*` host
- A login page is OAuth/SSO-gated (the *frontend* auth tells you nothing about whether the *API* enforces auth)

The core insight: **a SPA is a client to a backend API, and it ships the full map of that API — hosts, routes, sometimes keys — to anyone who views source.** The login page being protected says nothing about whether the API behind it checks tokens. Auth is frequently enforced on the *gateway/login* and missing on a *route group* of the API.

DO NOT skip this because "the app needs login" — that's exactly when this pays off.

---

## The play (5 steps)

### 1. Pull the shell + enumerate the bundles
```bash
curl -s https://console.target.com/ -o index.html
# React/CRA:
grep -oE '/static/js/[^"]+\.js' index.html
# Next.js:
grep -oE '/_next/static/[^"]+\.js' index.html
# generic:
grep -oiE 'src="[^"]+\.js[^"]*"' index.html
```
Download every bundle (they can be multi-MB — that's fine, it's all route data):
```bash
mkdir bundles
for j in $(grep -oE '/static/js/[^"]+\.js' index.html | sort -u); do
  curl -s "https://console.target.com$j" -o "bundles/$(echo "$j"|tr '/' '_')"
done
```

### 2. Harvest API hosts, routes, and secrets from the bundles
```bash
B=bundles/*.js
# Backend API hosts (incl. dev/beta/staging variants — often weaker auth)
grep -ohiE 'https://[a-z0-9.-]*(api|console|backend|service)[a-z0-9.-]*\.target\.com[a-z0-9/_-]*' $B | sort -u
# Versioned API base paths
grep -ohiE '/api/v[0-9]+/?' $B | sort -u
# Route literals — minified bundles store routes as STRING segments, not full URLs.
# Grep for quoted "resource/action" strings:
grep -ohiE '"[a-z0-9_-]+/[a-z0-9_/-]+"' $B | tr -d '"' \
  | grep -iE '(login|user|account|order|billing|invoice|payment|deal|report|token|otp|password|reset|admin|profile|auth|upload|export|role|permission|dashboard|wallet|finance|sales)' | sort -u
# Secrets (validate before trusting — most AIza keys are Maps/analytics, not Auth)
grep -ohiE '(AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]+|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|apiKey["'"'"']?\s*[:=]\s*["'"'"'][^"'"'"']+)' $B | sort -u
```
**Note:** minifiers store routes as concatenated string segments (e.g. `"account/payment/list"`), NOT full `/api/v2/...` URLs — so a naive `/api/v*` grep returns nothing. Grep for the **resource-word route strings** and prepend the base yourself.

**Harvest the runtime config endpoint too — it is frequently anonymous and names the security controls.**
```bash
# names vary: gui-parameters, /config, /bootstrap, /app-config, /env.json, /parameters
curl -s https://target.com/api/gui-parameters | python3 -m json.tool | head -100
grep -ohiE '"[a-z0-9_]*(allowlist|allowed|turnstile|captcha|recaptcha|site_?key|client_?id|issuer|authority|magic|reset|version|build)[a-z0-9_]*"[[:space:]]*:[[:space:]]*"[^"]*"' bundles/*.js | sort -u
```
What to pull from it: OAuth `client_id` / issuer / redirect allowlists, captcha site keys (tells you which barrier to expect at signup), build version+hash (correlate with public advisories), and feature flags that expose unreleased or internal-only endpoints. None of it is a finding on its own — all of it cuts hours off the next step.

**Lazy-loaded (async) chunks — don't stop at HTML-referenced bundles.** CRA/webpack SPAs reference only runtime+main+vendor in index.html; numbered async route chunks are named inside main.js's chunk map and loaded at runtime, so grepping only `/static/js/*.js` from the shell truncates route coverage to eager chunks.
```bash
grep -oE '[0-9]+":"[a-f0-9]+"' bundles/*main*.js        # {chunkId:"hash"} pairs
# reconstruct /static/js/<id>.<hash>.chunk.js, download each, re-run route/host/secret harvest
# asset-manifest.json (if present) lists them all -> hunt-source-leak
```

**Angular CLI names async chunks `chunk-XXXXXXXX.js` (8 uppercase alnum), not numeric ids.** There is no `{id:"hash"}` map to parse — enumerate the naming family from the entry bundle and fetch every match. On an Angular target the route/endpoint map lives almost entirely in these chunks, so stopping at `main.js` caps your coverage at the shell:
```bash
# discover the family, then download every match into bundles/ and re-run the harvest
curl -s https://target.com/main.js | grep -oE 'chunk-[A-Z0-9]{8}\.js' | sort -u
```

**Native-ESM / Vite / `type="module"` SPAs — crawl imports recursively instead of the chunk map.** These ship unbundled ES modules: the shell loads `/js/main.js`, which `import`s `./router.js`, `./api.js`, `./pages/*.js` as real paths. There is no webpack chunk map — walk the `import ... from './x.js'` graph breadth-first until no new `.js` refs appear. This often yields *more* route coverage than a minified bundle because the files are unminified and self-describing:
```bash
# seed from the shell's entry script, then BFS every relative/absolute .js import
python - <<'PY'
import re, urllib.request, os, collections
BASE, out = "https://target.com", "esm"
os.makedirs(out, exist_ok=True)
seen, q = set(), collections.deque(["/js/main.js"])
while q:
    p = q.popleft()
    if p in seen: continue
    seen.add(p)
    try: body = urllib.request.urlopen(BASE + p, timeout=20).read().decode("utf-8", "ignore")
    except Exception: continue
    open(os.path.join(out, p.strip("/").replace("/", "__")), "w", encoding="utf-8").write(body)
    for m in re.findall(r"""["'](\.{0,2}/[A-Za-z0-9_\-./]+\.js)["']""", body):
        norm = os.path.normpath("/js/" + m).replace("\\", "/") if m.startswith(".") else m
        if norm.startswith("/js/") and "vendor" not in norm: q.append(norm)
print(f"fetched {len(seen)} modules")
PY
```
Routes live in `router.js` (`path: '/admin/...'`); every API literal in `main.js`/`api.js`/`pages/*.js` is a quoted string — grep the harvested set the same way as step 2.

### 3. Establish a CONTROL — find an endpoint that IS gated
Before declaring anything vulnerable, send an unauthenticated request to an endpoint you expect to be protected, and capture what *correct* rejection looks like:
```bash
curl -s -X POST https://api.target.com/api/users -H 'Content-Type: application/json' -d '{}'
# secure → {"error":"Missing or invalid authorization header"} or HTTP 401
```
This is your differential. A sibling API (e.g. a second API host, or a different route group on the same host) is the ideal control — same stack, so a different response = real authz gap, not a quirk.

### 4. Test each route family UNAUTHENTICATED, both methods
For every discovered route, send it with **no `Authorization` header** and compare to the control:
```bash
for r in <routes>; do
  curl -s -o /tmp/r -w "[%{http_code}] $r\n" -X POST -H 'Content-Type: application/json' -d '{}' "https://api.target.com/api/v2/$r"
done
```
Interpret:
- **`401`/`"Missing authorization"`** → gated (correct). Move on.
- **`200` with data** → unauthenticated data exposure. **Finding.**
- **`405 Method Not Allowed`** → the route EXISTS and matched *before* method dispatch — frequently before auth middleware too. Enumerate the allowed verbs and retry each: a read verb returning `405` while a write verb returns `401` maps exactly where the auth gate sits relative to dispatch, and any verb that returns `400`-with-business-logic instead of `401` is the auth gap.
- **`400 "field X is mandatory"`** → the route processed your request and reached *business-logic validation* without an auth check → **auth bypass; supply the field minimally to confirm.**
- **`200` + verbose DB/stack error** (e.g. `PROCEDURE db_x.sp_y does not exist`) → reached the data layer unauthenticated; also a SQLi-surface signal.
- **Mandatory fields named like `is_admin` / `is_internal` / `requested_by` / `role_id` / `account_type`** → **authorization derived from client-supplied parameters** — set the privilege flag and you self-elevate. Critical-class.

### 5. Pivot & prove (minimally)
- IDs returned by one endpoint (`account_id`, `order_id`, `deal_id`) are the keys the *other* endpoints consume — they prove the whole router is reachable, not just one route.
- Test `dev-`/`beta-`/`staging-` API variants — they frequently have weaker/disabled auth.
- Check the response headers: `Access-Control-Allow-Origin: *` compounds the issue (any web origin reads it from a victim's browser).
- **STOP at minimum-necessary proof.** A handful of records (or a `totalCount`) confirms the missing check. Do NOT enumerate the table — see `redteam-mindset` data-minimization boundary. The finding is the absent auth, not the data volume.

---

## Server-driven auth flows: drive the whole state machine over HTTP (no browser)

Modern SPAs increasingly render auth as a **server-driven form**: the backend returns a JSON
schema describing the current step, and the client is a dumb renderer. That means you can drive
login, OTP, and account-recovery end-to-end with `curl`/`urllib` — no browser, no captcha solver,
no Playwright. This is the difference between "stuck at the login wall" and "mapped the entire
auth attack surface".

**Recognise the pattern.** A POST returns something like:
```json
{"login_token":"<64 hex>","next":"DYNAMIC_FORM",
 "dynamic_form_screen":{"screen_name":"Sign In: Enter password",
   "form_controls":[{"formControlType":"TEXT_PROTECTED","name":"password","required":true}],
   "buttons":[{"action":{"name":"Forgot password","url":"https://.../recover?token=<60 chars>"}}]}}
```
The schema names every field, and every `buttons[].action.url` / `.endpoint` / `id` is a literal
next-hop — a free route map of the auth machine, including branches the UI never shows you.

**Harvest the whole machine before touching it.** Grep the auth bundle for the flow endpoints and
walk them in discovery order:
```bash
grep -ohE '"/ajax/[a-z0-9/_.-]+"' auth_main.js | sort -u   # begin / form / resend / oauth2 / authorize
grep -ohE 'this\.http\.(post|get|put|patch)\('\''([^'\'']+)' auth_main.js   # exact call sites
```
Then follow the schema: each response's `next` tells you the next endpoint, and the response body
hands you the token the next call needs. Typical shape: `begin(email) → token` → `form(token,
password)` → `form(token, otp)` → success — with **a session cookie only minted at the final step**.

**Read the schema for the parameter names it will not tell you.** `form_controls[].name` is the
field key (`password`, `otp`, `email_otp`). But two call sites in the same bundle may use different
envelopes for the same endpoint — a convenience method posting `{login_token, password}` (snake_case)
and the generic pipeline posting `{loginToken, formFields:{password}}` (camelCase). Both are real
and the endpoint accepts whichever it was written for.

**Pitfalls specific to this pattern**
- **`ErrBadRequest "invalid JSON object"` = wrong envelope, not a dead endpoint.** Your request
  reached the endpoint and the request-parser rejected the *shape*. Go back to the bundle and copy
  the exact key names from the call site; do not conclude the endpoint is broken.
- **Distinguish the two 401 bodies to locate the gate.** `"invalid csrf token"` means your CSRF
  header NAME is wrong; `"authentication failure, type mismatch"` means the CSRF was accepted and
  you now need **a logged-in session**. Getting the second one is progress, not failure — it proves
  your header name is correct. Find the custom header name in the interceptor (`headers.set("X-Xsrf-Token", ...)`
  — case matters, and it is often NOT `X-CSRF-Token`), take its value from the init/appInfo JSON,
  and send it only on POST/PUT/PATCH/DELETE as the interceptor does.
- **Step tokens usually expire in ~2 minutes and each step has its own window.** A slow back-and-forth
  lands on a terminal `celebrationScreen` (`EOF: Login expired` / `Invalid state transition`).
  Set the whole chain from a fresh `init` and submit each step within seconds of obtaining its code.
- **`login_token` is often NOT single-use** — reuse it across submissions, and mint fresh tokens
  for the same email with no cooldown. Test that explicitly; it is a real finding when the password
  step accepts unlimited guesses per token (see the missing-control framing in `report-writing`).
- **Check anti-enumeration honestly, then say so.** Send `begin(email)` for a nonexistent address, a
  corporate address (`support@`, `admin@`, `noreply@`), and a syntactically-invalid one: the invalid
  one returns a format error while the rest return the identical next-step schema and comparable
  response timing. That is a *working control* — record it as such, it is what makes the rest of
  your report credible.

**Sibling apps behind one shell.** One host commonly ships several separately-versioned Angular
apps from a *different* CDN host — the HTML shell is your index into them:
```bash
# shell reveals app name + build date + hash: /<app>/<date>/<hash>/<app>/main.js
# e.g. auth-app, wallet-app, embedded-webview-app — each with its own runtime.js chunk map
```
Fetch each app's `runtime.js` first (it holds the chunk-name map and base path), then its chunks.
The authenticated app (wallet/dashboard) is a *different bundle* from the login app — map it once
you have a session, because that is where the money-moving endpoints live.

**CDN chunk fetches need browser-like headers.** A plain fetch of `.../<chunk>.js` may `403` while
the same URL succeeds with a normal UA + `Referer`/`Origin` of the app host + `Accept: */*`. Always
send them; a 403 on a chunk is a header problem far more often than a missing file.

---

## What "the API behind the SSO login" really means

A common, dangerous architecture:
- `console.target.com` (the SPA) → login is **Entra/Okta/Google OAuth** (looks airtight).
- `api.target.com` (the backend) → some route groups enforce the bearer token, **some route groups forgot the middleware.**

The frontend login is theatre if the API doesn't independently validate the token on every route. Always test the API directly, bare, regardless of how locked-down the login UI is.

---

## A `200` is not a bypass — read the body

The most expensive false positive in this play: a route returns `HTTP 200` and you call it an auth bypass. Many gateways answer **200 with a stub body** — an "exhausted / rate-limited / upgrade required" notice, a canned quote/template, or an error object with a friendly status. The transport succeeded; the resource was never served.

Before you believe any unauthenticated `200`:
- **`Content-Type: text/html`, or a body starting with `<!DOCTYPE` = SPA router fallback, not an endpoint.** A client-side router answers *any* path it does not recognize — including every `/api/...` path you invented — with `index.html` at `200 OK`. Strip every HTML response out of your results before counting "open" endpoints: on an SPA target this is the single largest source of false positives, and a catch-all route can also mask a genuine `401` behind a 200 shell.
- **Send a request whose correct answer you can recognize, and check the body is a real answer.** A model-gateway returning a generic fortune-cookie line for `"What is 47*89?"`, or echoing the same canned string regardless of input, is a gate, **not** a live backend. A real model/backend answers the actual question, echoes a randomised nonce you embedded, or returns input-specific data.
- **Vary the input and diff.** Same prompt 3–5× returning *different* strings is evidence of a real generator; identical output for different inputs is a stub.
- **Compare a known-gated sibling.** If the same-supposedly-open route with a *valid but exhausted* credential returns the same stub, the route is gated server-side and the "no-auth 200" is the gate answering you — not a hole.
- **A validation error is stronger evidence than a 200.** `400 "field X is mandatory"` / `"must be positive"` / `"Insufficient balance"` means your request reached business logic — that *is* the auth gap (step 4). A `200` with a stub is often the opposite: proof the check exists.

- **A gate can be credential-PRESENCE-dependent.** The same endpoint frequently branches on *whether* a credential is present: no credential → the stub is served straight from the gateway (no gate branch runs); credential present → the gate runs and returns the exhausted/limited notice. Neither branch is a bypass — the *absence* of the gate marker is still the gateway answering you. Fingerprint it with a marker that appears ONLY on the gated branch (a distinct response-`id` prefix, a `status` field, a response header): when that marker disappears but you still get a canned line instead of an input-specific answer, you have found a second stub path, not a hole.
- **Send the same credential in every auth header the stack might read, and diff.** Middleware is commonly wired to ONE header name — `Authorization: Bearer`, `x-api-key`, `api-key`, `X-Api-Key`, or a query param. The identical key can land in a *different branch* per header (gated on one, ungated on another). That inconsistency is a finding in its own right and the lead to chase if any branch performs a real call.
- **A rotating-value response is the one 200 that IS real.** If each unauthenticated call returns a *different* foreign record (new `id`/name/balance every time), the endpoint is not a stub — it is serving live data from a table with no ownership scoping. See `hunt-idor` for the unauthenticated rotating-IDOR pattern.

Rule of thumb: **for a claimed auth bypass, the proof is a correct, input-specific response from the protected resource — never the status code alone.**

---

## Anti-patterns

- **"It returned 200, so auth is missing."** Read the body — gates answer 200 with stubs. See "A `200` is not a bypass" above.
- **"The app requires login, so the API must be protected."** No — test the API directly, unauthenticated. The whole point.
- **"Minified bundle, can't read it."** You don't need to read it — grep it for hosts/routes/secrets. 5 minutes.
- **"`/api/v1/foo` returned 404, so no API here."** Wrong base or wrong method. Try `/api/`, `/api/v2/`, POST not GET, and the exact route strings from the bundle (Express's 404 echoes the path — use it to calibrate).
- **"AIza key found → critical secret."** Validate first — most are Maps/analytics keys (`CONFIGURATION_NOT_FOUND` on identitytoolkit = not Auth-enabled). Don't over-claim.
- **"Opaque token in the request body → forgeable."** Follow the call site before claiming it. If the bundle hands `itemId`/`token` straight to the generated API client with no cipher, key, or `encrypt(`/`decrypt(` in the same chunk, the value is minted and validated server-side and cannot be forged from the client — the endpoint is a mailbox, not an ATO primitive. Grep the crypto primitive first (`AES|RSA|JSEncrypt|CryptoJS|forge|subtle\.(encrypt|decrypt)`) near the call site; a service-client wrapper that merely passes the field through is proof the encryption happens on the server.
- **Dumping the whole dataset once you get a 200.** Stop at PoC. (`redteam-mindset`.)
- **Account-creation / write endpoints as "proof".** Read endpoints prove the auth gap without creating state. Never POST a `create`/`signup`/`upload` to "demonstrate" — that's a destructive write needing explicit per-action authorization.
- **Treating a `403`/`404` at the root as a dead host.** CDN and ALB edges commonly serve `403 Forbidden` (awselb/2.0, nginx) at `/` while a specific proxied path — `/graphql`, `/api/...` — returns `200`. Probe the bundle-named paths before concluding a host is dead; only an insgesamt-unreachable or DNS-fail host is dead.
- **Treating an `ErrBadRequest`/`invalid JSON` on a discovered route as "endpoint doesn't exist".** It exists and parsed your request — you have the wrong envelope. Copy the exact key names from the bundle's call site; server-driven form pipelines usually want `{<tokenKey>, formFields:{...}}` in camelCase.
- **Stopping at the login wall because the app needs 2FA.** If the auth flow is server-driven, the whole state machine (password → email OTP → SMS OTP → recovery) is plain HTTP with a schema that names every field and next-hop endpoint. Drive it with a script and an inbox, not a browser.
- **Using bundle-listed non-prod hosts only as auth-bypass pivots.** A `dev`/`preprod`/`ci` host listed in a production bundle that answers unauthenticated is its own finding (CWE-668, exposure to wrong sphere) — report the reachability, don't just mine it for weaker auth.

---

## Related Skills & Chains

- **`hunt-api-misconfig`** — once the API is mapped, run the broader misconfig matrix (method tampering, mass assignment, JWT alg confusion) per route.
- **`hunt-idor`** — the `account_id`/`order_id` pivots feed straight into IDOR testing across discovered routes.
- **`hunt-source-leak`** — sourcemaps (`*.js.map`) reconstruct original source for deeper route/secret extraction; same harvesting muscle.
- **`hunt-nextjs`** — for Next.js targets, layer the middleware-bypass (`x-middleware-subrequest`) and `/_next/data` route tests on top of this.
- **`redteam-mindset`** — the data-minimization boundary governs step 5: prove the missing check, don't exfiltrate the table.
- **`recon-scope-triage`** — verify the API host actually belongs to the target before testing (don't pop a same-named third party's API).
