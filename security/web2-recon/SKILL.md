---
name: web2-recon
description: Web2 recon pipeline — subdomain enum, URL crawling, JS analysis, temp emails, directory fuzzing. Trust-first asset discovery.
---

# WEB2 RECON — Trust-First Asset Discovery

Map the attack surface before hunting. Every endpoint is a trust boundary. Find them all.

See also: [[BountyForge]], [[Trust Map]], [[Methodology]], [[Vuln Classes]], [[3rd Eye]]

---

## TEMP EMAIL SETUP (Essential for Auth Testing)

```bash
# Mail.tm API (free, programmatic)
for i in 1 2 3; do
  DOMAIN=$(curl -s https://api.mail.tm/domains | jq -r '.[0].domain')
  EMAIL="hunter${i}_$(date +%s)@${DOMAIN}"
  PASSWORD="HuntPass${i}!"
  curl -s -X POST https://api.mail.tm/accounts \
    -H "Content-Type: application/json" \
    -d "{\"address\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" > /dev/null
  echo "Account $i: $EMAIL / $PASSWORD"
done
```

---

## STANDARD RECON PIPELINE

```bash
TARGET="target.com"
RECON_DIR="recon/$TARGET"
mkdir -p $RECON_DIR

# 1. Passive subdomain enum
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > /tmp/subs.txt

# 2. Multi-source (Chaos API + subfaster)
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" | jq -r '.[]' >> /tmp/subs.txt
subfaster -d $TARGET -silent | anew /tmp/subs.txt

# 3. DNS + live check
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/live.txt

# 4. URL crawl
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew /tmp/urls.txt
echo $TARGET | waybackurls | anew /tmp/urls.txt
gau $TARGET --subs | anew /tmp/urls.txt

# 5. Nuclei
nuclei -l /tmp/live.txt -t ~/nuclei-templates/ -severity critical,high,medium -o /tmp/nuclei.txt

# 6. Save to organized directory
cp /tmp/subs.txt $RECON_DIR/subdomains.txt
cp /tmp/live.txt $RECON_DIR/live-hosts.txt
cp /tmp/urls.txt $RECON_DIR/urls.txt
cp /tmp/nuclei.txt $RECON_DIR/nuclei.txt
```

---

## SUBDOMAIN ENUM — TOOLS MISSING? RESOLVE, DRIVE, SURFACE

Probe the toolbox FIRST and branch on what exists. Missing tools is a setup
state, not a dead end — record the fix, keep hunting.

```bash
for t in curl dig nslookup ffuf nuclei httpx dnsx subfinder jq python3; do
  printf '%-10s ' "$t"; command -v "$t" || echo MISSING
done
```

When `crt.sh` is unreachable and the ProjectDiscovery/Chaos API needs a key,
drop to the stdlib brute-forcer — resolve via socket first (kills ~90% of the
wordlist cheaply), then HTTP-probe only what resolves:

```bash
python3 scripts/subs-brute.py target.com words.txt
```

This produced live hosts on a cold target where every passive source was dead.
`scripts/subs-brute.py` ships with this skill; reuse it, don't rewrite it.

---

## HTTP/ENUMERATION WITHOUT curl — WHEN THE CLI IS UNRELIABLE

On some rigs `curl` fails mid-request (`client returned ERROR on write`) while the
same URL returns HTTP 200 from Python, and the local resolver returns wrong or
empty answers for external names. Both are rig state, not target behaviour —
switch transport, do not record them as findings:

```python
import urllib.request, ssl, json, concurrent.futures as cf
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120"

def doh(name):  # authoritative resolution, bypasses the local resolver
    j = json.loads(urllib.request.urlopen(urllib.request.Request(
        f"https://dns.google/resolve?name={name}&type=A",
        headers={"User-Agent": UA}), timeout=8, context=ctx).read())
    return [a["data"] for a in j.get("Answer", []) if a.get("type") == 1]
```

**Never pass the header dict positionally to `Request(url, {...})`.** The second
positional argument of `urllib.request.Request` is `data`, so the headers are
silently dropped, every UA-stripped request looks like a UA-rotation verdict,
and a CDN answers the bot challenge instead of the origin. Always
`Request(url, headers={...})`. The same trap applies to exception paths that
store `str(ex)` in the variable later read as bytes — coerce to bytes at the
boundary or a mid-run `TypeError` wastes the call (see Scripting hygiene below).

Batch DNS through a 60–100 worker `ThreadPoolExecutor`; a 5460-name brute across
30 base domains resolves in ~15 s this way. Passive sources that time out
(`crt.sh` under load, `anubis`, `omnisint`) — drop them from the loop instead of
letting one dead source stall the whole enumeration; hackertarget, rapiddns and
the Wayback CDX API survive long cold runs.

### CONNECTING TO A DoH-RESOLVED IP WITHOUT LOSING SNI

Once you hold the IPs yourself, the naive `http.client.HTTPSConnection(ip, 443)`
fails with `SSLV3_ALERT_HANDSHAKE_FAILURE` — an IP has no name, so no SNI is
sent and CDNs that need it refuse the handshake. Open the socket yourself and
wrap it with the hostname:

```python
import socket, ssl
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection((ip, 443), timeout=12)
tls = ctx.wrap_socket(sock, server_hostname=host)   # <-- SNI restored
tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n...\r\n\r\n".encode())
```

**Never leave a `socket.getaddrinfo` monkeypatch alive in a persistent kernel.**
The patch closes over itself, so the next call — including the DoH fetch that
feeds it — recurses until `RecursionError`. Either restore it
(`socket.getaddrinfo = _socket.getaddrinfo`) in a `finally`, or skip patching
entirely and use the wrap-socket form above, which needs no resolver change.

### UNUTHENTICATED ENUMERATION UNDER A CDN — THROTTLE, AND CLASSIFY THE WALL

Slow field/schema enumeration by hand is the fastest way to trip the edge rate
limiter (Cloudflare `error code: 1015`), which then poisons every later probe
with 429s and hides real signal. Sleep 3–8 s between probes when walking an
unauthenticated schema, and record a 1015/429 as edge state — it is not a finding
and it is not the target's behaviour. When the limiter has already tripped, stop
and wait rather than pressing; a probe answered through a tripped limiter tells
you nothing about the application.

Header path-rewrite probes (`X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`,
`X-Forwarded-For`, `X-User-Id`, `Authorization: Bearer null`) are worth one
burst each — but classify the result by body signature, not status code. A
proxied request that comes back as an edge block page (`Just a moment...`, vendor
banner, `error code: 1015`) is the wall answering, not the application decision
about your header. Only a response carrying the app's own branding and shape
means the header reached the handler.

## MULTI-HOST SWEEP — READ THE FALSE-POSITIVE RULES FIRST

Sweeping hundreds of subdomains with a status-code filter manufactures findings
that do not exist. The traps, in the order they bite: SPA catch-alls, Cloudflare
interstitials, and auth-designed-by-default endpoints. Read
`references/multi-host-sweep-pitfalls.md` before running a wide sweep — it also
covers when a wide sweep is the wrong tool entirely.

**Long-running sweeps: run them backgrounded.** A single script that walks every
host and path with per-probe timeouts routinely exceeds a foreground limit, and
a timeout kills the whole run. Write output to a file, start it with
`background=true, notify=true`, and keep working while it runs; poll with
`process(action="wait")` only when you genuinely need the result, and bail to
other work when the wait window closes. Batch each sub-procedure (navigate,
probe, extract) into one call rather than one call per action.

---

## FINGERPRINTING A HOST — READ THE VERSION HONESTLY

Pinning the exact product version is a recon step, not an exploit: banners,
header sets, page bodies, stylesheets, JS bundles, favicon hashes, and any
unauthenticated config endpoint. When the version cannot be obtained, say so
plainly — a recorded negative beats a guessed build.

**Method, in order:** response headers (`Server`, `X-Powered-By`,
`X-AspNet-Version`), page body strings and build markers, linked CSS/bundle for
version literals, favicon md5/sha256/murmur3, then any config endpoint the SPA
reveals. Record every negative source too — it is what lets a CVE candidate be
scored as *informational* instead of claimed.

A serving stack often gives itself away in a doc or error path
(`/docs/`, `/docs/config/`, `/docs/RELEASE-NOTES.txt`, `/docs/changelog.html`).
On a default Tomcat install the changelog even names the CVEs that version is
exposed to — read it, then verify each candidate's reachability before writing
it up.

---

## SELF-SERVICE TEST ACCOUNTS — WHEN UNAUTHENTICATED SURFACE IS EXHAUSTED

When every bounty-bearing asset you own has been swept and nothing is
reportable, the remaining value is authenticated application logic, which
requires an account. Before asking a program for credentials — or grimly
probing unauthenticated surface forever — check whether the program lets you
self-provision. Several high-value programs (Shopify $500 base, Vercel, GitLab)
publish signup paths that hand the bug-bounty tester their own sandbox
directly, and need no permission request at all.

**Procedure:**
1. Pull the program's `structured_scopes.instruction` via the HackerOne GraphQL
   block above — it states the self-service account policy (or its absence).
2. If self-service is offered, build the accounts with a self-owned identity
   (the platform's own alias/multi-account mechanism) so multiple permission
   tiers can be provisioned without extra platform profiles.
3. Record the stated hard rules before testing: only self-created assets, no
   contacting support as part of testing, no public pre-disclosure. Violating
   these disqualifies the whole account.
4. Once store/project exists, the deep testing is **API-token driven, not
   browser driven** — one human login, then the machine takes over. An API token
   reaches endpoints and generates objects at a scale no UI automation matches.

**Pitfall:** do not attempt to automate the signup/login flow itself. Browser
bot-gates (Turnstile, hCaptcha) are built specifically to detect automation;
defeating one from the very account you later submit from can get that account
banned before the first finding. Email verification links are also
receive-only by architecture — they can only be opened from the account owner's
inbox, so the machine cannot complete registration even in principle. Treat
"automate the whole signup" as a dead end and budget one human step instead.


---

## HACKERONE PROGRAM INGEST — SCOPE BEFORE TOUCH

Before touching a hair off the target's head, extract its official scope. H1's
front end is a JS shell, so scraping HTML gives you nothing — the scope lives
in the public GraphQL API and needs no auth:

```bash
python3 - <<'PYEOF'
import json, urllib.request
Q = {"query": "query{team(handle:\"HANDLE\"){handle offers_bounties "
     "submission_state base_bounty structured_scopes(first:100){edges{node"
     "{asset_type asset_identifier instruction eligible_for_bounty "
     "max_severity}}}}}}"
r = urllib.request.urlopen(urllib.request.Request(
    "https://hackerone.com/graphql", json.dumps(Q).encode(),
    {"Content-Type": "application/json"}), timeout=30)
d = json.load(r)['data']['team']
print(d['handle'], 'bounty:', d['offers_bounties'], 'base:', d['base_bounty'])
for e in d['structured_scopes']['edges']:
    n = e['node']
    print(f"{n['asset_type']:<22} {n['asset_identifier']:<45} "
          f"bounty={n['eligible_for_bounty']} sev={n['max_severity']}")
    if n.get('instruction'):
        print('  instruction:', n['instruction'][:400].replace('\n', ' | '))
PYEOF
```

`missing a field doesn't exist` errors are benign — retry without the unknown
field, the schema still names its neighbors. Run this before ANY probe: it
yields the authoritative bounty-bearing asset list (wildcards, specific
backend hosts, mobile app IDs) that passive DNS will never surface.

## BRIEF-FIRST PROGRAMS — READ THE ATTACHED PAGE, NOT JUST THE API

Bugcrowd and similar platforms deliver the engagement as a page the user
attaches to the conversation. That page **is** the scope document — asset
lists per group, the payout tiers, the out-of-scope block, and the excluded
submission types (typically: no availability attacks, no data extraction, no
actual exploitation or pivoting until approved).

**Workflow:**
1. Parse the attached brief first and reconstruct the scope table from it:
   in-scope hosts/IPs, out-of-scope names, and the excluded-submission rules.
   The out-of-scope list routinely names specific subdomains and affiliated
   brands — anything not on the in-scope list is untouchable.
2. Separate live testing from write-up: where the brief says "report the
   finding but do not actually test until approved", run the identification
   pass (versions, ports, headers, endpoints) and stop short of the exploit.
   Record the CVE candidate with reachability evidence and a verdict of
   *pending verification* rather than claiming impact.
3. Network-testing scope is per-asset: an IP group marked Network Testing
   licenses a port sweep on those IPs, and the same sweep is out of scope on
   hosts that only allow Website Testing.
4. Write each candidate through the 4-Question Gate before it enters a report
   (real / unauthenticated / impact / actionable). An endpoint that only
   publishes deployment shape belongs in the report as a Low with its exact
   evidence, not padded into an RCE claim.
5. When a compiled version/build cannot be obtained from the anonymous
   surface, record that as a **negative result** — it closes the CVE candidate
   honestly and is the finding of record.

## READ THE SCOPE `instruction` FIELD — IT IS THE TASKING

`structured_scopes.instruction` is not decoration. It states what the program
wants attacked, what they will refuse to pay for, and the exact report format
they require. Extract it with the scope and probe from that list:

- Tasking lines ("pass the two authentications", "bypass the upload") tell you
  which surface to spend the session on.
- Refusal lines ("business logic out of scope", "HTML+JS alone is not a
  vulnerability") tell you which findings will bounce no matter how well
  written — do not build a report on them.
- Format lines name the required report body fields and any mandatory
  artifact (screen recording). Reuse those headings verbatim in the report.

---

## BASELINE CAPTURE — BEFORE PROBING PATHS

Capture a 404 control per live host before probing a single path, then treat
any non-matching status/body-hash as signal (this is hunt-dispatch's soft-404
kill rule; it applies equally to any web2 host). Record: status, byte length,
body hash, server, and the auth-relevant headers — the batch capture lives in
`scripts/probe-host.sh`.

## EDGE-BLOCK VS APP-REJECT — FINGERPRINT THE MIDDLEBOX

Targets behind a vendor WAF/CDN answer from the edge with their own page, and
that page returns HTTP **200** as often as 403 — status code proves nothing.
Classify by body signature instead:

- **Block page:** small and fixed (~2.4–2.7 KB typical), a `<title>` echoing
  the request host plus the vendor name, a fixed marker sentence, an
  incident/transaction ID, your egress IP printed back, a countdown timer.
- **App page:** the product's own branding, dynamic length, content that
  varies per input.

Capture both signatures in the baseline, then classify every later probe by
signature. The pair doubles as an oracle: a form endpoint returning the app
page for one input and the block page for another is publishing the edge
filter's rule set — the cheapest way to map a hidden allow-list (upload
extensions, banned parameter names, blocked keywords) without ever reaching
the application. Recipe and the classifier gotcha: `references/edge-filter-mapping.md`.


### INVARIANT ERROR STRING = EDGE RULE, NOT A SCHEMA PROBLEM

When a write endpoint answers with the **same** error string for a deliberately
empty body, a minimal valid body, and every field-shape variant you can invent
— *and* a `GET` on the same route with the same credential returns `200` — stop
varying the payload. An application binder names the missing or malformed field
it wanted; a message that never changes across payloads is the middlebox
rejecting the request before the handler exists. Confirm by sending a body that
is not even valid JSON: if that produces the *same* string, the app never saw it.

The cost of missing this is real — payload-shape guessing against an edge rule
looks like progress on every attempt and burns a whole session. Record "writes
to this surface are blocked at the edge for session auth" and route around it
(different verb path, token vs cookie auth, sibling route, subdomain) instead of
iterating shapes.

**Scripting hygiene:** coerce every fetched body to bytes at the boundary
(`if not isinstance(body, bytes): body = body.encode()`) before any `in` test
or regex — exception paths that store `str(ex)` in the same variable otherwise
raise `TypeError` mid-run and waste a call.

---

## TRUST BOUNDARY DISCOVERY

These are the endpoints that matter most — where the system trusts something:

```bash
# ID parameters → IDOR candidates (identity trust)
cat /tmp/urls.txt | grep -E "[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=" | tee /tmp/idor-candidates.txt

# API endpoints → injection candidates (input trust)
cat /tmp/urls.txt | grep -E "/api/|/v1/|/v2/|/graphql|/rest/" | tee /tmp/api-endpoints.txt

# Auth endpoints → bypass candidates (identity trust)
cat /tmp/urls.txt | grep -E "/oauth|/login|/auth|/sso|/saml|/token" | tee /tmp/auth-paths.txt

# Admin/debug → privesc candidates (authority trust)
cat /tmp/urls.txt | grep -E "/admin|/internal|/debug|/actuator|/console" | tee /tmp/admin-paths.txt

# File upload → XSS/RCE candidates (input trust)
cat /tmp/urls.txt | grep -E "upload|file|attachment|document|image|avatar" | tee /tmp/upload-candidates.txt

# SSRF candidates (service trust)
cat /tmp/urls.txt | grep -E "webhook|import|export|pdf|generate|fetch|proxy" | tee /tmp/ssrf-candidates.txt

# SQLi candidates (input trust)
cat /tmp/urls.txt | grep -E "search|filter|sort|order|where|query|list" | tee /tmp/sqli-candidates.txt

# Sensitive paths (state trust)
cat /tmp/urls.txt | grep -E "\.env|\.git|config|backup|dump|export|download|log" | tee /tmp/sensitive-paths.txt
```

Build the full trust graph: [[Trust Map]]

---

## JS ANALYSIS — Where Hidden Bugs Live

On minified bundles the framework's own router tables and environment
constants survive the minifier even when operation names do not. Mine them
first; a route map doubles as a curl wordlist:

```bash
# router tables: CONST:"/path/:param" objects
python3 - <<'PYEOF'
import re
s = open('bundle.js', encoding='utf-8', errors='ignore').read()
for k, v in re.findall(r'([A-Z0-9_]{4,}):"(/[^"]+)"', s):
    print(f"{k} = {v}")
PYEOF
# environment literals: api.dev.*, api.stage.*, *.local.*
grep -aoE '[a-z0-9-]+\.(dev\.|stage\.|local\.|private\.|preprod\.|test\.)[a-z0-9.-]+' bundle.js | sort -u
# frontend API base paths, /vN routes, graphql endpoints
grep -aoE '"/(api|v[0-9]|graphql)[a-zA-Z0-9/_.:-]*"' bundle.js | sort -u
```

**Also harvest the login page's own asset references.** The bundle is not the
only route source: a login or landing page links its stylesheet, logo, and any
registration/password-reset SPA, and those references name real paths
(`/Web/Account/Login.htm`, `/Web/Shadowfax/reg/register.html`) that a
path-list sweep never produces. Fetch the page, extract `src`/`href`, and
recurse one level — the second-level SPA's bundle is where the live API routes
hide (Angular apps ship them inside route literals such as
`/user/v1/anonymous-config`, `/mfa/methods`, `/workspaces/v1/passcodeActivation`).

On an Angular bundle, grep the whole file (1–2 MB is normal) for the
**verbatim route literals**, not the concatenated API base — the SPA builds
paths from a base constant that only appears once, and the individual segments
are the reusable probes:

```bash
# route-ish literals from a minified Angular bundle
grep -aoE '["'"'`]/[a-z][A-Za-z0-9_/-]{3,50}["'"'`]' main-*.js | sort -u \
  | grep -Ei 'api|user|pass|token|auth|register|verify|email|invite|org|session|mfa|otp'
```

**Every route the SPA names is a probe target — probe it unauthenticated before
assuming it is gated.** A well-behaved app returns 401 on `/user/v1/config` and
still answers 200 on `/user/v1/anonymous-config`; the anonymous endpoint exists
for the pre-login render and discloses deployment configuration
(`isRunningAsCloudSaaS`, password policy, ToS state). That is a real Low.

**Then repeat the harvest WITH the session, as a bulk route table.** Dump every
bundle, regex out the two families a SPA always hardcodes — its own
`/internal/…` surface and the versioned `/api/…` surface — dedupe, and probe each
path with the authenticated cookie, recording one line per route (method, path,
status, byte length). Highest-leverage single pass on an authenticated target: it
surfaces endpoint families the UI never links, and the rows that matter are the
ones whose status disagrees with their siblings.

```python
import re, glob
routes = set()
for f in glob.glob('*.js'):
    s = open(f, encoding='utf-8', errors='ignore').read()
    routes |= set(re.findall(r'(?:/internal|/api/v2)/[A-Za-z0-9\-_/{}$.:]+', s))
for r in sorted(routes):
    print(r)   # keep {param} placeholders; substitute a real id/key when probing
```

Read **status clusters**, not individual codes: a long run of `403`/`404` with a
few `200`/`204`/`201` marks the live surface, and every `200` on a route the UI
never calls is a finding candidate. `405` means alive-but-wrong-verb — re-probe
with `POST`/`PATCH` before filing it absent. A route that rejects `{}` with a
*field-specific* message is reachable, so shape-guess there; a route that rejects
every shape with the same string is an edge rule (see above). Any route with a
placeholder segment is an IDOR candidate the moment it accepts an id you do not
own.

**An inconsistent verb-answer boundary is its own finding.** When `GET` on a
path returns 200 and `HEAD`/`OPTIONS` on the same path return 401, the auth
filter is bound to a method list rather than the route namespace. Record the
verb matrix per endpoint; a mismatch is a defect to report alongside whatever
the endpoint discloses.

Env-host literals found this way are a finding in their own right: an
unreferenced dev/stage origin responding like production is exposed attack
surface, and a static-assets host that mirrors prod lives in the JS too.
Other techniques follow the original pipeline below.

```bash
mkdir -p /tmp/js-deep
cat /tmp/urls.txt | grep "\.js$" | sort -u | head -100 | while read url; do
  fname=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -s "$url" -o "/tmp/js-deep/$fname" 2>/dev/null
done

# API calls → endpoints the frontend trusts
grep -rn "fetch(\|axios\.\|\.get(\|\.post(\|\.put(\|\.delete(" /tmp/js-deep/ | tee /tmp/js-api-calls.txt

# Auth code → tokens, cookies, headers
grep -rn "Authorization\|Bearer\|token\|cookie\|session\|localStorage" /tmp/js-deep/ | tee /tmp/js-auth-code.txt

# Secrets → hardcoded keys
grep -rn "api_key\|apiKey\|client_secret\|access_token\|private_key\|AKIA\|sk_live" /tmp/js-deep/ | tee /tmp/js-secrets.txt

# Dangerous sinks → XSS/SSRF vectors
grep -rn "innerHTML\|outerHTML\|document\.write\|eval(\|dangerouslySetInnerHTML" /tmp/js-deep/ | tee /tmp/js-dangerous-sinks.txt

# postMessage → DOM XSS vectors
grep -rn "postMessage\|addEventListener.*message\|onmessage" /tmp/js-deep/ | tee /tmp/js-postmessage.txt

# URL construction → SSRF vectors
grep -rn "new URL\|location\.href\|location\.assign\|location\.replace" /tmp/js-deep/ | tee /tmp/js-url-construction.txt
```

---

## DIRECTORY FUZZING

```bash
# Standard directory discovery
ffuf -u "https://target.com/FUZZ" \
     -w ~/wordlists/common.txt \
     -mc 200,201,204,301,302,401,403 \
     -ac -t 40 -o /tmp/ffuf-dirs.json

# API endpoint discovery
ffuf -u "https://target.com/api/FUZZ" \
     -w ~/wordlists/api-endpoints.txt \
     -mc 200,201,204,301,302 -ac -t 20

# Backup files
ffuf -u "https://target.com/FUZZ" \
     -w ~/wordlists/common.txt \
     -e .bak,.old,.orig,.save,.swp,.tmp,.backup \
     -mc 200 -ac
```

---

## TECH STACK → BUG CLASS MAP

| Stack | Hunt First | Hunt Second |
|-------|------------|-------------|
| Ruby on Rails | Mass assignment | IDOR |
| Django | IDOR | SSTI |
| Flask | SSTI | SSRF |
| Laravel | Mass assignment | IDOR |
| Express | Prototype pollution | Path traversal |
| Spring Boot | Actuator endpoints | SSTI |
| ASP.NET | ViewState deser | Open redirect |
| Next.js | SSRF via Server Actions | Open redirect |
| GraphQL | Introspection → auth bypass | IDOR via node(id:) |
| WordPress | Plugin SQLi | REST API auth bypass |

More bug classes: [[Vuln Classes]]

---

## 5-MINUTE RULE

If a target shows nothing interesting after 5 minutes, move on. Don't burn hours on dead surface.

**Kill signals:** All 403/static pages, no APIs, no interesting JS, no forms/auth/user data.

---

## TARGET SCORING

| Criterion | Points |
|-----------|--------|
| Max bounty >= $5K | +2 |
| Large user base or handles money | +2 |
| Program launched < 60 days | +2 |
| Complex features (API, OAuth, GraphQL) | +1 |
| Recent code changes | +1 |
| Private program | +1 |
| Tech stack you know | +1 |
| Source code available | +1 |

**< 4:** Skip | **4-5:** If nothing better | **6-8:** 1-3 days | **>= 9:** Up to 1 week

Next step: [[Trust Map]] → [[Methodology]]
