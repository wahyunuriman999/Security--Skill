---
name: web2-recon
description: Web2 recon pipeline — subdomain enum, URL crawling, JS analysis, temp emails, directory fuzzing. Trust-first asset discovery.
version: 1.0.0
license: MIT
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

## HACKERONE PROGRAM INGEST — SCOPE BEFORE TOUCH

Before touching a hair off the target's head, extract its official scope. H1's
front end is a JS shell, so scraping HTML gives you nothing — the scope lives
in the public GraphQL API and needs no auth:

```bash
python3 - <<'PYEOF'
import json, urllib.request
Q = {"query": "query{team(handle:\"HANDLE\"){handle offers_bounties "
     "submission_state base_bounty structured_scopes(first:100){edges{node"
     "{asset_type asset_identifier eligible_for_bounty max_severity}}}}}}"
r = urllib.request.urlopen(urllib.request.Request(
    "https://hackerone.com/graphql", json.dumps(Q).encode(),
    {"Content-Type": "application/json"}), timeout=30)
d = json.load(r)['data']['team']
print(d['handle'], 'bounty:', d['offers_bounties'], 'base:', d['base_bounty'])
for e in d['structured_scopes']['edges']:
    n = e['node']
    print(f"{n['asset_type']:<22} {n['asset_identifier']:<45} "
          f"bounty={n['eligible_for_bounty']} sev={n['max_severity']}")
PYEOF
```

`missing a field doesn't exist` errors are benign — retry without the unknown
field, the schema still names its neighbors. Run this before ANY probe: it
yields the authoritative bounty-bearing asset list (wildcards, specific
backend hosts, mobile app IDs) that passive DNS will never surface.

---

## BASELINE CAPTURE — BEFORE PROBING PATHS

Capture a 404 control per live host before probing a single path, then treat
any non-matching status/body-hash as signal (this is hunt-dispatch's soft-404
kill rule; it applies equally to any web2 host). Record: status, byte length,
body hash, server, and the auth-relevant headers — the batch capture lives in
`scripts/probe-host.sh`.

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
