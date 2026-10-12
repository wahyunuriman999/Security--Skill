# Viral Fitness Scoring — HIV Attack Vector Prioritization System

> **Concept:** HIV fitness describes how effectively a viral strain replicates in a given host environment.  
> Here, "viral fitness" quantifies how well your current toolset and skillset matches a specific target's defensive posture — predicting the probability of successful full-lifecycle execution.

---

## Scoring Formula

### Five Fitness Dimensions

Each dimension scored **0–10** with fractional values allowed.

```
Viral Fitness Score = (R × w_R) + (E × w_E) + (P × w_P) + (M × w_M) + (D × w_D)
                      ─────────────────────────────────────────────────────────────
                                    w_R + w_E + w_P + w_M + w_D

Where:
  R = Receptor Affinity Score
  E = Evasion Score
  P = Persistence Score
  M = Mutation Score
  D = CD4 Degradation Score (detection degradation capability)

Default weights: w_R = 2.0, w_E = 1.5, w_P = 1.5, w_M = 1.0, w_D = 1.0
(Receptor affinity weighted highest — entry is the critical path)
```

---

## Dimension Definitions and Scoring Rubrics

---

### Dimension R: Receptor Affinity Score (0–10)

**Definition:** How closely does the target's exposed attack surface match your available skills and tools?  
**High score = target's auth type, tech stack, and API surface align with your strongest skills.**

| Score | Meaning |
|-------|---------|
| 9–10 | Target uses tech your skills are optimized for (e.g., JWT + GraphQL when you have hunt-jwt-crypto + hunt-graphql) |
| 7–8 | Strong match on 2+ attack surfaces |
| 5–6 | Moderate match — some skills applicable, others out of scope |
| 3–4 | Weak match — target uses tech with limited skill coverage |
| 1–2 | Poor match — almost no skill alignment |
| 0 | No applicable skills (e.g., target is a proprietary protocol with no public tooling) |

**Scoring factors:**

| Factor | +Score | -Score |
|--------|--------|--------|
| Auth type is JWT | +2 (hunt-jwt-crypto is deep) | |
| Auth type is SAML | +1.5 (hunt-saml) | |
| OAuth2 present | +1.5 (hunt-oauth) | |
| GraphQL API | +1.5 (hunt-graphql) | |
| File upload present | +1 (hunt-file-upload) | |
| IDOR surface present | +1.5 (hunt-idor) | |
| gRPC only | | -1 (less tooling) |
| Custom binary protocol | | -3 (no skill coverage) |
| No web interface | | -2 |
| Source code available | +2 (full whitebox) | |

---

### Dimension E: Evasion Score (0–10)

**Definition:** How well can you evade the target's defensive controls?  
**High score = weak WAF, no rate limiting, no behavioral detection.**

| Score | Meaning |
|-------|---------|
| 9–10 | No WAF, no IDS, no rate limiting, no MFA |
| 7–8 | WAF present but known bypassable (Cloudflare free, ModSec basic) |
| 5–6 | WAF with custom rules OR rate limiting present |
| 3–4 | WAF + rate limiting + behavioral analysis |
| 1–2 | Enterprise WAF (Akamai Kona, AWS WAF w/ managed rules) + SIEM |
| 0 | Air-gapped, hardware token required, no external surface |

**Scoring factors:**

| WAF Detected | Base Evasion Score |
|-------------|-------------------|
| None | 9 |
| Cloudflare (free) | 7 |
| Cloudflare (pro/enterprise) | 5 |
| AWS WAF | 5 |
| Akamai Kona | 4 |
| Imperva Incapsula | 4 |
| F5 BIG-IP ASM | 3 |
| Fortinet FortiWeb | 4 |
| ModSecurity (default rules) | 7 |
| ModSecurity (custom tuned) | 5 |

**Modifier factors:**

| Factor | Modifier |
|--------|----------|
| H3/QUIC bypass available (rat_h3.py tested) | +1.5 |
| Browser fingerprint bypass viable (rat_ghost.py) | +1 |
| No behavioral analysis detected | +1 |
| Rate limiting absent | +0.5 |
| Rate limit threshold > 100 req/min | +0.5 |
| CAPTCHA deployed | -1 |
| Bot score / JS challenge | -1 |
| ML-based WAF (e.g., Cloudflare Bot Management) | -2 |

---

### Dimension P: Persistence Score (0–10)

**Definition:** How many viable persistence tiers are available to this target?  
**High score = multiple independent persistence paths that survive defender response.**

| Score | Meaning |
|-------|---------|
| 9–10 | All 4 tiers available (webshell path, OAuth, CI/CD, DNS) |
| 7–8 | 3 tiers available |
| 5–6 | 2 tiers available |
| 3–4 | 1 tier available |
| 1–2 | Persistence theoretically possible but extremely difficult |
| 0 | Stateless target — no persistence possible |

**Tier availability checklist:**

| Persistence Tier | Check | Score Contribution |
|-----------------|-------|-------------------|
| **Tier 1:** Webshell / admin account | File write capability OR admin creation | +2.5 |
| **Tier 2a:** OAuth app authorization | OAuth2 flow present, user can authorize apps | +2 |
| **Tier 2b:** Subdomain takeover | Dangling DNS records found (hunt-subdomain) | +1.5 |
| **Tier 3:** CI/CD pipeline access | GitHub Actions / Jenkins / CircleCI exposed | +2.5 |
| **Tier 4:** hiv_beacon.py | Any channel for low-frequency callback | +1.5 |

---

### Dimension M: Mutation Score (0–10)

**Definition:** How many distinct payload variants can you generate against this target?  
**High score = hiv_mutator.py has many applicable mutation strategies for this target's tech stack.**

| Score | Meaning |
|-------|---------|
| 9–10 | 50+ viable payload variants, all mutation strategies applicable |
| 7–8 | 25–50 variants, most strategies applicable |
| 5–6 | 10–25 variants, some strategies blocked by WAF |
| 3–4 | < 10 variants, heavy WAF filtering |
| 1–2 | Minimal mutation space (highly restrictive input validation) |
| 0 | No injection surface (static site, no user input) |

**Scoring factors:**

| Factor | Modifier |
|--------|----------|
| Multiple injection parameters found | +2 |
| hiv_mutator.py has WAF profile for this vendor | +2 |
| Unicode bypass tested and working | +1.5 |
| Chunked encoding accepted | +1 |
| Multipart content accepted | +1 |
| JSON input accepted (more mutation space) | +1 |
| GraphQL variables (mutation-rich) | +1.5 |
| Input length unlimited | +0.5 |
| Strict input validation (length, chars) | -2 |
| No injection surface (read-only API) | -5 |

---

### Dimension D: CD4 Degradation Score (0–10)

**Definition:** How effectively can you degrade, confuse, or bypass the target's detection capability?  
**High score = their detection is weak, rule-based, and easily flooded.**  
**Named after HIV's destruction of CD4+ T-cells (the immune system).**

| Score | Meaning |
|-------|---------|
| 9–10 | No SIEM, no EDR, rule-based WAF only, no alerting |
| 7–8 | Basic SIEM, no MDR, rule-based alerts |
| 5–6 | Mature SIEM with custom rules, some SOC coverage |
| 3–4 | 24/7 SOC, MDR, behavioral analytics |
| 1–2 | Enterprise MDR + threat hunting + deception tech |
| 0 | NSA-tier detection (air-gapped classified system) |

**Scoring factors:**

| Factor | Modifier |
|--------|----------|
| hiv_cd4_flood.py false-positive flood viable | +2 |
| Alert volume already high (noisy environment) | +1.5 |
| No after-hours SOC coverage | +1 |
| Rule-based SIEM (not ML-based) | +1 |
| Rate limit threshold allows flood volume | +1 |
| Honeypots/deception tech detected | -2 |
| ML-based detection (Darktrace, Vectra) | -2 |
| 24/7 MDR service (CrowdStrike Falcon Complete) | -3 |
| Insider threat program | -1 |

---

## Viral Fitness Decision Thresholds

```
Viral Fitness Score (VFS) →

VFS > 7.0  → FULL HIV LIFECYCLE
             Execute all 6 stages
             Deploy all persistence tiers
             High probability of success
             Recommended: comprehensive engagement

VFS 4.0–7.0 → SELECTIVE STAGES
              Execute Stages 1, 2, 3 only
              Assess persistence viability before Stage 4
              Selective attack vector focus
              Recommended: targeted exploitation, no full persistence

VFS < 4.0  → SKIP TARGET
              Target's defenses exceed current toolset capability
              Cost-benefit: not worth engagement
              Alternative: reconnaissance only, no active exploitation
              OR: wait for new tools/skills before engaging
```

---

## Scoring Worksheet

```markdown
## Viral Fitness Assessment: [TARGET NAME]
**Date:** [DATE]
**Assessor:** [NAME]

### Reconnaissance Summary
- Target URL: 
- Auth type: 
- WAF detected: 
- Tech stack: 
- API surface: 

### Dimension Scores

| Dimension | Raw Score (0-10) | Weight | Weighted |
|-----------|-----------------|--------|----------|
| R: Receptor Affinity | ___ | 2.0 | ___ |
| E: Evasion | ___ | 1.5 | ___ |
| P: Persistence | ___ | 1.5 | ___ |
| M: Mutation | ___ | 1.0 | ___ |
| D: CD4 Degradation | ___ | 1.0 | ___ |
| **TOTAL WEIGHTED** | | **7.0** | ___ |

**Viral Fitness Score (VFS) = Total Weighted / 7.0 = ___**

### Decision
- [ ] VFS > 7.0 → Full lifecycle
- [ ] VFS 4.0-7.0 → Selective stages
- [ ] VFS < 4.0 → Skip

### Stage Plan (if proceeding)
- Stage 1 tools: 
- Stage 2 receptor type: 
- Stage 3 mutation strategy: 
- Stage 4 persistence tiers: 
- Stage 5 infra targets: 
- Stage 6 lateral targets: 
```

---

## Scored Example Targets

### Example 1: Cloudflare-Protected Web Application

**Target profile:** SaaS app behind Cloudflare Enterprise, JWT auth, REST API, React SPA, no file upload.

| Dimension | Score | Justification |
|-----------|-------|---------------|
| R: Receptor Affinity | 7.5 | JWT (hunt-jwt-crypto +2), REST API (hunt-shadow-api +1.5), React SPA (hunt-spa-api +1.5), no file upload (-1) |
| E: Evasion | 5.5 | Cloudflare Enterprise base (5), rat_h3.py QUIC bypass viable (+1.5), Bot Management active (-1) |
| P: Persistence | 6.0 | OAuth2 present (Tier 2a, +2), no CI/CD exposed (-), subdomain candidates found (+1.5), hiv_beacon.py viable (+1.5) |
| M: Mutation | 6.0 | JWT has rich mutation space (hiv_mutator.py), WAF profile available for CF (+2), JSON input (+1), CF blocks many variants (-2) |
| D: CD4 Degradation | 5.5 | Basic SIEM assumed (+2), hiv_cd4_flood.py viable (+2), CF Bot Management limits flood (-1), no MDR confirmed |

```
VFS = (7.5×2 + 5.5×1.5 + 6.0×1.5 + 6.0×1.0 + 5.5×1.0) / 7.0
    = (15.0 + 8.25 + 9.0 + 6.0 + 5.5) / 7.0
    = 43.75 / 7.0
    = 6.25
```

**Decision: SELECTIVE STAGES (4.0–7.0)**  
**Plan:** Execute Stages 1–3. Focus on JWT attacks with hiv_mutator.py + H3 delivery. Assess Tier 2 OAuth persistence before committing to full lifecycle. Skip aggressive Stage 5-6 without confirmed persistence.

---

### Example 2: AWS API Gateway (Serverless)

**Target profile:** AWS API Gateway + Lambda, API key auth, REST API, no WAF (API Gateway only), high rate limits.

| Dimension | Score | Justification |
|-----------|-------|---------------|
| R: Receptor Affinity | 6.5 | API key auth (hunt-auth-bypass +1.5), REST API (+1), Lambda functions = injection potential (hunt-ssrf +1.5), cloud-iam-deep applicable (+2) |
| E: Evasion | 7.0 | No WAF (base 9), API Gateway throttling present (-1), no behavioral detection (-0), H3 not applicable to API GW (-1) |
| P: Persistence | 7.5 | IAM role chaining (cloud-iam-deep Tier 1, +2.5), Lambda layer injection (Tier 3 equivalent, +2.5), API key persistence (Tier 2, +2) |
| M: Mutation | 5.5 | API key manipulation limited, injection via Lambda env vars (+1), JSON body mutations (+1), strict schema validation (-2) |
| D: CD4 Degradation | 6.0 | CloudWatch basic alerting (+2), no SOC (+1), CloudTrail logs everything but rule-based (-0), hiv_cd4_flood.py viable for CloudWatch alert flooding (+2), AWS GuardDuty may be present (-1) |

```
VFS = (6.5×2 + 7.0×1.5 + 7.5×1.5 + 5.5×1.0 + 6.0×1.0) / 7.0
    = (13.0 + 10.5 + 11.25 + 5.5 + 6.0) / 7.0
    = 46.25 / 7.0
    = 6.61
```

**Decision: SELECTIVE STAGES — borderline (4.0–7.0, near upper threshold)**  
**Plan:** Strong cloud-iam-deep opportunity. Execute Stages 1–4 with focus on IAM lateral movement. The IAM persistence path (Tier 1/3 equivalent) makes this worth committing through Stage 6. cloud-iam-deep workflow is the primary value here.

---

### Example 3: Internal Admin Panel (No WAF)

**Target profile:** Internal admin panel, session cookie auth, PHP/MySQL, file upload present, no WAF, accessible via VPN or SSRF pivot.

| Dimension | Score | Justification |
|-----------|-------|---------------|
| R: Receptor Affinity | 9.0 | Session auth (hunt-session +1), PHP = RCE potential (hunt-rce +2), MySQL = SQLi (hunt-sqli +2), file upload (hunt-file-upload +2), admin panel = rich IDOR surface (hunt-idor +1.5) |
| E: Evasion | 9.5 | No WAF (base 9), no rate limiting (+0.5), internal target = minimal external security controls |
| P: Persistence | 8.5 | File upload = webshell (Tier 1, +2.5), admin account creation (Tier 1 backup, +2), internal CI/CD likely accessible (Tier 3, +2), hiv_beacon.py viable (+1.5) |
| M: Mutation | 8.5 | No WAF = no filtering (+3), PHP accepts all payload types (+2), file upload = webshell variants (+2), MySQL = full SQLi arsenal (+1.5) |
| D: CD4 Degradation | 8.0 | Internal system — likely no SIEM (+3), no external monitoring (+2), hiv_cd4_flood.py not needed but available, no behavioral analysis (+2) |

```
VFS = (9.0×2 + 9.5×1.5 + 8.5×1.5 + 8.5×1.0 + 8.0×1.0) / 7.0
    = (18.0 + 14.25 + 12.75 + 8.5 + 8.0) / 7.0
    = 61.5 / 7.0
    = 8.79
```

**Decision: FULL HIV LIFECYCLE (VFS > 7.0)**  
**Plan:** All 6 stages. Priority order: SQLi for data access → file upload for webshell (Tier 1 persistence) → admin account creation (Tier 1 backup) → internal network pivot via SSRF (Stage 5) → lateral to other internal systems (Stage 6). High confidence engagement.

---

### Example 4: GraphQL API (Modern Stack)

**Target profile:** GraphQL API, JWT auth, Node.js/TypeScript, Cloudflare free tier, no file upload, introspection enabled.

| Dimension | Score | Justification |
|-----------|-------|---------------|
| R: Receptor Affinity | 9.0 | GraphQL (hunt-graphql +1.5, introspection enabled = full schema), JWT (hunt-jwt-crypto +2), Node.js (hunt-nodejs +1.5), React frontend (hunt-spa-api +1, hunt-dom +1) |
| E: Evasion | 7.5 | Cloudflare free (base 7), H3 QUIC bypass viable (+1.5), no Bot Management (+1), basic rules only |
| P: Persistence | 6.5 | OAuth apps likely (Tier 2a, +2), subdomain check needed, no CI/CD visible yet, hiv_beacon.py viable (+1.5), JWT persistence via long-lived tokens (+1.5) |
| M: Mutation | 8.0 | GraphQL has very rich mutation space (variables, aliases, fragments, batching), hiv_mutator.py GraphQL mode (+2), CF free doesn't block complex GQL (+2), JWT alg variations (+2) |
| D: CD4 Degradation | 6.5 | Startup likely — no SIEM (+2.5), CF provides some logging (+0), hiv_cd4_flood.py GraphQL batching abuse viable as flood vector (+2), no MDR assumed |

```
VFS = (9.0×2 + 7.5×1.5 + 6.5×1.5 + 8.0×1.0 + 6.5×1.0) / 7.0
    = (18.0 + 11.25 + 9.75 + 8.0 + 6.5) / 7.0
    = 53.5 / 7.0
    = 7.64
```

**Decision: FULL HIV LIFECYCLE (VFS > 7.0)**  
**Plan:** All 6 stages. GraphQL introspection gives complete attack surface. Stage 2: JWT attacks (hunt-jwt-crypto) + GraphQL batching (hunt-graphql). Stage 3: hiv_mutator.py GraphQL mode. CD4 degradation: hiv_cd4_flood.py using GraphQL batch queries (each query = hundreds of operations = SIEM alert flood). High confidence, strong mutation space.

---

## Score Comparison Summary

| Target | VFS | Decision | Primary Attack Vector |
|--------|-----|----------|----------------------|
| Cloudflare Enterprise SaaS | 6.25 | Selective | JWT → hunt-jwt-crypto + rat_h3.py |
| AWS API Gateway | 6.61 | Selective | IAM pivot → cloud-iam-deep |
| Internal Admin Panel | 8.79 | Full lifecycle | SQLi + file upload → hunt-sqli + hunt-file-upload |
| GraphQL API | 7.64 | Full lifecycle | GQL introspection + JWT → hunt-graphql + hunt-jwt-crypto |

---

## Quick Assessment Checklist

Run this in Stage 1 output processing to get preliminary VFS:

```bash
# Parse Stage 1 receptor map into VFS calculator
cat stage1_surface.json | python -c "
import json, sys
data = json.load(sys.stdin)

r = 5.0  # baseline
if 'jwt' in data.get('auth_receptors', []): r += 2
if 'oauth2' in data.get('auth_receptors', []): r += 1.5
if 'saml' in data.get('auth_receptors', []): r += 1.5
if data.get('api_surface', {}).get('graphql', 0) > 0: r += 1.5
if data.get('source_leaks'): r += 2

e = {'none': 9, 'cloudflare': 7, 'cloudflare-enterprise': 5,
     'aws-waf': 5, 'akamai': 4, 'imperva': 4}.get(
     data.get('waf', {}).get('vendor', 'none'), 6)

print(f'Preliminary R={min(r,10):.1f}, E={e:.1f}')
print(f'Complete P, M, D scores manually.')
print(f'Estimated VFS (R+E only): {(min(r,10)*2 + e*1.5)/3.5:.2f}')
"
```

---

## VFS Over Time

Viral fitness is **not static**. Re-score after each of these events:

| Event | Re-score because... |
|-------|---------------------|
| WAF vendor upgrade | E score likely drops 1-3 points |
| New tools deployed (hiv_*) | M and D scores increase |
| New skills added | R score increases |
| Persistence established | P score locks in (mission continues regardless) |
| Post-patch re-engagement | R score may drop (patched receptors), new receptors may appear |
| IR engagement concluded | D score increases (SOC returns to baseline) |

---

*Viral Fitness Scoring v1.0*  
*HIV Framework — Attack Vector Prioritization System*
