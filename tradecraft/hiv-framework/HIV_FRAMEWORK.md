# 🧬 HIV Framework — Deep Methodology

## Biological Foundation

HIV survives not through invisibility but through **combinatorial strategy**. Each mechanism alone could be defeated. Together, they create a system that overwhelms coordinated defense.

The same principle applies to web2 security architecture. No single control is sufficient. The HIV-inspired attacker doesn't try to beat any one control — it beats the **coordination** between controls.

---

## Stage 1: gp120 — RECON / ATTACHMENT

**Biological analog:** HIV's gp120 protein recognizes and binds to CD4 receptors — specific surface proteins on T-cells. HIV doesn't randomly attack. It precisely identifies its target receptor before committing to infection.

**Web2 translation:** Before touching a single endpoint, map the target's entire immune surface.

### Reconnaissance Protocol

```
[PASSIVE — No direct interaction]
- Google dorking: site:target.com filetype:js
- Shodan/Censys for exposed services
- SecurityTrails for historical DNS
- GitHub/GitLab for leaked credentials, API keys
- Wayback Machine for old endpoints
- Certificate transparency: crt.sh

[SEMI-PASSIVE — Minimal footprint]
- DNS enumeration (passive resolvers)
- ASN/netblock mapping
- Tech stack via BuiltWith/Wappalyzer
- JS file extraction for API endpoint discovery
- robots.txt, sitemap.xml, .well-known/

[ACTIVE — Direct interaction, low rate]
- HTTP probe with timing analysis
- Header fingerprinting (Server, X-Powered-By, Via)
- Cookie structure analysis (session format, JWT vs opaque)
- Auth flow mapping (OAuth? SAML? custom?)
- Error message harvesting (verbose stack traces)
```

### CD4 Receptor Identification (What We're Looking For)

| Target "Receptor" | What It Tells Us |
|---|---|
| Authentication mechanism | Attack surface for auth bypass, token forgery |
| Session management type | Fixation, prediction, hijacking vectors |
| Input validation patterns | Injection surfaces |
| Rate limiting implementation | How hard we can push |
| WAF fingerprint | What evasion we need |
| API structure (REST/GraphQL/gRPC) | Query manipulation surface |
| JS framework + version | Known CVEs, prototype pollution |
| Cloud provider + CDN | SSRF targets, cache poisoning |

### CCR5/CXCR4 Co-receptor (Secondary Binding)

HIV needs a **second** binding site. Web2 equivalent: identify secondary access pathways.

```
Primary vector: Main web application
Co-vector options:
  - Mobile API (often less hardened)
  - Admin subdomain
  - Internal API exposed via SSRF
  - Third-party OAuth provider
  - Webhook receiver endpoints
  - CDN cache layer
  - GraphQL schema (often exposes more than REST)
```

---

## Stage 2: gp41 — INITIAL ACCESS / MEMBRANE FUSION

**Biological analog:** gp41 fuses the viral membrane with the cell membrane. This is the moment of penetration — irreversible entry into the host cell.

**Web2 translation:** Exploit the identified vulnerability. Cross the perimeter.

### Fusion Techniques by Receptor Type

```
AUTH RECEPTOR TARGETS:
├── JWT alg:none / weak secret
├── OAuth state parameter CSRF
├── SAML signature wrapping
├── Password reset token prediction
└── Account takeover via email collision

INJECTION RECEPTORS:
├── SQLi (boolean-based, time-based, OOB)
├── SSTI (Jinja2, Twig, Freemarker)
├── SSRF (cloud metadata, internal services)
├── XXE (entity injection for file read)
└── GraphQL injection / batching abuse

SESSION RECEPTORS:
├── Session fixation
├── Cookie attribute abuse (SameSite bypass)
├── JWT kid injection
└── CSRF with JSON content-type bypass

UPLOAD RECEPTORS:
├── MIME type bypass
├── Double extension (.php.jpg)
├── SVG XSS
└── Archive traversal (zip slip)
```

### The Fusion Moment

The goal isn't maximum impact at entry. Like HIV, **entry should be quiet**. Successful fusion that triggers alarms fails. Aim for:

- Single valid request that establishes foothold
- No excessive error generation
- Blend with normal traffic patterns
- "Look like a legitimate user" at the point of entry

---

## Stage 3: REVERSE TRANSCRIPTASE — PAYLOAD TRANSFORMATION

**Biological analog:** Reverse transcriptase converts viral RNA into DNA that can integrate into the host genome. Critically, it lacks error correction — producing mutations. This "error" is actually a feature: constant variation.

**Web2 translation:** Transform your payload into a form that bypasses filters, then continuously vary it.

### Encoding Pipeline

```
RAW PAYLOAD
    ↓
[Layer 1: Basic encoding]
URL encode → %3Cscript%3E
Double URL → %253Cscript%253E  
HTML entity → &lt;script&gt;
Unicode → \u003cscript\u003e

    ↓
[Layer 2: Context adaptation]
JSON string escape → \"
XML encoding → &#60;
CSS encoding → \3C
Base64 fragmentation

    ↓
[Layer 3: WAF-specific bypass]
Case variation → ScRiPt
Null byte insertion → scr\x00ipt
Comment injection → sc/**/ript
Whitespace variation → tab/newline/CR
Wildcard abuse → sc*ript (regex bypass)

    ↓
[Layer 4: Delivery obfuscation]
Fragment across multiple params
Split across headers + body
Use HTTP parameter pollution
Deliver via Referer/User-Agent
Encode in non-standard charset
```

### Mutation Engine (The "No Error Correction" Feature)

Don't send the same payload twice. Generate variants:

```python
import random, urllib.parse, base64

def mutate_payload(payload):
    """Generate a mutated variant of the payload"""
    strategies = [
        lambda p: p.replace("<", "%3C").replace(">", "%3E"),
        lambda p: p.replace("<", "\u003c").replace(">", "\u003e"),
        lambda p: p.replace("script", "scr" + random.choice(["/**/", "//\n", ""]) + "ipt"),
        lambda p: p.replace(" ", random.choice(["+", "%20", "\t", "\n"])),
        lambda p: "".join([c if random.random() > 0.1 else urllib.parse.quote(c) for c in p]),
    ]
    
    # Apply 1-3 random strategies
    n = random.randint(1, 3)
    chosen = random.sample(strategies, n)
    result = payload
    for fn in chosen:
        result = fn(result)
    return result
```

---

## Stage 4: INTEGRASE — PERSISTENCE / PROVIRUS

**Biological analog:** Integrase inserts the viral DNA directly into the host cell's chromosomes. The virus becomes part of the cell's own genetic code. This is the critical step — even when no virus is "active," the provirus remains.

**Web2 translation:** Establish persistence that survives session termination, IP changes, credential rotation, and partial remediation.

### Persistence Mechanisms (Provirus Equivalents)

```
[TIER 1: Session-level — weak, easily lost]
- Active session token
- Authenticated cookie

[TIER 2: Account-level — survives logout]
- OAuth application authorization (authorized app in victim's account)
- API key created under victim account
- Webhook registered to attacker's server
- Email forwarding rule
- Backup/recovery code theft
- Trusted device registration

[TIER 3: Infrastructure-level — survives account reset]
- Webshell in uploaded file
- Cron job via RCE
- Backdoored npm/pip package if supply chain access
- SSRF to cloud metadata → IAM role steal → create parallel access key
- Subdomain takeover (persists even if main app is patched)
- Cache poisoning with long TTL

[TIER 4: DNA-level — hardest to eradicate]
- Malicious OAuth app users keep re-authorizing
- Compromised CI/CD pipeline (runs on every deploy)
- Compromised developer machine (re-infects each push)
- SaaS integration (Zapier/IFTTT with stolen creds)
- Federated identity compromise (SSO provider access)
```

### The Provirus Principle

The best persistence is **invisible at rest**. A webshell that makes no requests is just a file. An OAuth app that isn't being used looks like any other authorized app. Design persistence that:

1. Produces zero outbound traffic when dormant
2. Looks indistinguishable from legitimate artifacts when inspected
3. Can be reactivated by a specific trigger (not random)
4. Has multiple layers — losing one doesn't mean losing all

---

## Stage 5: CELL HIJACK — LEGITIMATE INFRASTRUCTURE ABUSE

**Biological analog:** The infected cell's own ribosomes, enzymes, and energy systems are used to produce new viral particles. HIV doesn't bring its own factory — it uses the host's.

**Web2 translation:** Use the target's own infrastructure as your attack tool. Never use external resources when internal ones are available.

### Hijacking Target Infrastructure

```
EMAIL SYSTEMS:
- Abuse password reset to send phishing to other users
- Use contact forms for spam/phishing relay
- Exploit email preview to trigger SSRF

STORAGE SYSTEMS:
- Write to S3/GCS buckets the app uses
- Exploit file upload to deliver payloads to other users
- Use CDN as payload host (trusted domain)

COMPUTE:
- SSRF to cloud metadata for credentials
- Lambda/Function execution via injection
- Job queue injection (background task abuse)

AUTH SYSTEMS:
- OAuth flow to redirect tokens
- Impersonation via JWT manipulation
- Admin function abuse post-auth

INTERNAL SERVICES:
- SSRF to internal APIs (no auth required from inside)
- Blind SSRF for port scanning
- Redis/Memcached via SSRF for cache poisoning
- Kubernetes API via SSRF for container escape
```

---

## Stage 6: BUDDING — LATERAL MOVEMENT

**Biological analog:** New viral particles bud from the cell surface and infect adjacent cells. Each new infection becomes a new factory.

**Web2 translation:** Move from the initial access point to adjacent systems, accounts, and services.

### Lateral Movement Paths

```
WITHIN APPLICATION:
├── IDOR → access other user accounts
├── Privilege escalation → admin access
├── Tenant isolation bypass → other org's data
└── Role manipulation via mass assignment

ACROSS APPLICATIONS (same org):
├── SSO → use one app auth to access others
├── Shared credentials → reuse found passwords
├── Service account → app-to-app trust
└── Internal API access via SSRF pivot

ACROSS INFRASTRUCTURE:
├── Cloud metadata → IAM roles → other services
├── Database server → linked servers
├── VPN/internal network via SSRF
└── Container escape → host access → other containers

SUPPLY CHAIN (infecting new "cells"):
├── Compromised package → downstream consumers
├── CI/CD pipeline → infects every build
├── Shared library → spreads to all apps using it
└── Developer machine → infects all their repos
```

---

*HIV Framework — Methodology Reference*  
*Part of Security--Skill by wahyunuriman999*
