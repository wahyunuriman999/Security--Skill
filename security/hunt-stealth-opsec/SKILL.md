---
name: hunt-stealth-opsec
description: Hunting OPSEC for high-security targets — avoid triggering WAF/IDS/SOC alerts, traffic blending, request timing, tool fingerprint removal, safe enumeration techniques, evidence collection without detection, responsible disclosure timing. Use when target has active monitoring, bug bounty with SLA disclosure, or when previous probes got you blocked/noticed.
tags: [opsec, stealth, waf-evasion, ids, soc, traffic-blending, fingerprint, responsible-disclosure, timing]
version: 1.0.0
license: MIT
triggers: [hunt, stealth, opsec, waf-evasion, ids, soc, traffic-blending, fingerprint, responsible-disclosure, timing]
---

# Hunting OPSEC — Stay Invisible on High-Security Targets

## 1. MINDSET: HUNTER vs SCANNER

```
SCANNER mentality (gets you blocked):
- Run automated tools directly on prod
- 1000 requests/minute
- Default tool User-Agents (sqlmap, nikto, nmap)
- Test every endpoint with every payload
- No regard for logging/alerting

HUNTER mentality (stays invisible):
- Manual-first, tool-second
- Match legitimate traffic patterns
- Blend with normal user behavior
- Test ONE thing at a time, thoroughly
- Understand what gets logged before testing

High-security targets have:
- SIEM with anomaly detection
- WAF with ML-based bot detection
- SOC team reviewing alerts in real-time
- Bug bounty program that can revoke access
- Legal team that monitors ToS violations
```

---

## 2. TRAFFIC BLENDING TECHNIQUES

### Request Rate — Match Real Users
```python
import time, random

def human_delay():
    """Simulate human reading/thinking time"""
    # Between pages: 2-15 seconds
    # Between actions: 0.5-3 seconds
    # Occasional long pause (reading): 15-60 seconds
    
    roll = random.random()
    if roll < 0.7:
        time.sleep(random.uniform(1.0, 5.0))   # Normal
    elif roll < 0.9:
        time.sleep(random.uniform(5.0, 15.0))  # Reading
    else:
        time.sleep(random.uniform(15.0, 60.0)) # Long pause

def safe_request(session, method, url, **kwargs):
    """Make request with human-like timing"""
    human_delay()
    r = session.request(method, url, **kwargs)
    return r
```

### User-Agent Rotation — Real Browser UAs Only
```python
REAL_BROWSER_UAS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Mobile Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
]

# Include full browser header set
BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Upgrade-Insecure-Requests": "1",
    # Add Sec-Ch-Ua for Chrome fingerprint
    "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
}
```

### Session Management — Mimic Real User Session
```python
import requests

# Use real session cookies (log in via browser first)
# Don't use headless/automated sessions for sensitive probes

# If using Python requests, maintain session:
session = requests.Session()
session.headers.update(BROWSER_HEADERS)

# Login legitimately first (establishes legit session history)
session.post("https://target.com/login", data={"email": "your@test.com", "password": "xxx"})

# Then probe naturally within established session
# Don't jump to admin endpoints immediately after login
# Browse normally for a few minutes first
```

---

## 3. TOOL FINGERPRINT REMOVAL

### Remove Default Tool Signatures
```bash
# sqlmap default: sqlmap/1.x (#dev-sqlmap.org)
# Fix: --user-agent "Mozilla/5.0 ..." --random-agent

sqlmap -u "https://target.com/api?id=1" \
  --random-agent \
  --delay=3 \
  --level=1 --risk=1 \
  --technique=B \  # Boolean-based only (less noise)
  --batch

# nikto default: libwww-perl/x.x
# Fix: use -useragent flag or skip nikto on high-security targets

# nmap: OS fingerprint + timing signature
# Fix: -T2 (polite), --data-length 50 (pad packets)
nmap -sV -T2 --data-length 50 -p 443,8443 target.com

# ffuf: ffuf/x.x
# Fix: -H "User-Agent: Mozilla/..."
ffuf -u https://target.com/FUZZ -w wordlist.txt \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)..." \
  -rate 10 \
  -p 0.5

# nuclei: default Nuclei/x.x
# Fix: -H "User-Agent: ..."
nuclei -u https://target.com \
  -H "User-Agent: Mozilla/5.0..." \
  -rate-limit 5 \
  -bulk-size 5
```

### Burp Suite Stealth
```
Default Burp signature:
- X-Burp-Product header in some versions
- Distinctive Burp proxy User-Agent when forwarding

Fix:
1. Burp → Project Options → Connections → Hostname Resolution
2. Proxy → Options → Intercept → remove Burp headers
3. User Options → Misc → Performance Feedback → disable
4. Use "Match and Replace" to remove/replace all Burp signatures
5. Add real browser headers via Match and Replace
```

---

## 4. SAFE ENUMERATION TECHNIQUES

### Parameter Discovery — Safe Method
```python
# DON'T: enumerate 10,000 parameter names rapidly
# DO: test parameters contextually based on application logic

# Safe parameter discovery:
# 1. Read JS files to find parameter names used in frontend
# 2. Observe network traffic while using the app normally
# 3. Check API documentation if public (Swagger, OpenAPI)
# 4. Look at error messages that reveal valid parameter names

# If you must fuzz, do it slowly:
import time

params_to_test = ["debug", "admin", "internal", "test", "dev"]
for param in params_to_test:
    r = session.get(f"https://target.com/api/users?{param}=1")
    if r.status_code != 404:
        print(f"Interesting response for {param}: {r.status_code}")
    time.sleep(3)  # 3 second delay between probes
```

### IDOR Enumeration — Stay Under Rate Limits
```python
# DON'T: enumerate 10,000 IDs in 10 seconds
# DO: test small range to prove concept, then estimate impact

# Proof-of-concept approach:
# 1. Find your own resource ID: /api/users/12345
# 2. Test 5-10 IDs adjacent to yours: 12340, 12341, 12342...
# 3. Test a few clearly-different-user IDs: 1, 2, 3, 100, 1000
# 4. STOP when you have 2-3 examples proving the bug
# 5. DON'T enumerate all 1,000,000 users — unnecessary + gets you flagged

# For report: "I accessed 3 user accounts other than my own. 
# The pattern is predictable, suggesting all N users are affected."

SAFE_TEST_IDS = [1, 2, 3, 100, 999, 9999]  # Max 6 probe IDs
for uid in SAFE_TEST_IDS:
    r = session.get(f"https://target.com/api/users/{uid}")
    if r.status_code == 200:
        print(f"IDOR confirmed: user {uid} accessible")
        break  # STOP after first confirmation
    time.sleep(5)
```

### Directory/Path Discovery — Passive First
```bash
# PASSIVE (no active requests):
# 1. Wayback Machine: gau target.com | grep -E "/(admin|internal|debug|test)"
# 2. JS parsing: extract paths from bundle files
# 3. Robots.txt / sitemap.xml (already public)
# 4. Error pages that reveal path structure

# ACTIVE (minimal footprint):
# Use small, targeted wordlists — not 100k word lists
# Test only paths relevant to the application

TARGET="https://target.com"
WORDLIST="small_targeted_wordlist.txt"  # 200-500 entries, not 100k

ffuf -u "$TARGET/FUZZ" -w $WORDLIST \
  -rate 5 \           # 5 req/sec max
  -p 1 \              # 1 second between requests
  -fc 404,400 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
```

---

## 5. WHAT GETS LOGGED — KNOW BEFORE YOU TEST

### Enterprise Security Stack
```
Layer 1: WAF (Cloudflare/Akamai/AWS WAF)
Logs: IP, UA, URL, payload, timestamp, block reason
Triggers: Known attack signatures, anomaly scores, bot detection

Layer 2: CDN / Load Balancer
Logs: All HTTP requests, response codes, timing
Triggers: Unusual request rates, unusual geographic patterns

Layer 3: Application Logs
Logs: Authentication events, authorization failures, API calls
Triggers: Multiple 401/403 errors, unusual access patterns

Layer 4: SIEM (Splunk/Elastic/Sentinel)
Correlates: Multiple failed auth attempts = account takeover attempt
            Many 404 errors = directory scanning
            Unusual data access patterns = exfiltration attempt

Layer 5: Bug Bounty Platform
Logs: Your submissions, associated account activity
Triggers: Multiple reports from same account, out-of-scope testing
```

### What's Usually NOT Logged
```
- Static asset requests (JS, CSS, images) — usually not in app logs
- Cached responses — may not hit application
- OPTIONS preflight requests — sometimes ignored
- HEAD requests — sometimes ignored
- Request bodies on GET requests — usually not logged
```

---

## 6. RESPONSIBLE DISCLOSURE TIMING

### When to Report vs When to Dig Deeper
```
REPORT IMMEDIATELY (don't explore further):
- RCE found — do not execute commands beyond proof
- SQL injection found — do not dump data beyond your own test account
- Access to PII — confirm access, do NOT read/store/exfiltrate
- Cloud credential theft — do NOT use credentials beyond verifying they work
- Payment data access — report immediately, minimum evidence

DIG DEEPER (build full chain first):
- Low/Medium bug that needs chaining to be accepted
- Need to understand full impact before reporting
- Unclear scope — need more recon to confirm in-scope

RULE: Collect minimum evidence needed to prove the bug.
      Never access data you don't need. Never download PII.
      Never persist access (backdoors, added accounts).
```

### Disclosure Timeline for High-Security Targets
```
Day 0: Bug discovered, PoC confirmed
Day 1: Draft report, get evidence (screenshots + request/response)
Day 2: Submit to bug bounty platform
Day 3-7: Triage expected (check program SLA)
Day 14: Follow up if no response
Day 30: If no response → escalate politely, CC platform
Day 90: Coordinated public disclosure deadline (reasonable)

For CRITICAL bugs (RCE, data breach, auth bypass affecting millions):
- Report SAME DAY
- Use platform's emergency contact if available
- Note severity clearly in title: [CRITICAL] Remote Code Execution via...
```

---

## 7. EVIDENCE COLLECTION — STEALTH MODE

### Capture Evidence Without Storing Sensitive Data
```python
# Redact PII from evidence before storing
import re

def redact_pii(text):
    """Remove PII from captured response for evidence"""
    # Redact emails
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]', text)
    # Redact SSN
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN_REDACTED]', text)
    # Redact credit cards
    text = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[CC_REDACTED]', text)
    # Redact phone numbers
    text = re.sub(r'\b\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b', '[PHONE_REDACTED]', text)
    # Keep structure but redact values
    return text

# Save evidence
with open("evidence/idor_proof.txt", "w") as f:
    f.write("REQUEST:\n" + request_text + "\n\n")
    f.write("RESPONSE (PII REDACTED):\n" + redact_pii(response_text))
```

### Burp Evidence Best Practices
```
1. Use Burp's "Save item" not "Copy request" — preserves full context
2. Annotate requests with comments before saving
3. Use Burp Logger++ extension for session capture
4. Save screenshots immediately — don't rely on browser history

Evidence format for high-value bugs:
- Screenshot of full request in Burp Repeater
- Screenshot of response showing vulnerability
- Screenshot of impact (account data, admin access, etc.)
- HTTP request file (raw .txt)
- Video if complex multi-step (optional but powerful)
```

---

## 8. IF YOU GET BLOCKED

### Recovery Steps
```
SCENARIO: Your IP gets blocked by WAF

IMMEDIATE:
1. STOP all requests immediately
2. Document: what were you testing, what triggered the block
3. Wait 24 hours (WAF temp blocks often auto-expire)

IF TESTING CONTINUES:
1. Switch to residential proxy (different IP range)
2. Use VPN (different datacenter)
3. Test from mobile hotspot
4. If in bug bounty: contact program — "My IP was blocked during authorized testing"

SCENARIO: Bug bounty account suspended for "out of scope testing"
1. Reply professionally: "I was testing X because Y (business logic reason)"
2. Provide evidence of what you tested and why it seemed in-scope
3. If genuinely out of scope: acknowledge, ask for grace on first offense
4. Most programs: first violation = warning, not permanent ban
```

---

## OPSEC CHECKLIST — BEFORE EACH HUNT SESSION

```
[ ] VPN/proxy configured (not home IP on prod)
[ ] Browser User-Agent matches headers
[ ] Burp headers cleaned (no Burp signatures)
[ ] Rate limits set on all tools
[ ] Test account registered with temp email
[ ] Scope reviewed — what's allowed
[ ] Evidence folder ready with redaction workflow
[ ] Understand target's monitoring stack
[ ] Know program's response time SLA
[ ] Emergency stop plan ready
```
