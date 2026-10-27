---
name: auto-cors-scanner
version: 1.0.0
description: Automated CORS scanner for entire *.crypto.com domain
license: MIT
triggers: [auto, cors, scanner]
---

# Auto-CORS Scanner

Automated CORS misconfiguration scanner for *.crypto.com domain.

## Tools
1. cors-misconfig-scanner - defensive, Python stdlib
2. corsair_scan - 4 injection scenarios
3. CORS-Scanner (Go) - fast scanner
4. CORScanner - fast with gevent
5. corsbuster - 12 checks, 3-stage verification, PoC
6. ratproxy - no-SNI TCP relay

## Usage
```bash
# corsbuster (recommended)
corsbuster -u https://target.com/api/endpoint --html-report report.html --poc

# cors-misconfig-scanner
python -m cors_scanner --sarif -o report.sarif https://target.com/api

# ratproxy for Cloudflare-bypass
python ratproxy.py  # runs on 127.0.0.1:8888
```

## Automation for *.crypto.com
```bash
# 1. Enum subdomains
subfinder -d crypto.com -o subdomains.txt

# 2. Probe alive
cat subdomains.txt | httpx -silent -status-code > alive.txt

# 3. Filter APIs
grep -E 'api|graphql|rest|v[0-9]' alive.txt > api_endpoints.txt

# 4. Scan all
while read ep; do
  corsbuster -u "$ep" --html-report report.html --poc
  python -m cors_scanner --sarif -o report.sarif "$ep"
  sleep 2
done < api_endpoints.txt
```

## Integration with rat_h3
```python
from rat_h3 import fetch
async def scan_cors(host, path, origin):
    status, headers, _ = await fetch(host, path, extra_headers={"origin": origin})
    return {"acao": headers.get("access-control-allow-origin"), "acac": headers.get("access-control-allow-credentials")}
```