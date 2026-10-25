---
name: hunt-advanced-recon
description: Advanced recon for high-security targets — ASM automation, passive fingerprinting, git history secret mining, JS reverse engineering for hidden APIs, favicon hash correlation, certificate transparency mining, S3 bucket enumeration, wayback machine exploitation, leaked credentials from paste sites. Use at the START of any hunt on a hardened target.
tags: [recon, asm, git-history, js-reverse, favicon, cert-transparency, s3, wayback, osint, passive]
---

# Advanced Recon — High-Security Target Edition

## 1. ATTACK SURFACE MAPPING (ASM)

### Full Subdomain Enumeration Pipeline
```bash
TARGET="target.com"
OUT="recon_$TARGET"
mkdir -p $OUT

# Layer 1: Passive (zero noise)
subfinder -d $TARGET -o $OUT/subfinder.txt -all -silent
assetfinder --subs-only $TARGET >> $OUT/passive.txt
amass enum -passive -d $TARGET -o $OUT/amass_passive.txt
findomain -t $TARGET -q -o $OUT/findomain.txt

# Layer 2: Certificate Transparency
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | sort -u > $OUT/crt.txt

# Layer 3: DNS brute-force (louder, use after passive)
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  $TARGET -r resolvers.txt -o $OUT/bruteforce.txt

# Layer 4: Permutation (e.g., "api" → "api-v2", "api-internal", "api-staging")
gotator -sub $OUT/passive.txt -perm permutations.txt -depth 1 -numbers 3 > $OUT/permutations.txt
puredns resolve $OUT/permutations.txt -r resolvers.txt -o $OUT/permutations_resolved.txt

# Merge all
cat $OUT/*.txt | sort -u > $OUT/all_subdomains.txt
echo "Total: $(wc -l < $OUT/all_subdomains.txt) subdomains"
```

### HTTP Probing — Find Live Targets
```bash
# httpx with full fingerprinting
cat $OUT/all_subdomains.txt | httpx \
  -title -tech-detect -status-code -content-length \
  -follow-redirects -threads 50 \
  -o $OUT/live_hosts.txt

# Extract interesting ones
grep -E "(200|301|302|401|403)" $OUT/live_hosts.txt | \
  grep -iE "(admin|internal|staging|dev|api|dashboard|portal|jenkins|grafana|kibana)"
```

### Port Scanning (Targeted)
```bash
# Fast port scan on all live IPs
cat $OUT/live_hosts.txt | awk '{print $1}' | \
  dnsx -resp-only -a -o $OUT/ips.txt

# naabu for port discovery
cat $OUT/ips.txt | naabu -top-ports 1000 -o $OUT/ports.txt

# Deep scan on interesting ports
nmap -sV -sC -p 8080,8443,9200,9300,6379,27017,5432,3306 \
  -iL $OUT/ips.txt -oA $OUT/nmap_interesting
```

---

## 2. CERTIFICATE TRANSPARENCY MINING

```python
import requests, json, re

def ct_mining(domain):
    """Mine cert transparency for subdomains, emails, org names"""
    # crt.sh
    r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30)
    certs = r.json()
    
    subdomains = set()
    emails = set()
    orgs = set()
    
    for cert in certs:
        # Subdomains from SAN
        for name in cert.get('name_value', '').split('\n'):
            name = name.strip().lstrip('*.')
            if domain in name:
                subdomains.add(name)
        
        # Extract org from issuer
        issuer = cert.get('issuer_name', '')
        org_match = re.search(r'O=([^,]+)', issuer)
        if org_match:
            orgs.add(org_match.group(1))
    
    # certspotter API (more detail)
    r2 = requests.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names,issuer,revocation,problem_reporting")
    
    return subdomains, emails, orgs

# Also check: 
# https://transparencyreport.google.com/https/certificates?hl=en&cert_search_auth=&cert_search=include_subdomains:true,domain:{domain}
# https://censys.io/certificates?q=parsed.names%3A{domain}
```

---

## 3. GIT HISTORY SECRET MINING

### Automated Git Secret Scanning
```bash
# Clone repo (if public)
git clone --mirror https://github.com/target-org/repo.git /tmp/target_repo

# truffleHog — finds secrets in git history
trufflehog git file:///tmp/target_repo --only-verified --json > secrets.json

# gitleaks — high signal, low noise
gitleaks detect --source=/tmp/target_repo --report-path=gitleaks_report.json

# git-dumper — when .git exposed on web server
git-dumper https://target.com/.git/ /tmp/dumped_repo

# Check if .git exposed
curl -s https://target.com/.git/HEAD
# If returns "ref: refs/heads/main" → .git is exposed → dump everything
```

### Manual Git Investigation
```bash
# List all commits
git log --all --full-history --oneline | head -100

# Search all commit diffs for keywords
git log -p --all | grep -E "(password|secret|key|token|api_key|private|credentials)" -A3 -B3

# Find deleted files
git log --diff-filter=D --summary --all | grep delete

# Recover deleted file
git checkout <commit-hash> -- path/to/deleted/file

# Show all branches including remote/archived
git branch -a

# Look for config files in history
git log --all --full-history -- "*.env" "*.config" "*.json" "config/*"
git show <hash>:path/to/.env
```

### Find Exposed .env Files
```bash
# Check common paths
for path in .env .env.local .env.production .env.staging config/.env .env.backup; do
  curl -s -o /dev/null -w "%{http_code} $path\n" https://target.com/$path
done

# .git exposure check
curl -s https://target.com/.git/config
curl -s https://target.com/.git/COMMIT_EDITMSG
curl -s https://target.com/.git/refs/heads/main

# SVN exposure
curl -s https://target.com/.svn/entries
```

---

## 4. JS REVERSE ENGINEERING — HIDDEN API DISCOVERY

### Automated JS Endpoint Extraction
```bash
# Step 1: Find all JS files
cat $OUT/live_hosts.txt | while read url; do
  echo $url | hakrawler -js -depth 3 -plain
done | grep "\.js" | sort -u > $OUT/js_files.txt

# Step 2: Download and analyze
cat $OUT/js_files.txt | while read jsurl; do
  curl -s "$jsurl" | \
  grep -oE "(\"|\')(\/api\/[^\"\']+)(\"|\')|(https?://[a-z0-9._-]+\.[a-z]{2,}(/[^\"\'<>\s]+)?)" | \
  sort -u
done > $OUT/js_endpoints.txt

# Step 3: linkfinder for API endpoint discovery
python3 linkfinder.py -i https://target.com/static/app.bundle.js -o cli

# Step 4: Retire.js for vulnerable library detection
retire --js --path /tmp/target_js/ --outputformat json
```

### Manual JS Analysis
```javascript
// In browser console on target site:

// Find all XHR/fetch calls
let origFetch = window.fetch;
window.fetch = function(...args) {
  console.log('[FETCH]', args[0], args[1]);
  return origFetch.apply(this, args);
};

let origXHR = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url) {
  console.log('[XHR]', method, url);
  return origXHR.apply(this, arguments);
};

// Find all routes in React/Vue/Angular SPA
// React Router
window.__reactFiber  // look for Router components

// Angular routes
ng.probe(document.querySelector('router-outlet'))._debugContext.componentView.context.router.config

// Vue Router
window.__vue_router__?.options?.routes
```

### Webpack Bundle Analysis
```bash
# Extract webpack chunks
curl -s https://target.com/static/js/main.chunk.js | \
  python3 -c "
import sys, re
content = sys.stdin.read()
# Find all API endpoints
endpoints = re.findall(r'['\"]/(api/[^'\">\s]+)['\"]', content)
for ep in sorted(set(endpoints)):
    print(ep)
"

# webpackbar — analyze webpack stats
# If target exposes /webpack-stats.json or stats.json
curl -s https://target.com/webpack-stats.json | jq '.modules[].name' | grep -v node_modules

# source-map extraction
curl -s "https://target.com/static/js/main.js.map" | jq '.sources'
# Source maps reveal original source code including business logic, API routes, secrets
```

---

## 5. FAVICON HASH CORRELATION — FIND ORIGIN IP & RELATED ASSETS

```python
import mmh3, requests, base64, codecs

def get_favicon_hash(url):
    """Calculate favicon hash for Shodan/Censys search"""
    r = requests.get(url, verify=False, timeout=10)
    favicon = codecs.encode(r.content, 'base64')
    # Remove newlines
    favicon = favicon.replace(b'\n', b'')
    hash_val = mmh3.hash(favicon)
    return hash_val

# Common favicon locations
for path in ['/favicon.ico', '/favicon.png', '/static/favicon.ico']:
    try:
        h = get_favicon_hash(f"https://target.com{path}")
        print(f"Favicon hash ({path}): {h}")
        print(f"Shodan search: http.favicon.hash:{h}")
        print(f"Censys search: services.http.response.favicons.md5_hash=<md5>")
    except:
        pass

# Shodan API search for same favicon (find origin IP behind CDN)
import shodan
api = shodan.Shodan('YOUR_API_KEY')
results = api.search(f"http.favicon.hash:{hash_val}")
for r in results['matches']:
    print(f"IP: {r['ip_str']} Port: {r['port']} Org: {r.get('org','')}")
```

---

## 6. WAYBACK MACHINE EXPLOITATION

```python
import requests

def wayback_mining(domain):
    """Extract historical URLs, parameters, and endpoints from Wayback Machine"""
    
    # Get all URLs ever captured
    r = requests.get(
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original,statuscode,timestamp",
        timeout=60
    )
    urls = r.json()[1:]  # Skip header
    
    # Filter interesting
    interesting = []
    for url, status, ts in urls:
        if any(kw in url.lower() for kw in ['api', 'admin', 'debug', 'test', 'dev', 'internal', 'backup', '.env', 'config', 'secret', 'token', 'key']):
            interesting.append((url, status, ts))
    
    return interesting

# gau (getallurls) — faster
# gau target.com | sort -u > all_urls.txt
# gau --providers wayback,otx,commoncrawl target.com

# Find parameters from historical URLs
# cat all_urls.txt | unfurl --unique keys > parameters.txt
# Then test these params for injection, IDOR, etc.

# Find old API versions
# grep -E "/api/v[0-9]" all_urls.txt | sort -u
# Old versions may lack auth, have more verbose errors, or be unpatched
```

---

## 7. S3 BUCKET ENUMERATION

```bash
# Find bucket names from various sources
TARGET="targetcompany"

# Common naming patterns
for pattern in $TARGET "$TARGET-assets" "$TARGET-static" "$TARGET-uploads" \
               "$TARGET-backup" "$TARGET-data" "$TARGET-prod" "$TARGET-dev" \
               "$TARGET-staging" "$TARGET-media" "assets.$TARGET" "cdn.$TARGET" \
               "static.$TARGET" "files.$TARGET"; do
  echo "Checking: $pattern"
  
  # AWS S3
  aws s3 ls s3://$pattern --no-sign-request 2>/dev/null && echo "OPEN: s3://$pattern"
  
  # GCP Storage
  curl -s "https://storage.googleapis.com/$pattern/?max-keys=5" | grep -q "Contents" && echo "OPEN GCS: $pattern"
  
  # Azure Blob
  curl -s "https://$pattern.blob.core.windows.net/" | grep -q "xml" && echo "OPEN Azure: $pattern"
done

# S3Scanner
s3scanner scan --buckets-file bucket_names.txt --dump

# Check for bucket in JS files
grep -r "s3\.amazonaws\.com\|storage\.googleapis\.com\|blob\.core\.windows" $OUT/js_files/

# Test upload on found open bucket
aws s3 cp test.txt s3://found-bucket/ --no-sign-request
```

---

## 8. PASTE SITE & LEAK DATABASE MONITORING

```bash
# Search for target credentials/secrets in public pastes
# pwndb / dehashed for email/pass combos
curl "https://haveibeenpwned.com/api/v3/breachedaccount/target@company.com" \
  -H "hibp-api-key: YOUR_KEY"

# Search paste sites for target domain
# grep.app (search GitHub commits)
curl "https://grep.app/api/search?q=target.com+password&regexp=false" | jq '.hits.hits[].source.content'

# Shodan for exposed databases
shodan search "org:target-company mongodb port:27017 -auth" 
shodan search "hostname:target.com" 

# Hunter.io for email enumeration
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_KEY" | \
  jq '.data.emails[].value'

# theHarvester
theHarvester -d target.com -b all -f output.html
```

---

## 9. TECHNOLOGY FINGERPRINTING

```bash
# Wappalyzer via httpx
cat live_hosts.txt | httpx -tech-detect -json | jq '.technologies'

# WhatWeb
whatweb -a 3 https://target.com --log-json whatweb.json

# nuclei tech detection
nuclei -u https://target.com -t technologies/ -o tech_detect.txt

# Find specific tech vulnerabilities
# If Nginx: check for alias traversal, CRLF
# If Apache: check for mod_status, .htaccess exposure
# If IIS: check for tilde enumeration, NTLM auth
# If Node.js: check for prototype pollution, SSTI in templates
# If Java: check for Spring Boot actuators, deserialization

# Spring Boot actuator check
for endpoint in /actuator /actuator/env /actuator/health /actuator/info \
                /actuator/mappings /actuator/beans /actuator/metrics \
                /actuator/httptrace /actuator/logfile /actuator/dump; do
  curl -s -o /dev/null -w "%{http_code} $endpoint\n" https://target.com$endpoint
done
```

---

## 10. FULL RECON PIPELINE

```bash
#!/bin/bash
# Full passive → active recon pipeline
TARGET="${1:-target.com}"
OUT="hunt_$(echo $TARGET | tr '.' '_')_$(date +%Y%m%d)"
mkdir -p $OUT/{passive,active,js,git,cloud,wayback}

echo "[*] Phase 1: Passive enumeration"
subfinder -d $TARGET -silent -all -o $OUT/passive/subfinder.txt
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sort -u > $OUT/passive/crt.txt
cat $OUT/passive/*.txt | sort -u > $OUT/passive/all.txt
echo "[+] $(wc -l < $OUT/passive/all.txt) subdomains found"

echo "[*] Phase 2: HTTP probing"
cat $OUT/passive/all.txt | httpx -title -tech-detect -status-code -silent -o $OUT/active/live.txt
echo "[+] $(wc -l < $OUT/active/live.txt) live hosts"

echo "[*] Phase 3: JS analysis"
cat $OUT/active/live.txt | awk '{print $1}' | gau --providers wayback > $OUT/wayback/all_urls.txt
grep "\.js" $OUT/wayback/all_urls.txt | sort -u > $OUT/js/js_urls.txt
cat $OUT/js/js_urls.txt | xargs -P5 -I{} curl -s {} | grep -oE '"/(api/[^"]+)"' | sort -u > $OUT/js/endpoints.txt

echo "[*] Phase 4: Secret scanning"
cat $OUT/active/live.txt | awk '{print $1}' | \
  xargs -I{} curl -s "{}/.git/HEAD" | grep -q "ref:" && echo "[!] .git exposed"

echo "[*] Phase 5: Reporting"
echo "Subdomains: $(wc -l < $OUT/passive/all.txt)"
echo "Live hosts: $(wc -l < $OUT/active/live.txt)"
echo "JS endpoints: $(wc -l < $OUT/js/endpoints.txt)"
echo "Wayback URLs: $(wc -l < $OUT/wayback/all_urls.txt)"
```
