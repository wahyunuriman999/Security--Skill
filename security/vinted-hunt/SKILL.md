---
name: vinted-hunt
description: Hunt high-critical bugs in the Vinted Bugcrowd program.
version: 0.1.0
author: Hermes Agent
license: MIT
platforms: [windows]
metadata:
  hermes:
    tags: [bug-bounty, recon, vinted, bugcrowd, playbook]
    related_skills: []
triggers: [vinted, hunt, bug-bounty, recon, bugcrowd, playbook]
---

# Vinted Hunt Skill

Recon data, antimainstream high/critical hypotheses, PoC templates, and an English Bugcrowd submission template for the Vinted Bug Bounty (bugcrowd.com/engagements/vinted-uab-mbb). Source files live at `D:/security-skill-fixes/vinted-hunt/`.

## When to Use

- The user wants to hunt the Vinted Bugcrowd program (public since 30 Sep 2026, rewards $75–$8,000).
- The user wants non-obvious, low-duplicate findings rather than scanner-class XSS/missing-headers reports.
- The user needs a ready English report template for Bugcrowd submission.

Don't use for: live exploitation on the user's behalf (this agent does not perform attacks), or any target outside the 12 in-scope assets.

## Prerequisites

- User registered on Bugcrowd with a `@bugcrowdninja.com` email for this engagement.
- User owns all test accounts, listings, orders, and shipments used in PoCs.
- Files: `RECON.md`, `HUNT_PLAYBOOK.md`, `SUBMISSION_TEMPLATE_EN.md`, `scripts/recon_headers.py`, `scripts/js_miner.py`.

## How to Run

1. `read_file` on `D:/security-skill-fixes/vinted-hunt/RECON.md` — review verified scope, tech stack, internal hostnames, recent accepted findings.
2. `terminal` → run `python D:/security-skill-fixes/vinted-hunt/scripts/recon_headers.py` and `scripts/js_miner.py` to refresh passive recon (headers, robots.txt, JS endpoint mining).
3. `read_file` on `HUNT_PLAYBOOK.md` — pick one hypothesis (H1 checkout logic, H4 SSRF via webhook, H5 badger.it.vinted.com crypto oracle, H2 race condition are the highest bands).
4. User executes the chosen PoC template manually, throttled, on their own accounts only; capture screenshots + JSON.
5. `read_file` on `SUBMISSION_TEMPLATE_EN.md` — fill the Bugcrowd submission in English; one vulnerability per report.

## Procedure

1. Confirm target is one of the 12 in-scope assets (www.vinted.com/.net/.go.com, vinted iOS/Android, sandbox.vintedgo.com, sandbox.vinted.com, test-escalations.vintedgo.com, badger.it.vinted.com, careers.vinted.com, company.vinted.com, news.vinted.com).
2. Run passive recon only; no scanners, no brute force, no DoS, no automation of registration/cart/checkout (vinted.com robots.txt forbids transactional bots).
3. Test only your own accounts/items/orders; stop at first confirmed proof; never touch real members' data.
4. Delete any captured member data — confirmed deletion is a reward condition.
5. Submit one report in English with repro steps, request/response evidence, impact, and suggested fix.

## Pitfalls

- This skill contains hypotheses, not confirmed bugs. Never fabricate PoC results.
- Excluded report types (program policy): API-key disclosure without impact, CORS on non-sensitive endpoints, missing headers, low-impact CSRF, self-XSS, rate limiting, username/email enumeration, blind SSRF without business impact, host header without impact, subdomain takeover without takeover, pre-auth ATO/OAuth squatting, DoS/brute force.
- www.vinted.net, sandbox.vinted.com, news.vinted.com failed DNS at last recon; sandbox.vintedgo.com returned 403 for non-browser UAs.
- badger.it.vinted.com sends `Access-Control-Allow-Origin: *` — CORS-only findings are rejected unless a sensitive endpoint with credentials is proven.

## Verification

- Recon scripts return HTTP metadata for each in-scope asset without errors.
- Chosen hypothesis is reproduced by the user with request/response evidence on their own accounts.
- Bugcrowd submission drafted from `SUBMISSION_TEMPLATE_EN.md` with all fields completed.

