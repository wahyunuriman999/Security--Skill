# Anti-Mainstream Vector Selection

## Purpose
Choose vulnerability vectors that are (a) valid per program policy and (b) less commonly tested, to avoid duplicate reports and increase payout probability.

## When to apply
Any bounty program where you want to avoid "already reported" or "known issue" closures. Especially valuable for programs with explicit valid/invalid vector lists (AI/LLM programs, scope-rated programs).

## Methodology

### Step 0: Engagement Page Analysis

Before any technical recon, analyze the engagement page fully. It determines what is testable, what pays, and what to avoid.

- **Core metadata:** scope rating (1–4), targets and reward tiers (P1/P2/P3/P4), testing period/status, vulnerabilities rewarded count, average validation time, average payout
- **In-scope targets:** list every target with tags and known issues; separate Tier 1 vs Tier 2 vs SDK vs mobile vs API; flag wildcard scopes (*.domain.com); note researcher environment URL
- **Out-of-scope list:** excluded vulnerability types (XSS, CSRF, DoS, scanner-only, missing headers), excluded activities (social engineering, physical testing, exploitation past PoC), out-of-scope targets/domains — never report excluded types
- **Bonus programs:** bonus period dates, multipliers (P1 ×3, P2 ×2), specific bonus vectors; only submissions within the bonus window qualify
- **Researcher environment:** credentials process ("Get Credentials" button), users/tenants provided, access URL; if programmatic access is blocked by Cloudflare/WAF, plan for manual login — don't fabricate access
- **Rules of engagement:** automated tools allowed? rate limits? disclosure terms? required report format?
- **Recent activity:** recent accepted submissions per target, hall of famers — avoid targets with recent similar findings (duplicate risk)
- **Documentation:** save scope, targets, out-of-scope, bonus info, credentials process, and candidate vectors to a recon markdown file; reference before every testing session

### Step 1: Read the program policy for explicit vector lists
Programs often publish what they WILL and WILL NOT reward. Map every valid vector and every excluded category before testing.

### Step 2: Identify under-tested valid vectors
From the valid list, flag vectors that are technically eligible but rarely tested:
- Direct jailbreak → Indirect injection via RAG/external data connector
- General prompt injection → GraphQL IDOR on AI conversation API
- Direct SSRF via model fetch tool → SSRF via webhook/external connector config
- Self-XSS → XSS in anonymous/end-user context (widget, mobile SDK)

### Step 3: Cross-reference with program exclusions
Drop any vector the program explicitly excludes (e.g., "self-XSS", "missing security headers", "Contributor/Light Agent issues").

### Step 4: Prioritize by payout ceiling × uniqueness
Rank candidates by (P1 ceiling) × (estimated uniqueness). A P1 vector that 90% of hunters skip is worth more than a P1 vector everyone tests.

## Zendesk AI example (validated)
| Common vector (skip) | Anti-mainstream alternative | Why it avoids duplicates |
|---|---|---|
| Direct jailbreak/persona bypass | Indirect injection via RAG external connector | Program explicitly lists this as valid; few hunters test indirect injection via connectors |
| General prompt injection | GraphQL IDOR on AI Agent conversation API | Most hunters don't map AI Agent GraphQL schema; cross-tenant data leakage is P1 |
| SSRF via model fetch tool | SSRF via App Builder webhook URL config | Webhook SSRF is less commonly tested than model-fetch SSRF |
| Self-XSS | Web Widget SDK XSS in anonymous context | Program explicitly accepts anonymous-user XSS; widget SDK is rarely audited |

## Validation requirement
Every anti-mainstream vector must still meet the program's impact bar: cross-tenant data access, unauthorized state change, credential disclosure, or OOB-confirmed exfil. "Vector is unusual" is NOT impact by itself.