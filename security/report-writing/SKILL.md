---
name: report-writing
description: Bug bounty report writing for H1/Bugcrowd/Intigriti/Immunefi — report templates, human tone guidelines, impact-first writing, CVSS 3.1 scoring, title formula, impact statement formula, severity decision guide, downgrade counters, pre-submit checklist. Use after validating a finding and before submitting. Never use "could potentially" — prove it or don't report.
version: 1.0.0
license: MIT
triggers: [report, writing]
---

# REPORT WRITING

Impact-first. Human tone. No theoretical language. Triagers are people.

See also: [[Report Writing]], [[Triage]], [[A→B Chains]], [[Lead Ledger]]

---

## THE MOST IMPORTANT RULE

> **Never use "could potentially" or "could be used to" or "may allow".**
> Either it does the thing or it doesn't. If you haven't proved it, don't claim it.

```
BAD:  "This vulnerability could potentially allow an attacker to access user data."
GOOD: "An attacker can access any user's order history by changing the user_id
       parameter to the target user's ID. I confirmed this using two test accounts:
       attacker@test.com (ID 123) successfully retrieved victim@test.com (ID 456)
       orders, including their shipping address and payment method last 4 digits."
```

---

## TITLE FORMULA

```
[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]
```

## CLAIM-LEVEL VERIFICATION

- Verify every named field individually before putting it in a report; a multi-field GraphQL request can fail on the first invalid field and falsely make later fields look valid.
- Separate schema validation from resolver authorization: a field reaching `unauthenticated` proves schema acceptance, not data access; report the exact boundary you observed.
- Replace a finite probe's language with “tested subset” unless the enumeration is demonstrably complete; this prevents one stale or guessed field from weakening an otherwise valid report.
- Keep failed follow-up probes out of the primary impact narrative unless they are necessary to reproduce the finding; attach them as negative evidence or a separate assessment note.

**Good titles (specific, impact-first):**
```
IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data
Missing auth on POST /api/admin/users allows unauthenticated attacker to create admin accounts
Stored XSS in profile bio field executes in admin panel — allows privilege escalation
SSRF via image import URL parameter reaches AWS EC2 metadata service
Race condition in coupon redemption allows same code to be used unlimited times
```

**Bad titles (vague, useless to triager):**
```
IDOR vulnerability found
Broken access control
XSS in user input
Security issue in API
Unauthorized access to user data
```

---

## HACKERONE REPORT TEMPLATE

```markdown
## Summary

[One paragraph: what the bug is, where it is, what an attacker can do. Be specific.
Include: endpoint, method, parameter, data exposed, required access level.]

Example: "The `/api/users/{user_id}/orders` endpoint does not verify that the
authenticated user owns the requested user_id. An attacker can enumerate any
user's order history, including PII (email, address, phone) and purchase history,
by incrementing the user_id parameter. No privileges beyond a standard free
account are required."

## Vulnerability Details

**Vulnerability Type:** IDOR / Broken Object Level Authorization
**CVSS 3.1 Score:** 6.5 (Medium) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
**Affected Endpoint:** GET /api/users/{user_id}/orders

## Steps to Reproduce

**Environment:**
- Attacker account: attacker@test.com, user_id = 123
- Victim account: victim@test.com, user_id = 456
- Target: https://target.com

**Steps:**

1. Log in as attacker@test.com, obtain Bearer token

2. Send the following request:

```
GET /api/users/456/orders HTTP/1.1
Host: target.com
Authorization: Bearer ATTACKER_TOKEN_HERE
```

3. Observe response:

```json
{
  "orders": [
    {"id": 789, "items": [...], "email": "victim@test.com", "address": "123 Main St..."}
  ]
}
```

The response contains victim's full order history and PII despite being requested
by a different user.

## Impact

An authenticated attacker can enumerate all user orders by iterating user_id values.
This exposes: full name, email, shipping address, purchase history, and payment
method (last 4). With ~100K users, this represents a mass PII breach affecting
all registered users. Exploitation requires only a free account and takes minutes
with a simple loop.

## Recommended Fix

Add server-side ownership verification:
```python
if order.user_id != current_user.id:
    raise Forbidden()
```

## Supporting Materials

[Screenshot showing attacker's session returning victim's order data]
[Video walkthrough if available]
```

---

## BUGCROWD REPORT TEMPLATE

```markdown
# [IDOR] User order history accessible without authorization via /api/users/{id}/orders

**VRT Category:** Broken Access Control > IDOR > P2

## Description

[Same impact-first paragraph as HackerOne summary]

## Steps to Reproduce

[Same structured steps — exact HTTP requests, exact responses]

## Proof of Concept

[Screenshot/video showing the actual impact]

## Expected vs Actual Behavior

**Expected:** 403 Forbidden when user_id does not match authenticated user
**Actual:** 200 OK with victim's full order data

## Severity Justification

P2 (High) — Direct read access to other users' PII. Affects all user accounts.
No user interaction required. Exploitable by any authenticated user.
Automated enumeration could exfil all [N] user records in minutes.

## Remediation

Add ownership verification: `if order.user_id != current_user.id: raise 403`
```

---

## INTIGRITI REPORT TEMPLATE

```markdown
# [Bug Class]: [Exact Impact] in [Endpoint/Feature]

## Description

[Impact-first paragraph. Start with what an attacker can do, not with how you found it.
Include: endpoint, method, parameter, data exposed, required privileges.]

## Steps to Reproduce

**Environment:**
- Attacker: email=attacker@test.com (standard account, no special role)
- Victim: email=victim@test.com
- Tested: [date]

**Reproduction steps:**

1. [Login as attacker / visit URL / send request]

2. Send the following HTTP request:

\```http
METHOD /endpoint HTTP/1.1
Host: target.com
Authorization: Bearer ATTACKER_TOKEN
Content-Type: application/json

{"param": "victim_id_here"}
\```

3. Observe response contains victim's private data:

\```json
{"email": "victim@test.com", "address": "123 Main St", ...}
\```

## Impact

[Specific, quantified impact. What data, how many users, what can attacker do.]

CVSS 3.1 Score: X.X ([Severity]) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

## Remediation

[1-3 sentence concrete fix. Include code if helpful.]

## Attachments

[Screenshot or Loom video showing the impact — Intigriti triagers prefer video for complex bugs]
```

**Intigriti-specific notes:**
- Title format: `[Bug Class]: [One-line impact]` (no formula required, but keep it specific)
- Severity is set by you: Critical/High/Medium/Low/Exceptional
- CVSS 3.1 is standard (CVSS 4.0 also accepted on newer programs)
- PoC video is valued much more than screenshot alone — record with Loom
- Safe harbor: Intigriti enforces it, be comfortable going slightly aggressive with testing

---

## IMMUNEFI REPORT TEMPLATE

```markdown
# [Bug Class] — [Protocol Name] — [Severity]

## Summary

[One paragraph with: root cause, affected function, economic impact, attack cost.
Include numbers where possible: "attacker can drain $X in Y transactions."]

## Vulnerability Details

**Contract:** `VulnerableContract.sol`
**Function:** `claimRedemption()`
**Bug Class:** Accounting State Desynchronization
**Severity:** Critical

### Root Cause

[Exact code snippet showing the vulnerable code with comments]

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// Foundry PoC — run: forge test --match-test test_exploit -vvvv

contract ExploitTest is Test {
    // ... full working exploit
}
```

## Impact

[Quantified: "Attacker can drain X% of TVL = $Y at current rates.
Requires $Z gas. Attack is repeatable."]

## Recommended Fix

[Specific code change with before/after]
```

---

## CVSS 3.1 QUICK SCORING

### Formula
```
CVSS = f(AV, AC, PR, UI, S, C, I, A)
```

### Metric Quick Picks

| Metric | Value | Weight | When |
|---|---|---|---|
| **Attack Vector (AV)** | Network | +0.85 | Via internet |
| | Local | +0.55 | Local access needed |
| **Attack Complexity (AC)** | Low | +0.77 | Repeatable |
| | High | +0.44 | Race/timing needed |
| **Privileges Required (PR)** | None | +0.85 | No login |
| | Low | +0.62 | Regular user account |
| | High | +0.27 | Admin account |
| **User Interaction (UI)** | None | +0.85 | No victim action |
| | Required | +0.62 | Victim must click |
| **Scope (S)** | Changed | higher | Affects browser/OS/other |
| | Unchanged | lower | Stays in app |
| **Confidentiality (C)** | High | +0.56 | All data exposed |
| | Low | +0.22 | Limited data |
| **Integrity (I)** | High | +0.56 | Can modify any data |
| **Availability (A)** | High | +0.56 | Crashes service |

### Typical Scores by Bug Class

| Bug | Typical CVSS | Severity |
|---|---|---|
| IDOR (read PII) | 6.5 | Medium |
| IDOR (write/delete) | 7.5 | High |
| Auth bypass → admin | 9.8 | Critical |
| Stored XSS (any user) | 5.4–8.8 | Med–High |
| SQLi (data exfil) | 8.6 | High |
| SSRF (cloud metadata) | 9.1 | Critical |
| Race condition (double spend) | 7.5 | High |
| GraphQL auth bypass | 8.7 | High |
| JWT none algorithm | 9.1 | Critical |

---

## SEVERITY DECISION GUIDE

### Critical (P1)
- Full account takeover of any user without interaction
- Remote code execution
- SQLi with ability to dump/modify entire DB
- Auth bypass to admin panel
- SSRF to cloud metadata → IAM credentials exfil

### High (P2)
- Mass PII exposure (email, phone, SSN, payment data)
- Privilege escalation from user to admin
- SSRF reaching internal services (data returned)
- Stored XSS executing for all users of sensitive feature
- Payment bypass / financial loss without limit

### Medium (P3)
- IDOR on specific user's non-critical data
- XSS on low-sensitivity page requiring victim interaction
- CSRF on important but non-critical action
- Rate limit bypass on OTP (with effort demonstrated)

### Low (P4)
- Information disclosure (non-sensitive, no PII)
- Clickjacking on sensitive action WITH working PoC
- CORS on limited data

## Impact section — the three-block structure (for partially-verified chains)

When the full chain cannot be verified (missing second account, no victim interaction, locked
redirect_uri), write the Impact section in three explicit blocks — never overclaim and never
hide the gap:

```markdown
### What is PROVEN (tested, evidence attached)
[Numbered facts, each backed by a raw HTTP capture. Attacker capability stated concretely.]

### What this enables (the chain, concretely)
[The attack flow as a step diagram, written as fact about mechanism, not speculation.]

### What I could NOT verify (stated honestly)
[The exact dependency that blocked full verification, and why it requires [second account /
victim interaction / valid credentials]. Per-program rules these were NOT performed.]
```

Then close with a risk-framing paragraph: asset sensitivity + exploitation requirements +
"severity ceiling if [dependency] under-validates" + "verified floor". Triagers reward the
distinction between proven floor and theoretical ceiling — an impact section that admits its
own limits reads as credible, not weak.

## CVSS / severity-field alignment

Before hitting submit, recompute the CVSS vector against the FINAL chain evidence and make sure
the severity dropdown matches the score justified in the body. A pre-submission review flagging
"severity mismatch" (form says Medium, body argues High) means form and body disagree — always
fix the form to match the strongest defensible score, never the reverse.

## Asset field

The H1 asset selector is mandatory. Select the broadest in-scope asset that contains the
vulnerable host (e.g. `*.shopify.com` for a finding on `shopify.okta.com` when the program lists
the wildcard). An empty asset field is a blocking pre-submission issue.

---

## SEVERITY SELF-ASSESSMENT

Each YES raises severity:
```
1. Exposes PII / health / financial data of other users?        → +1 severity
2. Allows account takeover or privilege escalation?             → +2 severity
3. Requires ZERO user interaction from victim?                  → +1 severity
4. Affects ALL users (not specific condition)?                  → +1 severity
5. Remotely exploitable with no internal network access?        → baseline for High+
```

---

## DOWNGRADE COUNTERS

| Program Says | Counter With |
|---|---|
| "Requires authentication" | "Attacker needs only a free account — no special role or permission" |
| "Limited impact" | "Affects [N] users / exposes [PII type] / $[amount] at risk" |
| "Already known" | "Show me the report number — I searched hacktivity and found none" |
| "By design" | "Show me the documentation stating this is intended behavior" |
| "Low CVSS" | "CVSS doesn't capture business impact — attacker can extract [X] in [Y] minutes" |
| "Not exploitable" | "Here is the exact response showing victim's data returned to attacker session" |

---

## THE 60-SECOND PRE-SUBMIT CHECKLIST

```
[ ] Title follows formula: [Class] in [endpoint] allows [actor] to [impact]
[ ] First sentence states exact impact in plain English
[ ] Steps to Reproduce has exact HTTP request (copy-paste ready)
[ ] Response showing the bug is included (screenshot or JSON body)
[ ] Two test accounts used — not just one account testing itself
[ ] CVSS score calculated and included
[ ] Recommended fix is 1-2 sentences (not a lecture)
[ ] No typos in endpoint paths or parameter names
[ ] Report is < 600 words — triagers skim long reports
[ ] Severity claimed matches impact described — don't overclaim
[ ] Never used "could potentially" or "may allow"
[ ] PoC is reproducible by triager from a fresh state
```

Apply the checklist to the artifact you actually ship. A report that passes in thinking still
fails in the file: the length limit, the banned phrasing and the CVSS inclusion are properties of
the delivered text, so when you emit `REPORT_*.md`, the length and phrasing gates get checked
against that file's word count and matching strings — not against a summary you believe you wrote.
Word-count the file before calling it done.

### DELIVERABLE SHAPE — the report content goes in the reply, the file is the archive

The user pastes platform form fields from the chat reply. So the reply carries the report content
itself (title, summary, steps, impact, remediation as copy-paste blocks) and `REPORT_*.md` is
the durable archive of that same content plus attachments. Two consequences:

- **Do not ship a bare file path as the answer.** "Report is written at `<path>`" with no report
  text in the reply is a failed delivery — the user has to open a file manager to get the thing
  they asked for. The reply is the deliverable; the file is the backup.
- **One report per program, in that program's folder.** Findings against different targets never
  share a file and never get merged mid-report. When both a current target and a previous one are
  live, keep their reports in separate program folders and keep their attachment sets separate —
  an `attachments/<target>-<short-bug>/` folder mixing hosts from two programs is an upload
error waiting to happen, and the user edits each submission by hand.
- **Keep the report itself tight.** Everything longer than ~600 words of body prose belongs in a
  link or attachment, not in the Steps / Impact / Remediation fields the triager reads.

---

## CVSS 4.0 QUICK REFERENCE (newer programs)

CVSS 4.0 replaced CVSS 3.1 in November 2023. Some newer programs require it.

### Key Differences from CVSS 3.1

| Metric | CVSS 3.1 | CVSS 4.0 |
|---|---|---|
| Attack Vector | Network/Adjacent/Local/Physical | Same |
| Attack Complexity | Low/High | Low/High |
| **NEW**: Attack Requirements | (didn't exist) | None/Present (replaces some PR/UI) |
| Privileges Required | None/Low/High | Same |
| User Interaction | None/Required | None/Passive/Active |
| Scope | Unchanged/Changed | REMOVED |
| **NEW**: Sub-Impact metrics | (didn't exist) | Vulnerable/Subsequent system impact |

### CVSS 4.0 Score Examples

| Finding | CVSS 4.0 Score | Vector |
|---|---|---|
| Unauthenticated RCE | 10.0 | CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H |
| IDOR read PII, auth required | 6.9 | CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N |
| Stored XSS, admin views it | 8.2 | CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N |
| SSRF → cloud metadata | 8.7 | CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N |

### Quick CVSS 4.0 Calculator
```
Use: https://www.first.org/cvss/calculator/4.0
Key fields:
  VC/VI/VA = Vulnerable System Confidentiality/Integrity/Availability
  SC/SI/SA = Subsequent System (downstream impact)
  AT = None (no special condition) | Present (race/specific config needed)
  UI = None | Passive (victim visits URL) | Active (victim takes explicit action)
```

**Practical rule**: If program uses CVSS 4.0 and you don't know the vector, use the calculator and include the full string starting with `CVSS:4.0/AV:...`. Programs cannot dispute a valid vector string.

---

## PACKAGING — one folder per target, named after the target

The deliverable root is a folder **named after the target/program** (not the engagement slug),
holding the report, its attachments, and the probe scripts. Never a spread of per-field files
the user has to reassemble.

```
<target>/                              # named after the target, e.g. underarmour / crypto
├── README.md                          # index + submit-status table
├── INDEX.md                           # engagement log, one row per target
├── SUBMISSION_DRAFT.md                # whole report when there is a single finding
├── <sub-target>/                      # one folder per host that has a finding
│   ├── SUBMISSION_DRAFT.md
│   ├── attachments/                   # ONLY files that get uploaded to the platform
│   │   ├── <ID>-response.json
│   │   └── <stage>_out.txt
│   └── scripts/                       # probe code + its JSON output
├── _shared/                           # cross-host work, master evidence copy
└── _template/                         # copy this to start the next target
```

Rules that make the tree survive:

- **The root folder is the target name.** A folder named after the engagement rather than the
  target gets renamed by the user on sight. Get it right the first time; do not ship it and
  wait to be corrected.
- **Every file the report's "Evidence attachments" list names must exist at that exact relative
  path.** The body references `attachments/<file>`, so the tree and the body are checked
  against each other before shipping — a dangling path in the shipped report is a failed
  delivery.
- `attachments/` holds only what is uploaded. When the same evidence backs two submissions,
  keep the master copy in `_shared/` and each submission's `attachments/` carries what that
  report's attachment list names. Never attach a mixed set across hosts.
- Keep a `_template/` directory so the next engagement starts as `cp -r _template <target>`.
- When the user asks for the tree in the working profile's `output/` directory, copy it there
  and say which copy is master — two live trees with no declared master drift apart.
- Scripts that write absolute output paths must be re-pointed at their new home before the
  tree is called done; grep the tree for the old root and confirm zero hits.

The report body already contains title, description, steps, impact and remediation as section
headings — the user selects the platform's fields from the body it already carries. Do **not**
emit separate `title.txt` / `description.md` / `form_fields/` files; that shape was rejected and
is the wrong deliverable. A working folder of recon artefacts is fine to keep alongside, but it
is not part of the submission.

### Manifest — hash every attachment before shipping

After the reproducer has been run, emit a `MANIFEST.txt` in the same folder listing each shipped
file with its byte size and SHA-256, generated by script rather than by hand:

```python
import hashlib, os, datetime
out = ["<program> — 附件清单 / Attachment Manifest",
       "Verified UTC: " + datetime.datetime.now(datetime.timezone.utc).isoformat()]
for f in ["REPORT_x.md", "poc_x.py", "evidence_x.txt", "evidence_x.json"]:
    b = open(f, "rb").read()
    out.append(f"{f:<38} {len(b):>8}  {hashlib.sha256(b).hexdigest()}")
open("MANIFEST.txt", "w").write("\n".join(out) + "\n")
```

The manifest proves attachment integrity (the file the user uploads is the file you tested) and
gives the reply a single verifiable table to quote. Ship only files listed in it — inspect the
folder and drop working artefacts that never got hashed.

### PAIRING — the reproduction script must be run, not hand-written

The `poc_` script is an attachment the triager replays, so it has to be the artifact that was
actually executed. Write it, run it, and ship the artifacts it emitted — never ship a script you
did not execute on the same target the report describes. An evidence file whose contents are
hand-assembled prose is worth less than one byte-stream produced by the shipped script, and the
mismatch is obvious when the triager's run disagrees with your attached "evidence".

Two consequences:

- **The script prints its verdict.** Have it emit the deterministic line the report quotes
  (`setup=400 accounts=401 -> DEFECT CONFIRMED`) so the report's claim is generated by the same
  code the triager will run, not transcribed by hand.
- **Execution enforces the safety discipline.** A probe script that only ever sends empty bodies
  or read-only requests is safe by construction; keep it that way and say so in the report's
  testing-safety section. Never let a PoC script create, mutate, or delete real state just to
  make the evidence look richer.

---

## Excluded bug class: reframe as a MISSING CONTROL, never as the excluded thing

Programs routinely exclude a category — "rate-limiting bypass", "DoS", "missing security
headers" — and triage will auto-reject anything wearing that label. A genuinely broken control is
still reportable; the job is to name it correctly:

- **Frame it as the absent control, not the bypass.** 'No brute-force protection on the password
  step' is a missing control. 'Rate limit bypass' implies a limiter exists and you defeated it —
  which is the excluded thing and the auto-reject trigger.
- **Prove absence with a burst, then stop.** N rapid attempts (a dozen is plenty), each carrying a
  real timestamp, all returning the same error, with no `429` / lockout / captcha escalation. State
  the total attempted count and elapsed time; do not run hundreds of requests.
- **Show the same system implements the control elsewhere.** A captcha on signup, or throttling on
  the recovery-OTP step, proves the control exists in the codebase and was simply not applied to
  the target path. That contrast is the strongest form of the argument and it is cheap to collect.
- **Pre-empt the exclusion in the report body.** One line: state that the program excludes
  rate-limiting *bypasses*, note this documents an *absent* control, and say you accept the
  exclusion decision without dispute if triage still sees it that way. That reads as credible and
  removes the triager's easiest dismissal.
- **Score it honestly.** A brute-forceable login with no lockout is P4/P5 territory, not P1 — an
  honest low severity with a solid PoC preserves validity ratio; an inflated one gets rejected
  twice. Say the ceiling AND the verified floor.

---

## FIELD BOUNDARY — when the data you want does not exist

Triagers (and reporters under pressure) will ask for fields the platform never returns — another
user's password, PIN, `secretToken`, full `sk-` key. Two failure modes, both fatal to the report:

- **Fabricating it.** A guessed or synthesised credential is trivially detected and discredits the
  whole submission. Never invent a value to fill a schema field.
- **Harvesting it.** A report containing third-party plaintext credentials is credential theft, not
  disclosure — platforms close it regardless of how the rest of the finding was earned.

Ship the **negative-evidence table** instead. It answers the triager's obvious follow-up ("could an
attacker get passwords from this?") inside the report body rather than in the rejection thread:

```markdown
| Field | Returned by API? | Evidence |
|---|---|---|
| `password` / `pin` values | No | only flags returned: `passwordSet:true`, `pinChangedAt` |
| third-party `secretToken` | No | `GET /api/public/quota/<numeric_id>` → 404 |
| full `sk-` gateway key | No | masked in dashboard payload (`sk-q••••43ff`) |
```

A `null` backed by the request that proves it is null is a stronger artefact than a guess. Include
the reporter's **own** test credentials as the reproduction fixture where a flow needs them — that
is what a repro step calls for, and they are yours to disclose.

---

## HUMAN TONE GUIDELINES

**Write to a person, not a system:**
- Triagers are tired. Get to the impact in sentence 1.
- Use "I" not "the researcher" — you found it, own it
- Short paragraphs, bullet points for steps
- Hyperlink relevant docs if needed

**Escalation language (when payout is being downgraded):**
```
"This vulnerability does not require any special privileges — only a free account."
"The exposed data includes [PII type], which is subject to GDPR requirements."
"An attacker can automate this with a simple loop — all [N] records in minutes."
"This is exploitable externally without network access to any internal system."
"The impact is equivalent to a full data breach of [feature/data type]."
```

**Avoid:**
- Jargon the triager might not know
- 5-paragraph explanations of what IDOR is (they know)
- Theoretical chains ("could be combined with X to...")
- Passive voice ("it was observed that...")
- Qualifying language ("seems to," "appears to")

---

## REPORT LANGUAGE — mirror what the user asked for, per submission

The working language is not a global default. One program's submission may be requested in
Mandarin, another in English, and both can be live in the same session.

- **Write the report body in the language the user named for that submission.** The report file
  (`REPORT_*.md`), its headings, its severity assessment, and its remediation section all follow
  that language. Do not partially translate — a half-English file under Chinese headings reads as
  a machine dump and the user has to rewrite it.
- **Keep technical tokens verbatim inside the target language** — VRT node names, CWE numbers,
  CVSS vector strings, HTTP methods, endpoint paths, header names, and CVSS metric values stay
  in their original form. Only prose is translated.
- **The chat reply follows the report's language for the copy-paste fields** (title, VRT,
  severity, endpoints) so the user pastes one consistent language set into the form, while the
  surrounding explanation to the user stays in the language the user converses in.
- **Same-craft, not softened.** Language changes never softens the severity assessment. A report
  written in Mandarin carries the same honest severity request, the same "not verified"
  admissions, and the same deterministic PoC it would carry in English.
---

## STEPS TO REPRODUCE FORMAT (triager-optimized)

```markdown
**Setup:**
- Account A (attacker): email=attacker@test.com, ID=111
- Account B (victim): email=victim@test.com, ID=222
- Both created via normal registration — no special access

**Steps:**

1. Log in as Account A
2. Send this request (replace `111` with victim ID `222`):

\```
GET /api/v2/resource/222 HTTP/1.1
Host: target.com
Authorization: Bearer ACCOUNT_A_TOKEN
\```

3. Response contains Account B's private data:

\```json
{"id": 222, "email": "victim@test.com", "name": "Victim User", "address": "..."}
\```

**Expected:** 403 Forbidden
**Actual:** 200 OK with victim's private data
```
