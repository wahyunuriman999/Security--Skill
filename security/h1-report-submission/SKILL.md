---
name: h1-report-submission
description: "File H1 reports: weakness fallback map, form fields, fixes."
version: 1.0.0
author: ratman4080
license: MIT
metadata:
  hermes:
    tags: [hackerone, h1, bug-bounty, report, submission, weakness, severity, csrf, oauth]
    related_skills: [report-writing, triage-validation, bug-bounty]
triggers: [report, submission, hackerone, h1, bug-bounty, weakness, severity, csrf, oauth]
---

# HackerOne Report Submission

## When to Use

Load when filling out the H1 report submission form: choosing asset, weakness,
and severity; fixing Report Assistant blocking flags; or structuring the report
body. Pairs with `report-writing` (content quality) and `triage-validation`
(pre-report gate).

---

Cover the form-fill mechanics H1 adds on top of writing a good report.
Report content quality lives in `report-writing`. This skill covers the
platform-specific form fields and submission review gates.

---

## ONE FINDING PER REPORT

Strip ALL unrelated findings before submitting. A report covering five bug
classes reads like research notes — triagers bounce it or split it themselves
and credit only one. Write one focused report per finding.

---

## H1 FORM FIELDS

### Asset

Pick the most specific in-scope asset that matches the endpoint:
- Use the **wildcard entry** (e.g. `*.shopify.com`) when the subdomain is in
  scope but not listed individually.
- If H1 suggests changing asset in the review warning, accept it — the
  triager already knows which asset pays.

### Weakness

H1 weakness dropdowns are **program-specific** and often missing standard OWASP/CWE labels.
Check what is available BEFORE writing the report body, and rephrase the weakness
description to match the label you will actually use.

**Fallback map — use when your ideal term is absent:**

| Ideal Weakness | H1 Dropdown Fallback |
|---|---|
| Cross-Site Request Forgery (CSRF) | `Improper Access Control` (CWE-284) |
| OAuth State Abuse / Missing State Binding | `Improper Access Control` (CWE-284) |
| Authentication Bypass via OAuth | `Authentication Bypass` |
| Open Redirect | `URL Redirection to Untrusted Site` — if absent: `Improper Input Validation` |
| CORS Misconfiguration | `Sensitive Data Exposure` or `Improper Access Control` |
| Missing Rate Limiting | `Business Logic Errors` or `Improper Access Control` |
| Information Disclosure | `Sensitive Data Exposure` — use `CWE-497 Exposure of Sensitive System Information` when the leak is system details via error output (internal hostnames, version prefixes, timestamps), NOT credentials or env vars

Never leave weakness blank. Never pick `Cross-Site Scripting` for a non-XSS bug.

### Severity

H1 severity is typically a slider: `None | Low | Medium | High | Critical`.
Some programs also show `with` / `without` qualification — pick the one that
matches your CVSS vector. If the program overrides severity anyway, let them:
claiming High when evidence supports Medium makes triagers distrust your future
reports.

---

## PRE-SUBMIT VERIFICATION — re-read the code before writing the report body

Before writing any claim about a source-code finding:

1. **Read EVERY service's setup file independently.** A monorepo with two gRPC services can
   have different interceptor chains on each. A blanket claim "no protovalidate anywhere" or
   "no auth interceptors" is wrong if only one service was checked. Read each service's
   `public.go` / equivalent setup file and list the interceptors per service explicitly.

2. **Distinguish dev-mode config from production config.** `ENABLE_ENCLAVE=false` (compose
   default) makes the enclave listen on TCP; `ENABLE_ENCLAVE=true` (production Nitro) switches
   it to VSOCK. The production TCP exposure claim is only valid when the prod config or task
   definition confirms it. State the exact config file and env var that drives the behavior.

3. **Check runtime wiring, not just declaration.** `buf.validate` annotations and a dep in
   `go.mod` do not prove validation runs. Confirm the chain: `protovalidate.New()` in setup +
   `protovalidatemw.UnaryServerInterceptor(validator)` registered on the gRPC server.
   A missing interceptor registration makes all annotations inert.

4. **State honest severity ceilings.** When exploitation requires network reachability of an
   internal port, say so plainly in the Impact section. Disclose preconditions the triager
   will immediately spot; they reward honesty over inflation. Score High, not Critical, when
   reachability cannot be independently confirmed from outside the infrastructure.

5. **File separate reports for distinct root causes.** F1 (no auth interceptor) and F2
   (singleflight race) share the same repo but are independent root causes with independent
   fixes. Never merge them into one report — triage splits or closes the weaker one.

H1's Report Assistant often flags issues before you can submit. Common blockers
and how to fix them:

| H1 Flag | Fix |
|---|---|
| "Report reads like research notes" | Rewrite as a single focused finding — remove all other bug mentions |
| "Missing concrete proof-of-concept" | Add exact curl / HTTP request showing the attack, add response transcript |
| "No asset selected" | Select the matching in-scope wildcard or subdomain |
| "Weakness not found" | Use fallback map above; rephrase body to match new label |
| "Steps not reproducible" | Number every step; include exact request headers, body, and response |

---

## REPORT STRUCTURE (H1-SPECIFIC)

```
Title: [Class] [Exact Control Failure] on [Asset/Endpoint]

Summary
  One paragraph: what, where, what attacker can do.
  No sub-bullets, no research notes covering multiple bugs.

Steps to Reproduce
  1. Numbered. Concrete. curl-ready.
  2. Include exact HTTP request text (method, URL, headers, body).
  3. Include exact HTTP response (status, relevant headers, body snippet).
  4. Include comparison baseline (e.g. missing state returns 302 error).

PoC / Attack Flow
  For CSRF/OAuth: include the attack HTML page or redirect flow diagram.
  For IDOR: side-by-side request from attacker session + victim data in response.

Impact
  Specific. Quantified. Who is affected, what data/access is at risk.

Recommended Fix
  1-3 sentences. Concrete code or config change.

Scope and Safety of Testing
  Brief: no other user's data accessed, no automated scanners, read-only.
```

---

## EVIDENCE REQUIREMENTS

- **Live HTTP transcript** — run the exploit within 24h of submitting;
  include timestamps from `date` or the response `Date:` header.
- **Raw request + raw response** — not paraphrased, not summarized.
- **Baseline comparison** — show the control case that proves your result is
  anomalous (missing state → 302 error; same state → 200 twice = vulnerable).
- **PoC file** — attach as `.html`, `.py`, or `.sh`; triagers reproduce
  from the attachment, not from description alone.

---

## PITFALLS

- **Weakness dropdown varies by program.** Open the dropdown and read all options
  before deciding — CSRF is frequently absent; use Improper Access Control instead.
- **CWE-497 not CWE-200 for system-info-via-error findings.** Leaking internal
  hostnames, API version paths, and server timestamps in error responses is
  Exposure of Sensitive System Information (497), not generic Exposure of
  Sensitive Information (200) — reserve 200 for credentials/PII, and make 209 the
  secondary when the carrier is an error message. Triagers correct this on sight.
- **Asset = the host exhibiting the behavior, not the host disclosed.** When a
  proxy endpoint on asset A reflects the identity of internal host B, A is the
  reportable asset; B is evidence. Selecting B because "the leaked backend is
  more in-scope" gets corrected by triage — pick the asset that serves the
  failing response.
- **Accept non-blocking triage corrections without debate.** When triage offers
  to fix classification/asset in a non-blocking note, apply both immediately to
  the submitted report, reply in one paragraph naming exactly what changed, and
  never counter-request a severity bump in the same reply — it reads as
  negotiating and damages credibility on the next report.
- **Document non-findings to narrow triage.** A short "we tested X and it was
  clean" paragraph (CORS tested, no credentialed reflection) pre-empts the
  triager's first question and signals thoroughness — but only list checks you
  actually ran, with the origin/host values used. A claimed non-finding you did
  not test is a fabricated one.
- **H1 review can suggest a weakness the dropdown lacks.** When the pre-submission
  review names a classification (e.g. "should be CSRF") that is not in the dropdown,
  the dropdown is likely a searchable typeahead — type the suggested term instead of
  scanning the visible list. If it truly is absent, pick the closest CWE-mapped label
  and put the suggested term in the report title and body so the triager sees the
  match.
- **H1 review flags are blocking.** Red (🔴) flags must be fixed before Submit
  is enabled. Yellow (⚠️) flags are advisory — address them anyway.
- **Do not include unrelated findings in the PoC HTML.** Even a comment
  mentioning another bug can cause the triager to split or stall the report.
- **Title must name the exact endpoint or component.** "OAuth vulnerability on
  Shopify" is rejected; "OAuth State Not Invalidated on shopify.okta.com/oauth2/v1/authorize"
  is accepted.
- **Re-capture live evidence on the day of submission** — stale transcripts get
  rejected when the endpoint's behavior has changed.
- **Live-verify before writing the report, not after.** A state-reuse claim is
  only submittable when both requests (first use AND reuse) were re-fired
  within hours of submitting and both returned 200 — re-running the exact curl
  steps IS the evidence capture. Print timestamp, request, status, and key
  headers for each case, plus the rejected baseline, into one `evidence_*.txt`
  the moment the responses arrive. A report written before this transcript
  exists reads as theory and gets flagged as missing proof-of-concept.
- **Validate report claims at the smallest unit the API validates.** For
  GraphQL, probe each claimed field separately after a combined query fails;
  a first invalid field aborts validation and gives no evidence about later
  fields. Mark finite field lists as a tested subset, not a complete schema,
  unless an actual exhaustive enumeration proves completeness.
- **Run the exact shipped reproducer after the final edit.** Regenerate the
  evidence file and manifest from that run, then check that every attachment
  named in the report exists and is hashed; otherwise the report and its PoC
  can silently describe different claims.
- **Keep one finding and one evidence boundary per submission.** Do not mix
  negative recon results, rate-limit blockers, or unrelated endpoint probes
  into the primary report unless they are required to establish the reported
  impact; unrelated research notes make a valid report look speculative.
