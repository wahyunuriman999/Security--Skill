# Recon-Only Engagement Hardening — Low-Severity Findings

Some engagements forbid exploitation until approval (excluded-submission clauses
against actually exploiting, pivoting, or extracting data). Recon maps the
surface but cannot prove impact, so most candidates land at informational.
Hardening a low-severity candidate into a submittable finding is a specific
craft — and the boundary between "hardened" and "padded claim" must stay visible.

**User preference (always-on): the report is evidence-backed, never claim-backed.
Ship what was tested; state plainly what was not. An unproven claim is worse than
a weaker severity, because triager trust is the asset that pays future reports.**

## 1. The impact-proof gate — write this down first

Before drafting, answer in one line each:

- *(a)* what does an unauthenticated attacker learn or DO that they could not before
- *(b)* which specific field or behaviour carries that value
- *(c)* what was tested to confirm it

If *(c)* is empty, the candidate is a lead — keep it in the ledger, do not draft
the report. Do not let a 200-status-without-auth response become "a finding"
by repetition.

## 2. The method-consistency matrix (proves a control defect, not a quirk)

When an endpoint answers differently per HTTP method (`GET` 200 while `HEAD`/
`OPTIONS` 401), one row proves nothing — a proxy or an edge rule can do that. The
finding becomes a control defect only when the sibling endpoints are consistent.
Build the matrix across BEHAVIOR (not just status codes):

| Endpoint | GET | HEAD | OPTIONS |
|---|---|---|---|
| target-path | **200 (body)** | **401** | **401** |
| sibling-1 | 401 | 401 | 401 |
| sibling-2 | 401 | 401 | 401 |
| sibling-3 | 302 | 302 | 302 |

Ship the table with ONE row differing from all siblings — that is the proof the
filter is bound to a method list rather than the route. Without the sibling rows
the report is an observation.

## 3. The negative-result matrix — the strongest hardening move

A borderline finding dies when the triager wonders "did they even try X?" Write
the negatives into the report so the boundary of the claim is explicit:

```
[ ] method-override bypasses (X-HTTP-Method-Override / X-Method-Override /
    X-HTTP-Method) crossed with POST/PUT on every protected sibling
[ ] header-trust probes (X-Original-URL, X-Rewrite-URL, X-Forwarded-For,
    Referer, Accept, forged Cookie, Bearer null / Bearer x)
[ ] CORS reflection (site origin + attacker origin + Origin: null)
[ ] parameter fuzzing for tenant/org/debug/all/full/internal/admin selectors
[ ] cache exposure (Cache-Control, Expires, Vary, CF-Cache-Status, X-Cache)
[ ] wider namespace sweep — the *class* of endpoint, not just the one found
[ ] the obvious chained primitive (e.g. registration, reset, upload flow)
```

Every line that was probed is reported with its negative result. This converts
"here is a 200" into "here is what this is NOT, tested" and pre-empts the most
common auto-close. A negative that was never run is never claimed.

## 4. CVE ranges are verified against the advisory, never recalled

Version disclosure is submittable only when a real exploit exists — but
recalling affected ranges from memory manufactures false findings that must be
retracted later (a retracted report costs more credibility than an unfiled one).
Before any CVE sentence enters a report:

1. Look the CVE up in the advisory/NVD entry THIS session and quote the exact
   affected range.
2. Compare against the version actually fingerprinted, and state the comparison
   in the report — including when it is NEGATIVE.
3. Verify the CVE's *type* too: rewrites and bypasses are regularly mis-remembered
   as RCE, and the mismatch is fatal to the report.
4. If no applicable CVE exists, say so in the report and drop the claim — the
   configuration/EOL observation can still be filed honestly at its own weight.

## 5. State the boundary affirmatively

Close the impact section with what the finding does NOT establish, phrased as
scope-of-proof rather than apology:

> I did not obtain, and do not claim, any credential, session, customer record,
> or file. No authenticated comparison was possible, and I state that limitation
> rather than infer beyond it.

A triager grants severity to a finding whose author has already mapped its ceiling.

## 6. Report skeleton for a hardened low-severity finding

1. Title — VRT-mapped, with the specific class named
2. Severity request — argue P4 with the axes from §2/§3
3. In-scope justification — quote the engagement's own excluded-submission clause
   and show the finding does not depend on exploitation, pivot, or extraction
4. Summary — one paragraph
5. Steps to reproduce — copy-pasteable request, response status line, verbatim body
6. Control-defect evidence — the method matrix (§2)
7. Negative-result matrix — the boundary (§3)
8. Impact statement — bounded and honest (§5)
9. Remediation — numbered, includes companion items found on adjacent hosts
10. Evidence attachment list — hashes and byte counts; note the absence of cookies
    and Authorization headers in every artifact

## 7. Reading a low-severity candidate honestly

An endpoint named `anonymous-config` returning render/bootstrap values is
plausibly intended behaviour — a suggestive name is evidence AGAINST the finding,
not for it. The same applies to any endpoint whose name describes its own access
model. Check whether the consuming client actually needs the sensitive fields
before claiming disclosure; if the pre-login client renders fine without them,
report the excess as a remediation note rather than a severity driver.

The decisive test for a policy-disclosure claim is an authenticated read of the
same endpoint for comparison. Without an authorized test account that comparison
cannot be made, and the report must say so rather than inferring the worse case.
