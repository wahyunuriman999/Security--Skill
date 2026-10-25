---
name: edge-filter-mapping
description: "Read WAF block pages vs app pages; map edge allow-lists."
version: 1.0.0
metadata:
  hermes:
    tags: [waf, edge-filter, allow-list, upload, fingerprint, recon]
    related_skills: [web2-recon]
---

# Edge Filter Mapping

## When to Use

Load when a target answers probes through a vendor WAF/CDN middlebox and you
must tell "the filter caught it" from "the application rejected it" before
claiming anything — and when a form endpoint's answers disagree between
payloads, which is how the edge rule set leaks.

## 1. Fingerprint both signatures first

Fire two requests at the same endpoint: one benign, one carrying a payload
marker. Record length + hash for each.

- **Block/edge page hallmarks:** fixed small body (commonly 2.4–2.7 KB), a
  `<title>` that echoes the request host and then the vendor name
  (`<host>-->Vendor`), a fixed sentence such as "This Request Was Blocked", an
  incident/transaction ID, the caller's egress IP printed back, and a countdown
  timer script.
- **App page hallmarks:** the product's own branding, dynamic length, real
  content that changes with input.

## 2. Classify by marker line, never by a vendor-name substring

When the vendor's product name is also the site's brand — routine for a
security vendor hosting its own portal, sandbox, or marketing site — matching
the brand in the body misclassifies every app page as a block page. Anchor the
classifier on the block page's fixed marker line and its fixed size class
instead.

## 3. The signature pair is an allow-list oracle

A form endpoint that returns the app page for one input and the block page for
another is publishing the filter's rule set. Map it without ever reaching the
application:

1. Send **inert** content under each filename/extension you care about — valid
   magic bytes plus a unique marker string, nothing that executes.
2. Classify each response by signature.
3. The accepted set is the allow-list; the blocked set is the filter's rule.
4. Only then reason about what the allow-list permits. An extension list that
   admits `.htm`/`.html` but not `.php` variants puts server-side execution out
   of reach on that surface, and the hunt should move.

Interleave controls (a known-allowed file between every probe) and vary the
filename per round — a filter that rate-limits or caches on first sight will
otherwise make the last round disagree with the first.

## 4. Reading the result honestly

An allow-list behaving exactly as the program documented is **not a finding**.
Record it as a mapped control plus a documented non-finding, and spend the
remaining time on the surface the scope actually tasked. Where the filter wins
every variant, the right move is the 5-minute rule: move to another host or
feature rather than escalating against a middlebox that is doing its job.

When an extension is accepted but the program's own instruction text says that
class of file is not a vulnerability on its own, treat the acceptance as the
control working, not as a hit.
