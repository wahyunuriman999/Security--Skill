# Multi-Host Sweep Pitfalls — False-Positive Rules

Read this BEFORE running a wide subdomain/path sweep. A status-code-only probe
sweeping hundreds of hosts manufactures findings that do not exist. Every rule
below is a body-signature check that must accompany the status code.

---

## 1. SPA catch-alls — the single largest false-positive source

A React/Vue/Next host answers EVERY path with `index.html` (200, ~1-2 KB,
identical body). `/health`, `/status`, `/env.js`, `/metrics`, `/.env` all return
the same app shell — they are not endpoints.

**Rule:** capture the `/` (or `/nonexistent-<random>`) baseline body hash and
byte length per host. Report a path as signal ONLY when its body differs from
baseline. Never treat `200` alone as signal.

Symptom seen in practice: an `env.js` probe returning exactly the index page on a
frontend build-artifact host, and a `prompt-to-miniapp-sample` dev host answering
every path with the same page.

## 2. CDN interstitial pages masquerading as 403/503

Cloudflare (and equivalents) answer origin-authenticated paths with a challenge
page: status 403 or 503, body containing "Just a moment..." or a JS challenge.
A naive probe records this as an auth-gated actuator endpoint.

**Rule:** before treating ANY 403/503 as an app response, assert the body does
NOT contain the interstitial marker. Classify by signature:

| Body signature | Verdict |
|---|---|
| "Just a moment" / cf-challenge script | CDN interstitial — discard |
| App branding, dynamic length | Real app response — investigate |

## 3. Staging/preview instances answer 200 for everything

Hosts like `pre.<company>.com` serve the same fixed-size page on every path,
including paths that would 404 in production. Status codes carry zero
information there; only content diff does.

**Rule:** for a staging host, run the SAME path list twice with a random marker
path inserted. If the marker returns the same body as real paths, the host is a
catch-all — drop it from the path-finding stage and only use it for behavioural
fingerprinting.

## 4. Origin-error status codes are operations, not vulnerabilities

526/520/origin-timeout on a CDN-fronted host is a backend availability event.
It is not reportable unless it persists and impacts the target's own users.

**Rule:** record it, re-probe once after a delay, and discard if transient.

## 5. Public-by-design API responses are not leaks

A GitLab instance exposing `/api/v4/projects` unauthenticated is only a finding
if it returns non-public objects. Verify with a visibility filter:

**Rule:** for any unauthenticated API that lists objects, always run the
restrictive query (`?visibility=internal`, `?visibility=private`, or equivalent)
and count results. Zero results = by design, not a finding. Non-zero = real.

## 6. Storage-host listing probes need the response format to confirm

A bucket/CDN origin returning HTML when you send `?list-type=2` is NOT
confirming anonymous listing — S3 answers with `ListBucketResult` XML.

**Rule:** only accept an anonymous-listing finding when the response body is
S3/GCS XML (`<ListBucketResult>`, `<Contents>`, `<Key>`), not an HTML page.

## 7. JSON catch-all APIs

A backend that returns `{}` with status 200 for every unknown route under a
prefix (seen on `envoy`-fronted app-boot and similar) is a route wildcard, not
an exposed actuator.

**Rule:** diff the body against a known-bad path. Identical empty object on
`/actuator/env` and `/zzz-random` = no actuator.

## 8. The HTML login catch-all on a file-transfer appliance

Some products (MOVEit Transfer and peers) front their whole HTTP surface with
one HTML login page: a fixed byte size (e.g. exactly 5,361 bytes, title
"Server Login") returned for `/`, `/api/v1/token`, `/guest/`, and
`/zzz-random` alike, with 404s suppressed entirely. Status 200 on every path
means nothing there.

**Rule:** record the catch-all's exact byte length and title per host, then
classify a path as real **only when its byte length, Content-Type, or Location
differs**. On these hosts, `302 -> /Web/Account/Login.htm` (a 555-byte redirect
carrying `savedpath`) is the signal of a *real* handler that exists and wants a
session — the redirect target itself is the route. Treat the catch-all body as
the baseline and its redirect as the finding, never the 200.

## 9. A non-matching favicon hash is not a version verdict

A fingerprint that fails to match the vendor's default icon proves only that
the icon was customised. It does **not** prove the software is absent, patched,
or a different version.

**Rule:** compute favicon md5/sha256 and the Shodan-style murmur3
(`http.favicon.hash`) anyway to record the asset, but downgrade any version
claim built on a hash mismatch to *unverified*. When the version genuinely
cannot be pinned from the unauthenticated surface (no banner, no build marker in
the page, CSS, bundle, or config endpoint), say so and score the CVE candidate
as informational — a guessed build is worse than a recorded negative.

## 10. Approach protocol

1. Baseline every host first (status, byte length, body hash, server header).
2. Diff, don't just filter on status.
3. Classify every non-200 by body signature before recording it.
4. Discard CDN interstitials and origin errors before analysis.
5. Only then treat the residue as attack surface.

Running a sweep without steps 1-3 produces a findings list that is mostly
noise, and writing those up as "vulnerabilities" destroys the researcher's
credibility with the program.

</parameter <REDACTED>: this file is not needed; use existing edge-filter-mapping.md instead if it overlaps. Wait, it does not overlap — edge-filter-mapping is about WAF rule mapping. This is about sweep false positives. Keep separate, different topic.>, 