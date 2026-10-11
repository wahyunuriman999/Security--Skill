# Gateway / Provider Error Taxonomy

Decision table for classifying a failed inference call on an OpenAI-compatible
gateway or a local multi-provider proxy. Classify BEFORE picking a fix — most
"retry harder" effort is spent on the wrong class.

## By status and body

| Signal | Meaning | Cure |
|---|---|---|
| `401 invalid_api_key`, identical on every endpoint including `/models` and billing | Key is unknown or revoked | Stop. No request shape fixes it; report the key as dead. |
| `401` on payload endpoints only, discovery answers | Route or policy requirement, key is live | Harvest the docs/policy/adapter hints from the error body and follow them. |
| `403` on payload with discovery open, body names quota/balance/credit | Valid key, empty account — the billing wall itself | Top-up. Say so plainly; do not hunt a request-side workaround. |
| `402 Paid Model — Credits Required` (often wrapped in a `503`) | Same as above, per-model gate | Same as above. The outer status is the proxy's envelope, not the cause. |
| `404 No active credentials for provider X` | Provider registered but the proxy has no credential wired for it | Fix the wiring. The key may be perfectly valid. |
| Connection refused / no route on a `127.0.0.1:<port>` base_url | Upstream process down, or the config's port is wrong | Check the listener before auditing request shape. |
| Instant empty body carrying a `blockReason` | A pre-inference classifier rejected the request before the model read it | No prompt-level technique reaches the model. Switch models or re-scope the ask. |
| Slow, well-formed prose that politely declines | The model's own refusal | Prompt-level work may still pay off here; test framing on this model. |

## Reads that change the verdict

- **Discovery is not entitlement.** A `/models` listing on a proxy is the vendor
  catalogue plus whatever the proxy can route to. It proves nothing about a
  specific model ID.
- **Per-model, never per-gateway.** Keys can be scoped to a model allow-list and
  each model names its own error. Smoke the exact ID you intend to ship.
- **Chat OK is not agent OK.** Runtimes gate tool support per model; a model that
  answers chat can still refuse `tools`. Send one tool-bearing request before
  adopting a local model as an agent default.
- **A public endpoint's 200 proves the service is up, never that your key works.**
- **An alias and its provider block must agree on base_url** — a mismatch only
  fails when that alias is actually used.

## What each class means for effort

Two of these (dead key, empty balance) have no technical workaround, and one
(local process down) is not a request problem at all. Recognising the class on
the first probe is what keeps a triage pass from turning into a hunt for a bypass
that does not exist.
