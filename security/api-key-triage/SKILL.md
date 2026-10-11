---
name: api-key-triage
description: Verify unknown API keys and gateway auth state.
version: 1.0.0
author: ratman4080
license: MIT
metadata:
  hermes:
    tags: [api-key, credentials, gateway, openai-compatible, triage, auth]
    related_skills: [blocked-page-recovery, godmod]
---

# API Key Triage

## When to Use

Use when handed a base URL + key pair (OPENAI_BASE_URL / OPENAI_API_KEY style),
any unfamiliar OpenAI-compatible or OpenRouter-style gateway, or any service
returning opaque auth errors — before spending turns on bypass attempts.

## Goal

Determine whether an unknown API credential actually works, where its limits
are, and what route to use.

## Always-on rules

1. **Read the gateway's own docs before probing.** Auth-error bodies almost always
   carry `docs_url`, `policy_endpoint`, `mcp_tool`, or an `adapter` field. Fetch
   that doc first; it names the required protocol. Gateways put their truth in
   error payloads — treat every error body as a map, not a wall.
2. **Distinguish key-state from account-state.** A 401 identical across every
   endpoint (including billing) means the key is unknown/revoked. A 401 only on
   payload endpoints while discovery works means a policy or route requirement.
   Verify with the gateway's own key-inspection endpoint (`/key`, `/auth/key`,
   `/credits`) before theorizing. A 403 on payload with discovery still open means
   a *valid key with exhausted balance* — a different verdict from a dead key, and
   the only cure is a top-up, not a better request.
3. **Test endpoints without a key as a canary.** If `/models` returns byte-identical
   bodies with and without the key, that endpoint is public and proves nothing
   about the key. Any 200 that ignores auth is a false positive — never report it
   as "the key works".
4. **Probe per-model, not per-gateway.** A gateway where 9 of 10 model IDs answer
   `403 quota zero` is balance-gated, not model-gated; one model returning a single
   `200` means that model's bucket happened to have credit, not that the catalogue
   is open. Smoke the *specific* model ID you intend to ship, since keys can be
   scoped to a model allow-list and each model names its own error.
5. **Treat an endpoint that hangs as an unusable endpoint, not a slow one.** If a
   chat call exceeds its timeout on every attempt while a sibling route answers in
   seconds, drop that provider — record it and move on. Do not park it as a
   fallback, because a hanging default burns the user's turn before any fallback
   can fire.
6. **Never send credentials as command arguments** — put them in env vars or a
   `.env` read via `--env-file`; argv leaks into process listings.
7. **Write all curl `-o` / `-D` targets to the scratch dir.** On MSYS/Windows
   hosts a bare `/tmp` path silently fails mid-write (curl error 23, truncated
   bodies). Use `$TMPDIR` or an explicit native-style path under the workspace.
8. **Balance-gated services have no bypass to find.** Credits/limits on prepaid
   AI gateways are the billing mechanism itself; the "free" surface is the
   $0-priced catalogue plus unauthenticated tool endpoints. Say so plainly
   instead of hunting for a workaround when the key is dead.
9. **Follow docs for alternate hostnames.** Providers alias API hosts
   (`api.x.so` vs `www.x.so`); docs code samples often reveal the host whose
   key-inspection and chat routes actually answer. Probe both before concluding.
10. **Classify the error class before choosing a fix.** One gateway returns four
    verdicts that get conflated: `401 invalid_api_key` (the key itself is
    rejected), `404 No active credentials for provider X` (the provider is
    registered but unwired — a wiring bug, and the key may be perfectly valid),
    `402/403` naming credits/quota/balance (valid key, empty account), and
    connection-refused on a local `127.0.0.1` port (the upstream process is
    down or the config's port digit is wrong). Each has its own cure; retrying
    the request cures none of them. See
    `references/gateway-error-taxonomy.md`.
11. **A local model that answers chat but refuses `tools` is not an agent
    model.** Runtimes gate tool support per model, so every chat smoke test can
    pass while every agent loop fails. Send one request carrying a `tools`
    array before adopting a local model as a default, and record which models
    pass.

## Procedure

1. Smoke the discovery endpoint (`/models`) with and without the key — compare
   hashes to detect whether it validates auth at all.
2. Attempt the payload endpoint once (`/chat/completions`) and read the FULL
   error body. Harvest every URL/tool/adapter hint it contains.
3. Fetch the hinted docs (setup guide, npm README, adapters). Determine the
   required request shape before any further code.
4. Call the key-inspection endpoints: `/key`, `/auth/key`, `/credits`, and any
   dashboard equivalents on both hosts. This is the authoritative verdict on
   whether the key exists and has balance.
5. If a special route is required (e.g. encrypted/private inference), install the
   vendor adapter and run its `doctor`/verification command — it validates
   attestation without paid inference and separates your local setup from
   server-side rejection.
6. Report per-endpoint results in a table: what answered, what 401'd, and what
   the gateway itself said the state is. Do not mask a dead key as "limited".

## Pitfalls

- An error type named after a policy (e.g. `incognito_error`) can be the generic
  rejection envelope for ANY invalid key — read the message, don't decode the type.
- A 200 on a public catalogue proves the service is up, never that your key is good.
- Vendor E2EE/TEE routes can pass local attestation and still be rejected at the
  gateway edge; that combination means account/key state, not your implementation.
- A 403 whose body says quota/balance/credit is exhausted is the billing wall
  itself — there is no request shape that moves it. Verify the balance endpoint
  before writing any request-side workaround, and report the balance figure
  together with the per-model error so the verdict is unambiguous.
- Inline JSON/status parsing in shell one-liners breaks on quoting and escaped
  payloads; when a probe needs more than a status code, write the loop as a small
  script file with urllib and print compact per-model lines.
- npm adapter `latest` and `next` tags can differ; install the version the docs
  pin and run the tarball's own CLI rather than assuming the registry default.
- Modules imported by a vendor's raw script resolve only when the script sits
  inside its package dir next to `node_modules` — copy it there before running.
- A config block's base_url port is a claim, not a fact. Confirm the listener
  with a direct call to host:port before treating the provider as broken — one
  wrong digit presents as a dead provider and sends you auditing request shapes
  that were never at fault.
- A proxy can advertise a model for a provider whose credentials were never
  registered, so `/models` may list an ID that returns `404 no active
  credentials` on every call. A listing is routing metadata, not entitlement.
- When a user asks whether a removed provider still exists, answer from a fresh
  per-model payload call, not from the config file: present-but-blocked and
  absent-but-listed need opposite answers.
