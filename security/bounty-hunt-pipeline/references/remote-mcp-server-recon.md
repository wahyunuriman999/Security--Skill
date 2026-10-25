# Remote MCP Server Recon

Applies when a program lists an MCP server as its own asset (typically a mid-tier
P1). Test it as an **API with a JSON-RPC front end**, not as a chatbot: the
chat-shaped bugs (prompt injection, LLM-output manipulation) are usually excluded
by name, while the auth/authz bugs behind the tools pay normally.

## Transport handshake

The streamable-HTTP transport negotiates on `Accept`. A bare JSON POST to the
endpoint path is refused before any auth check:

```
POST /mcp   (no Accept: text/event-stream)
406  {"jsonrpc":"2.0","error":{"code":-32000,
      "message":"Not Acceptable: Client must accept text/event-stream"},"id":null}
```

Send `Accept: application/json, text/event-stream` with
`Content-Type: application/json`, and read the reply as SSE (the body may be a
`data:` frame rather than raw JSON). A `406` like the above is a transport error,
**not** an auth decision — do not record it as "no auth required".

Discovery documents on the MCP host are public and cheap:

```
GET /.well-known/oauth-protected-resource     # resource, authorization_servers,
                                              # scopes_supported, bearer_methods_supported
GET /.well-known/oauth-authorization-server   # only if the IdP host itself is in scope
```

**`scopes_supported` is the authorization test matrix, not trivia.** It enumerates
the product's authorization axes as a read/write cross-product (e.g. `…role:read:wallets`,
`…role:write:orders`, `…role:write:drops`). Build the scope-crossing test from that
list directly instead of guessing at privileged actions.

**Hosts named inside a discovery document are separate assets.** The `resource`
and `authorization_servers` values point at the API and IdP hosts; learning their
names by reading a JSON document from an in-scope MCP host does not put those
hosts in scope. Test only hosts that appear in the program's target list.

## Enumerate the catalog in every credential state, not just the anonymous one

The tool catalog is **filtered by credential state**, so an anonymous `tools/list`
is not the surface — it is a bootstrap view. A server gated on an application key
has been seen to list exactly one tool when unauthenticated: a
`get_instant_api_key`-style callable that mints a free key on the spot and whose
description names the header to send it in (`X-API-KEY`) and the second credential
wallet-scoped tools need (`Authorization: Bearer <wallet JWT>` — bootstrap one with `references/siwe-wallet-jwt-auth.md`). Call it, then
re-handshake with the key and re-list: the catalog expands by an order of
magnitude, and the wallet-scoped half is where authorization bugs live.

Record the three states as separate observations — no credential, free-tier
credential, wallet/account credential — because "tool requires scope X" in a
description is the authorization matrix you test against.

**The pre-auth tool list is a strict subset, so a one-tool catalog proves nothing
about the surface.** Never close an MCP asset on the anonymous view.

The mint endpoint is abuse-limited globally per source IP and answers `429` with a
retry-after measured in tens of minutes. Schedule it — a background job that
sleeps until the window and mints once — instead of polling; and while it waits,
hunt the surfaces that need no credential. On a shared NAT / datacenter egress this is a persistent throttle, not a waitable window: a scheduled mint that slept a full hour still returned `429` with the retry-after *reset* (the bucket mixes in other tenants' attempts on the shared IP). A recurring `429` after a long clean wait is the tell that the egress is shared — stop re-queuing local pollers (each attempt only extends the shared bucket) and route the mint through a VPS / alternate egress instead.

## The tool-level refusal arrives in the body, not the status line

A rejected `tools/call` has been observed as HTTP `401` wrapping a *normal*
JSON-RPC result envelope:

```
401  {"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text",
      "text":"This tool requires an OpenSea API key … call get_instant_api_key"}],
      "isError":true}}
```

Parse the body before recording a verdict. Two consequences: an `isError`
envelope with a 401 status is a *credential-state* answer (the tool exists; you are
not entitled to it yet), and a tool absent from `tools/list` may be filtered rather
than nonexistent. Read `www-authenticate` and any `resource_metadata` pointer off
the same response — that pointer is where the required scope names live.

## Enumerate both transports — the legacy path is a second code path

The modern streamable endpoint is not the only listener. The legacy HTTP+SSE
transport is typically still mounted, and it is a *different* code path with its
own middleware:

```
GET /sse            -> 200, event: endpoint,
                       data: /sse/message?sessionId=<hex>
POST /sse/message?sessionId=<hex>   (each JSON-RPC frame, incl. notifications)
```

Drive the full sequence (`initialize` → `notifications/initialized` →
`tools/list` → `resources/list` → a `tools/call`) through it and compare against the
streamable endpoint. Here both transports enforced the same gate, so the answer was
parity — but establish that by testing, never by assumption: a legacy transport
commonly lacks the middleware retrofitted onto the newer one, and a divergence is
the finding.

**Resources are frequently open while every tool is gated.** `resources/list` and
`resources/read` have been served with no credential at all: the MCP-app widgets
(`ui://widget/<product>/<name>.html`, `mimeType: text/html;profile=mcp-app`) came
back in full. Read them — a server-rendered widget is client-side code the vendor
ships, and its sinks (`innerHTML`, `dangerouslySetInnerHTML`, interpolation of tool
output into markup) are a legitimate review surface for the asset that serves it.
Keep the ruling honest: a bundled framework runtime and a React render path explain
most generic sink hits, so a sink only counts when the interpolated value is
stranger-writable and the write path is shown.

## Reflected origin with credentials is not a finding on this asset class

These hosts answer `OPTIONS` with the caller's `Origin` echoed back plus
`Access-Control-Allow-Credentials: true`, while the plain `GET` returns `*`. That
looks like the classic misconfiguration and is not exploitable here: authentication
rides explicit headers (`X-API-KEY`, `Authorization`) and no session cookie is set,
so a browser on an attacker origin cannot make a credentialed cross-origin read.
Report it only with a proven credentialed read in hand; header echo alone is the
noise a triager closes as informational.

## Enumeration sequence

1. `initialize` (protocolVersion + client capabilities) → `notifications/initialized`
   → `tools/list`. Then read every tool's `inputSchema` before calling anything.
2. Classify each tool by its arguments: object **identifiers**, **URLs/hosts**,
   **paths**, **amounts**, and whether it **mutates** state. That classification is
   the whole test plan.

## What to test, in order

1. **Unauthenticated reachability.** `tools/list` and one read-only `tools/call`
   with no `Authorization` header. Which tools does the server gate, and what does
   the refusal look like (401 `resource_metadata` pointer vs a JSON-RPC error)?
   An unauthenticated *mutating* tool is the critical result here.
2. **Scope crossing.** Call a tool requiring scope B with a token granting only
   scope A — the discovery scope list gives both halves. Multi-scope MCP servers
   rarely re-check scope per tool.
3. **Object-level authz.** Any tool taking an identifier is the API's IDOR
   surface wearing a different hat: the server fronts the same REST backend, so
   swap in an object belonging to another account and compare against the
   owner's view.
4. **URL/path arguments** → SSRF and file-read probes.
5. **Mutating tools with a weak or read-only token** (create listing, favorite,
   write profile, transfer, place order).

Keep step 1–5 **read-only** until a refusal pattern is proven: tool calls mutate
production state, and program rules generally forbid impacting production. Never
let a mutating test run against real objects to "see what happens".

## Exclusion to confirm before investing

"Manipulation of LLM responses, e.g. via prompt injection" is a standing exclusion
on MCP assets, as is phishing/social engineering. Read the asset's exclusion block
first: those two are the instinctive first tests and they are usually unpaid.

## Neighbouring hosts found while probing

An MCP host typically sits in front of an API host owned by the same product, and
the MCP tool schemas mirror that API. If the API host is also a listed target,
the tool schemas are a free, authoritative endpoint inventory for it — including
routes that may not be documented. If it is not listed, treat the schemas as
architecture notes only.
