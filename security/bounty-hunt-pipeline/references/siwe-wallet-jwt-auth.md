# SIWE → PAT → Wallet JWT (identity bootstrap for wallet-scoped MCP/API)

When an in-scope MCP server or API gates wallet-scoped tools behind
`Authorization: Bearer <wallet JWT>`, mint a legitimate test identity from a
throwaway key with NO funded wallet and NO email signup. Verified working against
OpenSea's auth (`api.opensea.io`), RS256 JWT issued by Zitadel
(`iss: https://auth.opensea.io`).

Keypair + signing need `eth-account`; install into an isolated venv with
`uv venv ethvenv` + `uv pip install --python ethvenv/Scripts/python.exe eth-account`
— `import Crypto` / `coincurve` / `eth_account` are NOT in the stock Hermes python.

## Flow (each step returns 200 only when the previous state is carried forward)

1. `Account.create()` (or `Account.from_key(pk)` to reuse) → checksummed `address`.
2. `POST /api/v2/auth/siwe/nonce` (no auth) → `{"nonce":"<alphanumeric>"}`.
3. Build the message BYTE-EXACT — the server re-derives the same string to
   `ecrecover`, so any whitespace slip silently fails verification:

```text
opensea.io wants you to sign in with your Ethereum account:
<checksummed-address>

Click to sign in and accept the Platform Terms of Service (https://opensea.io/tos) and Privacy Policy (https://opensea.io/privacy).

URI: https://opensea.io
Version: 1
Chain ID: 1
Nonce: <nonce>
Issued At: <JS ISO with ms + Z, e.g. 2026-10-23T08:05:53.249Z>
```

   Construction rule, not the literal: `prefix =
   "{origin} wants you to sign in with your {accountType} account:\n{address}\n\n{statement}\n"`
   (origin = `opensea.io`, no scheme, so it is the bare domain; accountType =
   `Ethereum`), `suffix = "URI: https://opensea.io\nVersion: 1\nChain ID: 1\nNonce:
   {nonce}\nIssued At: {iso}"`, then `message = prefix + "\n" + suffix` — there is a
   blank line between the statement and `URI:`.
4. Sign with **EIP-191 personal_sign** (`encode_defunct(text=msg)`), NOT EIP-712 / typed data.
5. `POST /api/v2/auth/siwe/verify` with body
   `{"message": <parsed msg object>, "signature": "0x…", "chainArch": "EVM"}` where
   the parsed object is `{domain, address, statement, uri, version, chainId, nonce,
   issuedAt, accountType}` (chainId/version are STRINGS). Response carries the user +
   wallet, and `Set-Cookie` with `access_token` + `refresh_token`.
6. Extract the session: `"access_token=…; refresh_token=…"` for the `Cookie` header.
7. `POST /api/v2/auth/tokens` `{label, scopes:[…], expiresInDays:1}` with that cookie →
   PAT (`{id, scopes, token}`).
8. `POST /api/v2/auth/tokens/exchange` `{subjectToken: PAT}` → `{accessToken}` = wallet JWT.

## Scope names (OpenSea) — discovered by trial error, then fix once

The `scopes` array is validated server-side; a wrong name returns
`{"error":{"message":"Invalid scopes: <the exact wrong ones>"}}`. Canonical set observed:

- VALID: `read:eligibility`, `read:favorites`, `write:drops`, `write:favorites`,
  `write:orders`, `write:wallets`.
- INVALID despite looking obvious: `read:rewards`, `read:account`, `read:orders`,
  `read:drops`, `read:collections`, `read:traits`, `read:profile`.

Submit only the smallest read-only set first; a fresh wallet returns
`Requested scopes exceed account entitlement` for the write scopes, so branch the
script on that error rather than assuming writes are reachable.

## The resulting JWT — what to read off it

RS256, `kid` → JWKS at `https://auth.opensea.io/oauth/v2/keys`. Claims that matter
for authorization testing: `opensea_scopes` (space-joined string), `linked_wallets`
(array), `wallet` (single address), `sub` (userId). IDOR on wallet-scoped tools =
pass a victim address/account param and check whether the backend binds it to
`linked_wallets` instead of trusting the parameter. To force the signature itself
through `alg:none` / RS256→HS256 confusion, use `hunt-jwt-crypto`, not here.
