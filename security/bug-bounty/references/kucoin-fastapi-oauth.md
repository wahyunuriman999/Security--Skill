# KuCoin Fast API OAuth — Attack Surface Reference

## Architecture Overview

```
www.kucoin.com/oauth                                  # Consent page (user-facing)
www.kucoin.com/_oauth/access-token                    # GET — exchange auth code for tokens
www.kucoin.com/_oauth/refresh-token                   # POST — refresh access token
www.kucoin.com/_oauth/resource/cyber-truck-vault/v2/outer/api-key/add   # POST — create API key
api.kucoin.com/api/v2/broker/withdrawal               # POST — fast withdrawal (broker-tier)
```

Broker registers via form → receives `client_id` + `client_secret`. User does OAuth consent → broker gets `authorization_code` → broker exchanges for `access_token` + `refresh_token` → broker POSTs to `cyber-truck-vault` to generate user's API key → broker uses API key to call KuCoin REST APIs on user's behalf.

## Token Mechanics

- `access_token`: valid 1 hour, used as `Authorization: bearer <token>` header
- `refresh_token`: valid 3 days; refreshing invalidates old access token immediately
- Permissions on the API key are derived from `authGroupMap` passed to `cyber-truck-vault`

## Permission Flags (authGroupMap)

```json
{
  "API_COMMON": true,
  "API_SPOT": true,
  "API_MARGIN": true,
  "API_FUTURES": true,
  "API_EARN": true,
  "API_TRANSFER": true,
  "API_WITHDRAW_OAUTH": true,
  "isAddressbookOnly": false
}
```

`isAddressbookOnly: false` = withdraw to ANY address. `true` = address book only.

## PRIMARY VECTOR — `authGroupMap` Injection (Critical/P1)

**Design flaw:** KuCoin instructs brokers to pass `authGroupMap` "exactly as returned" from the OAuth callback but does NOT re-verify this server-side. The `cyber-truck-vault` endpoint trusts the broker's POST body.

**Attack:** Broker (malicious or compromised) modifies POST body:
- Set `API_WITHDRAW_OAUTH: true` even though user authorized `false`
- Set `isAddressbookOnly: false` to bypass address book restriction

**Result:** API key with withdrawal permission user never granted. Broker calls `POST /api/v2/broker/withdrawal` to attacker wallet.

**Safe PoC (zero funds moved):**
1. Complete OAuth as own test account with withdrawal disabled
2. Intercept broker POST to `cyber-truck-vault`
3. Inject `API_WITHDRAW_OAUTH: true`
4. Check returned API key permissions via `GET /api/v1/user/api-key/info`
5. If `API_WITHDRAW_OAUTH: true` returned → confirmed, stop here

**Scale impact:** Compromised broker → ALL broker users exposed (mass exfiltration).

## SECONDARY VECTOR — Refresh Token Scope Escalation (Critical/P1)

`POST /_oauth/refresh-token` requires `scope` as broker-supplied (compulsory per docs). Test:

```http
POST https://www.kucoin.com/_oauth/refresh-token

{
  "grant_type": "authorization_code",
  "refresh_token": "<valid_refresh_token>",
  "scope": "OAUTH_CREATE_API API_WITHDRAW_OAUTH"
}
```

If server returns token with expanded permissions without re-consent → privilege escalation.

## TERTIARY VECTOR — OAuth State CSRF → ATO

Consent URL: `https://www.kucoin.com/oauth?response_type=code&client_id=X&redirect_uri=X&scope=OAUTH_CREATE_API&state=123`

`state` documented as compulsory but server-side enforcement is the test. Attacker initiates flow → tricks victim into completing it → victim's KuCoin account linked to attacker's broker session.

## QUATERNARY VECTOR — WebSocket Auth Downgrade

V2 WebSocket migrating from Connect Token → Signature-based auth creates a window where both may be valid:

```
POST https://api.kucoin.com/api/v1/bullet-private   # legacy: get Connect Token
wss://wsapi.kucoin.com/endpoint?token=CONNECT_TOKEN  # test on V2 WebSocket endpoint
```

If V2 accepts legacy Connect Token → private channel access without HMAC signature.

## Broker Registration (Required for Testing)

Public form: https://docs.google.com/forms/d/e/1FAIpQLScvGVN4_iUOZ_yemX730vc3T0ehEYvTv4hmBDYuF-zPC-jryw/viewform

Alternative: find any existing broker app using KuCoin Fast API — their `client_id` is embedded in the OAuth authorize URL they expose publicly.

## Why Anti-Mainstream

- Standard hunters target CSRF on user-facing consent page or classic sub-account IDOR
- The `cyber-truck-vault` server-to-server leg is audited by almost no one — requires understanding the full broker flow, not just the user-facing OAuth page
- `isAddressbookOnly` is underdocumented and not obviously security-critical at first glance
- Refresh token `scope` injection requires careful reading of RFC 6749 §6 against KuCoin's implementation
- Endpoint name `cyber-truck-vault` signals recent addition — less battle-tested

## API Key Permissions Endpoint

```
GET https://api.kucoin.com/api/v1/user/api-key/info
KC-API-KEY: <generated_key>
KC-API-SIGN: <hmac_signature>
KC-API-TIMESTAMP: <ms>
KC-API-PASSPHRASE: <passphrase>
KC-API-KEY-VERSION: 3
```

Returns permission list — use this to prove an injected permission was accepted without executing any withdrawal.
