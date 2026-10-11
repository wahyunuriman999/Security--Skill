---
name: jwt-token-analyzer
version: 1.0.0
description: JWT analyzer for cross-tenant testing
license: MIT
---

# JWT Token Analyzer

JWT analyzer for cross-tenant testing with CVE-942/CWE-346 focus.

## Tools
1. nantzzsec/jwt-analyzer - defensive, zero deps
2. bavamont/jwt-security-analyzer - 22 attack vectors
3. calebosburn/jwt-analyzer - CLI with alg confusion

## Usage
```bash
# nantzzsec (defensive, zero deps)
python jwt_analyzer.py --token "<jwt>" --output report.json

# calebosburn (CLI)
python -m jwt_analyzer.main <TOKEN> --json

# bavamont (desktop)
npm run start
```

## Cross-Tenant Testing
```bash
# Compare tokens across tenants
python jwt_analyzer.py --token "$token1" --output tenant1.json
python jwt_analyzer.py --token "$token2" --output tenant2.json
```

## Key Findings
| Finding | CWE |
|---|---|
| alg confusion (RS256->HS256) | CWE-347 |
| alg none bypass | CWE-347 |
| weak HMAC secret | CWE-347 |
| kid injection | CWE-347 |
| privilege escalation | CWE-269 |

## Integration with rat_h3
```python
from rat_h3 import fetch
async def test_cross_tenant(host, token_a, tenant_b):
    status, headers, body = await fetch(host, "/api/endpoint",
        extra_headers={"authorization": f"Bearer {token_a}", "x-tenant-id": tenant_b})
    return status, body
```