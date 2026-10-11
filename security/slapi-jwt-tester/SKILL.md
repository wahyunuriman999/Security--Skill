---
name: slapi-jwt-tester
version: 1.0.0
description: slapi JWT tester for cross-tenant testing
license: MIT
---

# slapi JWT Tester

slapi.travel.crypto.com JWT tester for cross-tenant testing.
Requires valid travel.crypto.com account.

## Valid Tenants
- cdc, moca, superlogic (exist → 401)
- others → 400 (doesnt exist at Cache)

## Cross-Tenant Testing
```python
from rat_h3 import fetch
async def test_slapi_cross_tenant(session_cookies, target_tenant):
    status, headers, body = await fetch(
        "slapi.travel.crypto.com",
        "/v1/orders", method="POST",
        extra_headers={
            "x-tenant-id": target_tenant,
            "cookie": session_cookies,
            "content-type": "application/json",
            "origin": "https://travel.crypto.com",
            "referer": "https://travel.crypto.com/"
        },
        body=json.dumps({
            "accountId": "test",
            "subscriptionId": "test",
            "items": [{"productId": "test", "quantity": 1}]
        }).encode()
    )
    return status, body
```

## Test Matrix
| Source | Target | Expected |
|--------|--------|----------|
| cdc | moca | 401 (secure) / 200 (vuln) |
| cdc | superlogic | 401 / 200 |

## Safety
- Only with your own travel account
- No real orders/payments
- Respect rate limits