---
name: merchant-graphql-idor-tester
version: 1.0.0
description: Merchant GraphQL IDOR tester for cross-account testing
license: MIT
---

# Merchant GraphQL IDOR Tester

pay.crypto.com/graphql IDOR tester for cross-account testing.
Requires valid merchant account.

## GraphQL Mutations
- CreateSubscription, cancelSubscription, recollectSubscriptionPayment
- updateTeam, acceptTerms

## Queries
- subscription (accountId, subscriptionId)
- subscriptions (accountId, page, perPage)

## IDOR Test Matrix
| Test | Session A | Target B | Vulnerable If |
|------|-----------|----------|---------------|
| subscriptions query | Account A | Account B ID | Returns B's subs |
| subscription query | Account A | Account B sub ID | Returns B's sub |
| createSubscription | Account A | Account B IDs | Creates for B |
| cancelSubscription | Account A | Account B sub ID | Cancels B's sub |
| recollectPayment | Account A | Account B invoice | Recollects B's |
| updateTeam | Account A | Account B team | Updates B's team |

## Auth
```python
from rat_h3 import fetch
async def test_idor(session_a, account_b_id, query, variables):
    body = {"query": query, "variables": variables}
    status, headers, body = await fetch(
        "pay.crypto.com", "/graphql", method="POST",
        extra_headers={
            "content-type": "application/json",
            "origin": "https://merchant.crypto.com",
            "referer": "https://merchant.crypto.com/",
            "cookie": session_a
        },
        body=json.dumps(body).encode()
    )
    return status, body
```

## Safety
- Only your own merchant accounts
- No real orders/payments
- Use dry-run where possible
- Respect rate limits