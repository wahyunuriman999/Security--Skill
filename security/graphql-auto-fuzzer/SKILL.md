---
name: graphql-auto-fuzzer
version: 1.0.0
description: Safe GraphQL mutation fuzzing with chain generation
license: MIT
triggers: [graphql, auto, fuzzer]
---

# GraphQL Auto-Fuzzer

Safe GraphQL mutation fuzzing with dependency-aware chain generation.

## Tools
1. GraphQLer - dependency-aware fuzzing
2. GQLMap - automated pentest
3. graphql-fuzz - structure-aware
4. CrackQL - brute-force utility

## Usage
```bash
# GraphQLer
python -m graphqler --mode compile --url https://target.com/graphql --path ./out --auth "Bearer TOKEN"
python -m graphqler --mode fuzz --url https://target.com/graphql --path ./out --auth "Bearer TOKEN"

# GQLMap
python gqlmap.py https://target.com --crawl --introspect

# graphql-fuzz (Rust)
cargo add graphql_fuzz rand
```

## Safety
- Use --disable-mutations for recon
- Use read-only token first
- Set --max-iterations
- Rate limit with --delay
- Never use admin token

## Integration with rat_h3
```python
from rat_h3 import fetch
import json
async def graphql_query(query, variables=None):
    payload = {"query": query}
    if variables: payload["variables"] = variables
    status, headers, body = await fetch(host, "/graphql", method="POST",
        extra_headers={"content-type": "application/json"}, body=json.dumps(payload).encode())
    return status, body
```