# Security--Skill

A battle-tested security skill arsenal for AI-assisted bug bounty hunting and red-team operations.

Built and hardened through live authorized engagements (HackerOne: crypto.com, Shopify), Indonesian ISP middlebox territory, and real report-submission feedback loops.

## What's inside

| Layer | Contents |
|---|---|
| **hunt-\* skills** (58) | Per-vulnerability-class hunting methodology: detection patterns, payload tables, bypass techniques, chain templates — each distilled from public disclosed bug bounty reports (681 total report patterns across 24 vulnerability classes) |
| **Enterprise platform skills** (10) | Okta, M365/Entra, cloud IAM, vCenter, enterprise VPN, APK/iOS red-team pipelines |
| **Web3 audit stack** (21) | Solidity/DeFi bug classes, Foundry PoC, fuzz harness, meme-coin audit, storage-safety analysis |
| **Tradecraft** | HIV-principle evasion framework (glycan shield, latency, mutation, reservoir, integration), red-team mindset discipline, triage 7-Question Gate, evidence hygiene |
| **Custom tooling** | `rat_h3.py` (QUIC/HTTP-3 client that bypasses TCP middleboxes), `rat_ghost.py` (browser-fingerprint session layer), `rat_oob.py` (OOB callback toolkit), `rat_digest.py` (HTTP digest auth attack toolkit) |

**Start here:** [`INDEX.md`](../INDEX.md) — decision tree + full skill map (110 skills by category, overlap notes).

## Repo hygiene (2026-10-12)
- 110/110 skills carry `version` + `license` frontmatter (validated).
- `tools/tests/` — correctness test suite (8 tests, all green). Run:
  `~/workspace/rat-tools-venv/bin/python -m unittest discover -s tests`
  from `~/workspace/skills/_shared/tools/`. Covers: multi-value header
  collection, gzip/brotli/deflate decompression, DoH response parsing,
  RFC 2617 digest vectors, digest parse/crack round-trip, OOB module health.
  `rat_ghost.py` is excluded from the harness by design (author review only).

## Skill categories

```
security/
├── hunt-*.md          # 58 vuln-class hunting skills (XSS, SQLi, SSRF, IDOR, OAuth, ...)
├── okta-attack        # Okta-as-IdP red-team chain
├── m365-entra-attack  # Microsoft 365 / Entra ID chains
├── web3-*.md          # Smart contract audit stack
├── triage-validation  # 7-Question Gate — kills weak findings before submission
├── redteam-mindset    # Operator discipline: DO NOT STOP, data-minimization
├── engagement-learning-loop  # Post-engagement lesson ledger (LESSONS.md)
└── ...
```

## Origin story

This arsenal was assembled and battle-tested during authorized bug bounty engagements:

- **HackerOne crypto.com program** — CORS origin-reflection finding, GraphQL surface mapping, WAF fingerprint analysis through Indonesian ISP DNS-hijack + SNI-MITM conditions
- **HackerOne Shopify program** — OAuth state-reuse CSRF chain on `shopify.okta.com` with PKCE-gap analysis
- Every lesson from every engagement is captured in `engagement-learning-loop/references/LESSONS.md`

## Tooling highlights

### rat_h3.py — HTTP/3 direct-to-CDN-edge client
Bypasses TCP-only national middleboxes (DNS hijack + SNI MITM) via QUIC/UDP 443 to Cloudflare edge IPs.
v2: real edge-IP discovery via DNS-over-HTTPS (stdlib), multi-value header
collection (no more set-cookie collapse), gzip/brotli/deflate decompression,
persistent `H3Session` with multiplexed streams + edge-IP failover, and
timestamped evidence transcripts (`capture_dir`).
Requires: `~/workspace/rat-tools-venv` (aioquic, httpx, certifi, brotli).

### rat_ghost.py — Glycan Shield session layer
Full Chrome fingerprint (sec-ch-ua, sec-fetch-*), referer-chain management, cookie capture, human-timing jitter. Requests indistinguishable from real user traffic.

### rat_oob.py — OOB callback toolkit
Tag-based blind-callback polling for SSRF/blind-XSS/LLM-exfil validation. `gen` → fire payload → `wait <tag>`.

## License

Skill content follows the upstream licenses (Claude-BugHunter: MIT/CC BY 4.0, sippts: GPL for adapted digest functions). Custom tooling: MIT.

## Credits

- **Claude-BugHunter** (elementalsouls) — the hunt-* skill bundle, 681 report patterns
- **Pepelux/sippts** — digest auth parsing adapted into `rat_digest.py`
- **Hermes Agent** skill system — the runtime this arsenal lives in
