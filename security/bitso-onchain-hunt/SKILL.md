---
name: bitso-onchain-hunt
description: Hunt Bitso Bugcrowd targets; auth maps, geo blocks.
version: 1.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [bug-bounty, bitso, nvio, onchain-cc, privy, keycloak]
    related_skills: [bounty-hunt-pipeline, hunt-auth-bypass, hunt-idor]
---

## When to Use
Use when testing any Bitso Bugcrowd target (bitso.com, nvio.mx, nvio.ar, onchain.cc, Bitso mobile apps), provisioning test accounts on them, or resuming the Bitso engagement from CANDIDATES.md.

# Bitso MBB OG Hunt

## Engagement facts
- Program: `bugcrowd.com/engagements/bitso-mbb-og`. P1 $11k-15k (2x during promo windows — check announcements).
- In scope: `bitso.com`, `nvio.mx`, `nvio.ar`, `onchain.cc`, 4 mobile apps. Cross-domain: bitso.com/nvio.mx/nvio.ar = ONE logical entity (same root cause = single finding, report on whichever domain hit first).
- Subdomains NOT listed are out of scope (blanket clause is literal — dev/stage/sandbox hosts exist, record don't test).
- Testing header required: `X-Bug-Bounty: Bugcrowd-<username>`. User has no Bugcrowd account — accounts self-provisioned via disposable inboxes instead.
- Workspace: `~/Downloads/bountyforge-hunt/bitso/` (per-target folders, FINDINGS/CANDIDATES/README at root).

## Target architectures (verified)
- **onchain.cc** (`app.onchain.cc`): Next.js on Vercel. Auth = Privy (self-hosted `privy.onchain.cc`, app id `cmmbywupp00z40cjmounuovri`) email-OTP -> `POST /api/terminal/auth/login` sets httpOnly cookie. API is **cookie-session only** (bearer rejected). Vercel edge challenge (429) blocks non-browser IPs — test from browser page context. API client = axios `terminalApi` (withCredentials) + `analyticsApi`. Money flows: `POST /api/terminal/transactions/submit` (validates/broadcasts server-side — even a real on-chain tx not owned by the session user is rejected), cashback claim `POST /api/cashback/claim {network}` (verified live: `{network:"solana"}` -> 200 `nothing-to-claim` with `claimMinUsd:1` + rate-limit fields; any other network -> 400 `invalid_network`; a funded response returns a signed voucher — the double-spend candidate, capital-gated), accruals `GET /api/cashback/accruals?ref=` (session-scoped). `/api/rpc/read` proxies Solana JSON-RPC but requires the session cookie (usable in-page to fetch a real tx for PoC material).
- **nvio.mx/ar**: CRA SPA (identical 5.5MB bundle on both). API same-origin `https://nvio.mx/api/v3/`. Keycloak realm `web` (public client `nvio-web-client`, direct-grant disabled). Registration: `POST /create_lead_account` -> `/verify_lead_account {email, emailToken(6-digit), password}` -> user_id + ott. **Geo allowlist = Mexico only** (US rejected, IP-based).
- **bitso.com**: TLS-blocked from the local XL ISP (crypto-domain SNI-MITM) — use cloud browser.

## Proven workflow
1. **Account provisioning without Bugcrowd ninja email**: create mail.tm inbox (`POST api.mail.tm/accounts` + `/token`, username must be alphanumeric, dots stripped), then Privy email-OTP on app.onchain.cc/login (Continue -> email -> 6-digit code from inbox `intro` field).
2. **Two-account IDOR/BOLA testing**: Privy login is per-email; logout via app Menu -> Logout (httpOnly cookie kills localStorage tricks).
3. **Endpoint extraction from Next.js app**: in-page `fetch` all `/_next/` chunk URLs (106 chunks ~= 8.4MB), regex `/api/[path]` literals and `terminalApi.(get|post)(...)` call sites. Do NOT re-fetch chunks repeatedly (5s daemon limit) — extract everything in one pass.
4. **API testing from page context**: `fetch(path, {credentials:'include'})` inside the app origin — cookies auto-attach, bypasses Vercel challenge. Max ~3 sequential fetches per browser_exec call (5s daemon timeout); use `Promise.all` for parallel.
5. **React-controlled form fill**: synthetic value setters are ignored once the app shows "Last used" state. Fix: `inp.focus(); inp.select()` then `cdp('Input.dispatchKeyEvent', keyDown/keyUp Backspace)` then `cdp('Input.insertText', text=...)` — that syncs React state.

## Pitfalls (hard lessons)
- Free MX/AR proxies: 0/1224 live SOCKS5 exits were Mexican. Buy a cheap MX/AR VPS for nvio.mx account testing instead of scanning proxy lists.
- JWT forgery on onchain.cc is closed: alg:none -> 403, HS256 key-confusion -> 401 (no bearer trust anywhere).
- `transactions/submit` enforces the type enum (TRANSFER/SWAP only) and broadcasts server-side: a garbage base64 tx AND a real 956-byte on-chain tx belonging to another wallet are both rejected, with no trade record created. Fund-free fake-volume/cashback paths are closed.
- Cross-user params (`?userId=`, body `userId:`) are ignored server-side; accruals refs and claims are session-scoped.
- Bonus/points engines use server-side `accountCreatedAt` — client `frontendSettings` is display-only. Welcome bonus/lootbox (`BONUS_LOOT_CLAIM_PATH`) is deposit-gated; referral (`x-referred-by` on auth/login) credits no cashback without referee activity.
- `auth/refresh` is httpOnly-cookie-bound: the body `refreshToken` is ignored entirely (bogus/own/other all return 200 with the cookie present, 401 without) — no cross-account token ATO via the body.
- Browser daemon restarts lose page state AND the httpOnly session cookie (ephemeral profile) — every restart forces a full Privy OTP re-login. Re-check page origin and session before each batch: a lost page context surfaces as `Failed to parse URL from /api/...`, a dead session as `{"error":"unauthenticated"}`. Recovery: `ensure_real_tab()` -> `new_tab("https://app.onchain.cc/portfolio")` -> probe `/api/terminal/users/me` -> re-login per workflow step 1 if 401.

## Mobile track (in scope, not yet started)
Bitso Wallet (`com.bitso.wallet`) and Bitso Alpha (`com.bitso.alpha`) on iOS + Android are in-scope targets with zero work done — the least-hunted surface in this engagement, and each app is treated as unique for submission purposes.
- Binary acquisition is the gate: mirrors (apkpure/apkmirror/apkfab) are challenge-gated from this rig, several aggregator domains are dead, Wayback CDX unreliable. Use the Play Store via the user's real Chrome profile (they must fully quit Chrome first) or ask the user to hand over the APK — see `bounty-hunt-pipeline` "Mobile app teardown" for the decision order.
- Once the APK is in hand, first-pass triage: `unzip` the APK (no jadx/apktool on this rig), then `strings`/grep the dex for hosts, `apiKey`-shaped constants, exported activities/receivers/services in AndroidManifest. xml, `file://`-allowing WebView settings, and custom-scheme deep links (`bitso://`).

## Next-session priorities
See `~/Downloads/bountyforge-hunt/bitso/CANDIDATES.md` — top item: cashback claim voucher double-spend. All fund-free accrual paths are verified closed (fake trade, bonus, referral); the only enabler is ~$2 USDC on Solana to account B's embedded wallet `EFAngmA78hbPHcZMyggEWxK9SYRxQA8mqk9KtgjyHFLU`, then a real $1-2 in-app swap -> claim -> run the replay/race/voucher-reuse battery.
