# Public Repository Analysis for Bug Bounty

## Purpose
Audit an organization's public repositories when they are explicitly in scope (e.g., Zendesk lists github.com/zendesk, Tymeshift, klausapp, ultimateai as in-scope targets).

## When to apply
Program policy explicitly includes public repos. Look for org-level scope statements naming GitHub orgs or specific repos.

## Workflow

### 1. Enumerate org repos
- GitHub org page: github.com/<org>
- GitHub API: api.github.com/orgs/<org>/repos (may be rate-limited without auth)
- Clone promising repos: AI/ML, SDK, CLI, theme, connector, workflow, mobile SDK

### 2. Clone high-value repos first
Priority order:
1. AI/ML/LLM feature repos (agent builders, copilots, RAG pipelines)
2. SDKs (mobile, web widget, messaging)
3. CLI and deployment tools (auth tokens, config)
4. Themes and frontend bundles (XSS sinks)
5. Connectors and integrations (webhook SSRF, external data sources)

### 3. Grep for high-value patterns
Secrets: api_key, apikey, secret, password, token, AWS keys (AKIA, sk_live), Google service accounts, private keys
SSRF: webhook, url, fetch, axios, request, http, https, endpoint, redirect
XSS: innerHTML, dangerouslySetInnerHTML, eval, document.write
Auth: logout, login, token, profile, csrf, authenticity_token

### 4. Validate before trusting
- AIza keys are often Maps/analytics, not Auth-enabled (CONFIGURATION_NOT_FOUND on identitytoolkit)
- secrets.yml development values may not match production (ENV-based)
- .env.example files show required vars but not values
- Check if exposed credentials are actually valid before claiming impact

### 5. Map to bounty impact
A leaked secret is only a finding if it's valid AND grants access to something in scope. An example .env file with empty values is NOT a finding.

## Zendesk media-streams example (validated)
- secrets.yml: development secret_key_base exposed (dev-only, not production)
- google_application_credentials.json: empty template (not valid creds)
- server.js: x-original-host header used to construct WebSocket URL → host header injection vector
- END_OF_INTERACTION_URL env var → open redirect vector on Twilio callback