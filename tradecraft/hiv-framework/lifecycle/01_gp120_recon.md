# Stage 1: gp120 — Reconnaissance

> gp120 mengenali reseptor CD4 sebelum HIV commit ke infeksi.
> Recon mengenali attack surface sebelum menyentuh endpoint.

## CD4 Receptor Mapping (Target Identification)

| "Receptor" | Attack Surface |
|---|---|
| Auth mechanism | bypass, token forgery |
| Session management | fixation, prediction |
| Input validation | injection surfaces |
| Rate limiting | push limits |
| WAF fingerprint | evasion planning |
| API structure | query manipulation |
| JS framework+ver | known CVEs |
| Cloud provider | SSRF targets |

## Recon Tiers

### Passive (Zero Touch)
```bash
# Dorking
site:target.com filetype:js
site:target.com "api_key" OR "access_token"

# Infra
subfinder -d target.com
amass enum -passive -d target.com
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value' | sort -u
shodan search org:target.com

# Code leaks
truffleHog https://github.com/target
```

### Semi-Passive (Minimal Footprint)
```bash
whatweb target.com
curl -si target.com | grep -iE "server|x-powered|via"
# Extract API endpoints from JS bundles
cat *.js | grep -oP '"/api/[^"]*"' | sort -u
```

### Active (Low Rate)
```bash
httpx -u https://target.com -title -tech-detect -status-code
# Manual: trace auth flow, map parameters, note token formats
```

## CCR5 Co-receptor (Secondary Vectors)

```
Primary:    Main webapp
Co-vectors: Mobile API (often less hardened)
            Admin subdomain
            Internal API via SSRF
            Third-party OAuth provider
            Webhook receiver endpoints
            GraphQL schema
```

*Stage 1: gp120 Recon | HIV Framework | Security--Skill*
