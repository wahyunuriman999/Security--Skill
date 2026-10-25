# Security--Skill

Arsenal skill keamanan untuk AI-assisted bug bounty hunting, red-team, dan blue-team.

Dibangun dan diuji lewat engagement authorized (HackerOne: crypto.com, Shopify, eToro,
T-Mobile), kondisi middlebox ISP Indonesia, dan loop feedback submission report nyata.

## Isi

| Folder | Skill | Cakupan |
|---|---|---|
| `security/` | 130 | hunt-* per kelas vuln (XSS, SQLi, SSRF, IDOR, OAuth, JWT, GraphQL, …), enterprise platform (Okta, M365/Entra, vCenter, VPN), Web3 audit, mobile pipeline, metodologi bug bounty |
| `security-atlas/` | 870 | Atlas 870 skill mapped MITRE ATT&CK: cloud IAM, AD/ADCS, K8s, malware analysis, forensics, IR, threat intel, detection engineering, OT/ICS, zero trust, compliance |
| `security-atlas-roadmap/` | 1 | Router 64-cluster: sinyal tugas -> nama skill. Cakupan 870/870 skill |
| `tools/` | 10 file | HIV framework (mutator, WAF fingerprinter, beacon, CD4 flood, scoring) + rat_h3/rat_ghost/rat_oob/rat_digest |
| `tradecraft/` | 28 file | HIV evasion framework, OPSEC protocol, anti-forensics, payload database (XSS/SQLi/SSRF), engagement timeline |

**Mulai dari sini:** [`INDEX.md`](INDEX.md) — decision tree + peta skill lengkap.

## Cara pakai roadmap

Jangan baca 870 deskripsi skill untuk memilih. Muat `security-atlas-roadmap` —
satu tabel 64 baris memetakan sinyal tugas ke nama skill, lalu `skill_view` yang tepat.

```bash
ATLAS="security-atlas"
rg -il "<keyword>" "$ATLAS" --glob "SKILL.md"
```

## Aturan prioritas

1. **`security/hunt-*`** — prioritas untuk web/API bug bounty. Distilasi dari 681 pola
   report disclosed di 24 kelas vuln.
2. **`security-atlas/`** — pelengkap: cloud, AD, malware, forensics, IR, OT, detection.
3. **`security-atlas-roadmap/`** — router, dipakai saat tugas tidak jelas masuk mana.

## License

Konten skill mengikuti license upstream (Anthropic-Cybersecurity-Skills: MIT,
Claude-Red: MIT, Claude-BugHunter: MIT/CC BY 4.0, sippts: GPL untuk fungsi digest).
Custom tooling: MIT.

## Kredit

- **Claude-BugHunter** (elementalsouls) — bundle hunt-*, 681 pola report
- **Anthropic-Cybersecurity-Skills** (mukul975) — 818 skill mapped MITRE ATT&CK
- **Claude-Red** (SnailSploit) — 49 skill metodologi offensive
- **Pepelux/sippts** — parsing digest auth diadaptasi ke `rat_digest.py`
- **Hermes Agent** — runtime tempat arsenal ini hidup