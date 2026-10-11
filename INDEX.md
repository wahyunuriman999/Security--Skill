# Security--Skill — Master Index

110 skills. Start from the task, not the skill name.

## Decision tree

```
Mau ngapain?
├── Bug bounty end-to-end (program intel → recon → hunt → report)
│   └── bounty-hunt-pipeline            ← START HERE (hypothesis-driven, gates)
├── Recon / scope dulu
│   ├── web2-recon                      (subdomain, crawl, JS, dir enum)
│   ├── recon-scope-triage              (pastikan aset milik target sblm test)
│   ├── offensive-osint / osint-methodology
│   └── supply-chain-attack-recon
├── /hunt orchestrator (redteam / wapt mode)
│   └── hunt-dispatch                   ← router: fingerprint → skill set
├── Nemu sinyal spesifik → skill kelas vuln (lihat tabel)
├── Smart contract / DeFi
│   └── web3-start-here                 ← master index web3
│       → web3-hunt-foundation → web3-audit / smart-contract-audit
├── Butuh payload / bypass table / wordlist
│   └── security-arsenal  (+ web2-vuln-classes utk referensi 28 kelas)
├── Validasi temuan sebelum nulis report
│   └── triage-validation               (7-Question Gate — WAJIB lolos)
├── Nulis report
│   ├── H1         → h1-report-submission + report-writing
│   ├── Bugcrowd   → bugcrowd-reporting + report-writing
│   └── HackenProof→ hackenproof-triage-marketplace
└── Habis hunt → engagement-learning-loop (catat lesson ke LESSONS.md)
```

## Skill map by category

### Workflow & methodology
| Skill | Pakai kapan |
|---|---|
| bounty-hunt-pipeline | Bug bounty full-cycle (pilihan utama utk H1) |
| bug-bounty | Workflow lengkap alternatif |
| bb-methodology | "3rd eye": pahami dulu sblm asumsi, validasi sblm report |
| redteam-mindset | Disiplin operator red team |
| godmod | Expert mode utk riset/teknikal dalam |

### Recon & OSINT
| Skill | Pakai kapan |
|---|---|
| web2-recon | Pipeline recon web2 standar |
| recon-scope-triage | Triase hasil ASM: milik siapa sblm testing |
| offensive-osint / osint-methodology | OSINT operasional |
| supply-chain-attack-recon | Supply-chain attack surface |
| hunt-subdomain | Subdomain takeover |
| hunt-shadow-api | Shadow/zombie/undocumented API |
| hunt-spa-api | Bongkar hidden API dari JS bundle SPA |
| hunt-source-leak | Source map / .env / build artifact leak |

### Injection
hunt-sqli · hunt-nosqli · hunt-xss · hunt-html-injection · hunt-dom ·
hunt-ssti · hunt-xxe · hunt-ldap · hunt-rce · hunt-deserialization ·
hunt-file-upload · hunt-ssrf · hunt-http-smuggling

### Auth, session, ATO
hunt-ato · hunt-auth-bypass · hunt-oauth · hunt-saml · hunt-jwt-crypto ·
jwt-token-analyzer · slapi-jwt-tester · hunt-mfa-bypass · hunt-session ·
hunt-forgot-password · hunt-brute-force · hunt-captcha-bypass

### Access control & logic
hunt-idor · hunt-api-misconfig · hunt-business-logic · hunt-race-condition ·
hunt-csrf · hunt-clickjacking · hunt-open-redirect · hunt-host-header ·
hunt-cors · hunt-cache-poison · hunt-websocket · hunt-grpc · hunt-graphql ·
hunt-fintech-graphql · graphql-auto-fuzzer · hunt-llm-ai · hunt-rag-vector ·
hunt-exceptional-conditions · hunt-misc

### Platform & stack
hunt-aspnet · hunt-sharepoint · hunt-ntlm-info · hunt-laravel · hunt-nextjs ·
hunt-nodejs · hunt-springboot · hunt-k8s · hunt-cicd · hunt-tls-network ·
okta-attack · m365-entra-attack · enterprise-vpn-attack ·
vmware-vcenter-attack · cloud-iam-deep · hunt-cloud-misconfig

### Mobile
apk-redteam-pipeline · ios-redteam-pipeline

### Web3 / smart contract
Mulai dari **web3-start-here** (master index) → web3-hunt-foundation.
Audit: web3-audit · smart-contract-audit · solidity-auditor · code-sleuth ·
x-ray · web3-bug-classes · web3-case-study-role-misconfig ·
web3-methodology-research · web3-hunt-zksync-era
PoC & fuzz: web3-poc-foundry · fizz · fizz-convert · fizz-sync ·
web3-solidity-audit-mcp · web3-grep-arsenal · web3-ai-tools ·
web3-triage-report · meme-coin-audit

### Reporting & triage
report-writing · h1-report-submission · bugcrowd-reporting ·
hackenproof-triage-marketplace · triage-validation · evidence-hygiene ·
engagement-learning-loop

### Tools (testing aids)
auto-cors-scanner · api-key-triage · merchant-graphql-idor-tester

### Shared
`_shared/` — bukan skill: README, `tools/` (rat_h3, rat_ghost, rat_oob,
rat_digest + `tests/`), `tradecraft/`. Butuh venv:
`~/workspace/rat-tools-venv/bin/python`.

## Overlap notes (biar nggak load dobel)
- hunt-sqli vs hunt-nosqli: SQL relasional → sqli; Mongo/Couch/Redis → nosqli.
- hunt-xss vs hunt-dom vs hunt-html-injection: reflected/stored → xss;
  sink client-side/postMessage → dom; HTML tanpa JS → html-injection.
- hunt-graphql vs hunt-fintech-graphql vs graphql-auto-fuzzer: generik →
  graphql; money-movement/KYC → fintech-graphql; fuzzing otomatis → auto-fuzzer.
- report-writing vs h1-report-submission vs bugcrowd-reporting: template umum
  → report-writing; taktik spesifik platform → h1 / bugcrowd.
- web3-audit vs smart-contract-audit vs solidity-auditor: framework 10 kelas
  DeFi → web3-audit; multi-expert dalam → smart-contract-audit; audit sambil
  develop → solidity-auditor.
