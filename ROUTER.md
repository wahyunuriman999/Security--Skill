# ROUTER — Pick the right skill in 10 seconds

Read this file only. Do NOT read all 1001 `SKILL.md` files to choose.
Open exactly one skill after routing, then follow that skill.

## The 10-second rule

1. Match your task signal to ONE row in the decision tree below.
2. If the row names several skills, pick the most specific one.
3. Open only that skill's `SKILL.md` and execute it.
4. If no row fits, use `security/pentest-ref-corpus` (catalog of 108 repos
   + 2 curated catalogs) or grep `routing.json` by keyword — never browse
   the whole tree.

Machine-readable index for the same routing: [`routing.json`](routing.json)
— 1001 entries: `name`, `path`, `domain`, `description`, `triggers`, `lines`.
Grep it by keyword instead of reading files: `rg -i "<keyword>" routing.json`.

## Decision tree

```
Task
 +-- Web/API bug bounty? -----------------> security/hunt-<vuln>
 |    XSS, SQLi, SSRF, IDOR, OAuth, JWT, GraphQL, CORS, CSRF, SSTI, XXE,
 |    file upload, race condition, business logic, ATO, MFA, session, ...
 |    Priority: hunt-* first. They are distilled from disclosed reports
 |    and carry validation gates (canary, encoding check, OOB proof).
 |
 +-- Full bounty workflow / triage / report? -> security/bug-bounty,
 |    then security/triage-validation, security/report-writing,
 |    security/bugcrowd-reporting or security/h1-report-submission.
 |
 +-- Enterprise platform? ----------------> security/okta-attack,
 |    security/m365-entra-attack, security/cloud-iam-deep,
 |    security/enterprise-vpn-attack, security/vmware-vcenter-attack
 |
 +-- Mobile app? -------------------------> security/apk-redteam-pipeline
 |    (Android) or security/ios-redteam-pipeline (iOS)
 |
 +-- Smart contract / Web3? --------------> security/web3-* chain.
 |    Start at security/web3-start-here, follow its NEXT links in order:
 |    foundation -> bug-classes -> grep-arsenal -> poc-and-foundry ->
 |    triage-report -> methodology-research -> ai-tools ->
 |    web3-solidity-audit-mcp. For audit readiness, security/x-ray first.
 |
 +-- Cloud / AD / K8s / malware / --------> security-atlas/<domain>/
 |    forensics / IR / OT / detection       Use the atlas router below;
 |    do NOT read all 870 descriptions.
 |
 +-- Task signal unclear? ----------------> security-atlas-roadmap
      (64-cluster routing table, 870/870 atlas coverage)
```

## Atlas domains (870 skills)

| Domain | Skills | Signal |
|---|---|---|
| `atlas/cloud-iam` | 103 | AWS / Azure / GCP IAM, S3, CloudTrail, GuardDuty |
| `atlas/malware-forensics` | 64 | malware analysis, disk/memory/network forensics |
| `atlas/postex-c2` | 62 | persistence, lateral movement, C2 detection |
| `atlas/network` | 58 | traffic analysis, baselining, packet tools |
| `atlas/ad-kerberos` | 46 | AD, Kerberos, BloodHound, ACL abuse, DCSync |
| `atlas/web-appsec` | 46 | web appsec outside the hunt-* set |
| `atlas/api-graphql` | 48 | API / GraphQL assessment and detection |
| `atlas/k8s-container` | 45 | Kubernetes, containers |
| `atlas/source-secrets` | 26 | secrets, supply chain |
| `atlas/phishing-social` | 20 | phishing, social engineering |
| `atlas/recon-osint` | 20 | recon, OSINT tooling |
| `atlas/report-methodology` | 20 | reporting, methodology |
| `atlas/llm-ai-security` | 13 | LLM / AI security, RAG |
| `atlas/mobile` | 11 | mobile analysis (atlas side; pipelines live in `security/`) |
| `atlas/iot-firmware` | 8 | IoT, firmware |
| `atlas/wifi-rf` | 6 | Wi-Fi, RF |
| `atlas/cicd-devsecops` | 4 | CI/CD, DevSecOps |
| `atlas/thick-client` | 1 | thick-client pentest |
| `atlas/misc` | 269 | cross-cutting; grep `routing.json` by keyword, do not browse |

## Priority rules (do not override by browsing)

1. `security/hunt-*` beats atlas for any web/API vulnerability class.
2. A specific skill beats a general one (`hunt-jwt-crypto` beats
   `hunt-ato` for a JWT signature bug; `hunt-html-injection` is used until
   JavaScript execution is proven, then escalate to `hunt-xss`).
3. Validation beats collection: a finding is not a finding until its
   skill's proof gate passes (canary, OOB callback, second-account check).
4. One skill per task step. Chain skills in order (recon -> hunt ->
   validate -> report), do not load the whole chain at once.

## Coverage

- `security/`: 130 skills, indexed in [`INDEX.md`](INDEX.md).
- `security-atlas/`: 870 skills, indexed in
  [`security-atlas-roadmap/SKILL.md`](security-atlas-roadmap/SKILL.md).
- Total: **1001 skills**. This router, `INDEX.md`, the atlas roadmap, and
  `routing.json` together cover 1001/1001 — no orphan skill.
- `tools/` and `tradecraft/` are tooling/documentation, not skills, and
  are deliberately NOT routed through this file.
