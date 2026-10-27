# Security--Skill

A security skill arsenal for AI-assisted bug bounty hunting, red-team, and blue-team work.

Built and tested through authorized engagements (HackerOne: crypto.com, Shopify, eToro,
T-Mobile), Indonesian ISP middlebox conditions, and real submission-report feedback loops.

## Contents

| Folder | Skills | Coverage |
|---|---|---|
| `security/` | 130 | hunt-* per vulnerability class (XSS, SQLi, SSRF, IDOR, OAuth, JWT, GraphQL, …), enterprise platforms (Okta, M365/Entra, vCenter, VPN), Web3 audit, mobile pipelines, bug bounty methodology |
| `security-atlas/` | 870 | Atlas of 870 skills mapped to MITRE ATT&CK: cloud IAM, AD/ADCS, K8s, malware analysis, forensics, IR, threat intel, detection engineering, OT/ICS, zero trust, compliance |
| `security-atlas-roadmap/` | 1 | 64-cluster router: task signal -> skill name. Coverage 870/870 skills |
| `tools/` | 10 files | HIV framework (mutator, WAF fingerprinter, beacon, CD4 flood, scoring) + rat_h3/rat_ghost/rat_oob/rat_digest |
| `tradecraft/` | 28 files | HIV evasion framework, OPSEC protocol, anti-forensics, payload databases (XSS/SQLi/SSRF), engagement timeline |

**Start here:** [`ROUTER.md`](ROUTER.md) — pick the right skill in 10 seconds,
without reading all 1001 files. Full map: [`INDEX.md`](INDEX.md).

## Instant routing — no long reads

Do not read 1001 skill files to choose one. Route first, open one skill second:

1. Read [`ROUTER.md`](ROUTER.md) and match your task signal to its decision tree.
2. Or grep the machine-readable index by keyword:
   ```bash
   rg -i "<keyword>" routing.json
   ```
   `routing.json` covers all 1001 skills with `name`, `path`, `domain`,
   `description`, and `triggers`.
3. Open only the routed skill's `SKILL.md` and execute it.

For the atlas alone, the legacy route still works: load
`security-atlas-roadmap` — one 64-row table mapping task signals to skill
names — then open the exact skill it names.

```bash
ATLAS="security-atlas"
rg -il "<keyword>" "$ATLAS" --glob "SKILL.md"
```

## Priority rules

1. **`security/hunt-*`** — first priority for web/API bug bounty. Distilled from 681
   disclosed-report patterns across 24 vulnerability classes.
2. **`security-atlas/`** — complementary coverage: cloud, AD, malware, forensics, IR, OT, detection.
3. **`security-atlas-roadmap/`** — router, used when it is unclear which skill fits.

## Validation

```bash
python3 scripts/validate.py
```

Checks skill count against `routing.json`, frontmatter (`name`, `description`,
`version`, `license`), duplicate names, name/directory mismatches, and broken
internal `.md` links. The only allowed exception is `invariants.md` inside
`security/x-ray`, which that skill itself generates as its report file.

## License

Skill content follows its upstream license (Anthropic-Cybersecurity-Skills: MIT,
Claude-Red: MIT, Claude-BugHunter: MIT/CC BY 4.0, sippts: GPL for the digest function).
Custom tooling: MIT.

## Credits

- **Claude-BugHunter** (elementalsouls) — hunt-* bundle, 681 report patterns
- **Anthropic-Cybersecurity-Skills** (mukul975) — 818 skills mapped to MITRE ATT&CK
- **Claude-Red** (SnailSploit) — 49 offensive methodology skills
- **Pepelux/sippts** — digest-auth parsing adapted into `rat_digest.py`
- **Hermes Agent** — the runtime this arsenal lives in
