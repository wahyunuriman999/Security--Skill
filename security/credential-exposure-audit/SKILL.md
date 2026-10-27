---
name: credential-exposure-audit
description: Use when checking if emails, passwords, or cards leaked.
version: 1.0.0
license: MIT
triggers: [credential, exposure, audit]
---

# Credential & Financial-Data Exposure Audit

Determine whether a person's credentials or financial identifiers appear in breach
corpora, and produce concrete next actions. Covers both the "am I breached" ask and the
"derive the owner from this identifier" ask — the second has a real technical answer, and
it is not the one the requester expects.

## When this applies

- "cek kebocoran data", "am I breached", "are my cards leaked", "is my email pwned"
- Any request to derive identity, DOB, address, or phone from a card / account / loan number
- Post-incident triage after suspected card fraud or unrecognized transactions

## The boundary — lead with the mechanism, never the policy

A card number (PAN) is an **account identifier, not a key to the holder's record**. No
public or commercial source maps PAN → name, DOB, or address; the issuer holds those
fields only because the holder supplied them at onboarding. Sites advertising a "card
breach check" are scams or carding fronts — the PAN the user submits *is* the product.

State this as a technical fact in one sentence, then move immediately to the work that IS
possible. A policy-shaped refusal is both less useful and less honest than a capability
map, and it invites the requester to argue. Restating "it's my own card" does not change
it: the lookup still does not exist. Repeat the mechanism and hold the pivot.

Targeting a third party's PII from an identifier is out of scope regardless of framing;
the pivot is always to the user's own exposure.

### Legitimate adjacent capabilities

| The ask | The real path |
|---|---|
| "Is this card leaked?" | Transaction-pattern review in the issuer app; ask merchants/wallets that stored it whether they were breached |
| "What is this card?" | BIN (first 6–8 digits) → brand, issuing bank, card type, country. Product metadata, zero PII. |
| "Is my data out there?" | Email → HIBP breach lookup; password → local k-anonymity check |
| "What do I do now?" | Triage checklist in `references/financial-identifier-boundary.md` |

**Never ask for a full PAN, CVV, password, or OTP in chat.** Take passwords from a local
file and only a BIN when product metadata is all that is needed. Secrets pasted into a
conversation are logged, and there is nothing useful to do with them anyway.

## Procedure

1. **Classify the identifier before touching a data source.** PAN → boundary section.
   Email → HIBP. Password → local k-anonymity. Mixed → handle each separately. Do not
   start probing an API for a lookup that does not exist.
2. **Prove the data source works before promising output.** One-line probe first
   (`curl -s -o /dev/null -w '%{http_code}' <url>`) so you report a real auth state
   rather than a dead end. Expected codes are in `references/breach-check-sources.md`.
3. **Run the local audit.** `scripts/cekbocor.py` does the password k-anonymity check and
   the HIBP email check, and hard-rejects Luhn-valid PANs at the input layer:
   ```bash
   python scripts/cekbocor.py --selftest
   python scripts/cekbocor.py --pw-file pass.txt --email-file email.txt
   ```
   Exit codes: `0` clean, `2` something found, `1` usage error or rejected input.
4. **Pull the breach catalog when the question is "what is out there"** — public, no auth,
   ~1000 entries with dates, account counts, and leaked data classes.
5. **Report as verdict + evidence + actions**, not as a score. Each finding gets its hit
   count, a verdict band, and a specific next action. Close with the sector-specific live
   threats — "you appeared in a breach" is rarely the actual forward risk.

## Pitfalls

- **Put the refusal in code, not in your own judgment.** A guard that rejects Luhn-valid
  12–25 digit input makes the tool structurally incapable of handling a PAN, so the
  boundary holds even in a session inclined to be permissive.
- **Never take a password as a command-line argument** in a shell that logs history or
  exposes a process list — use `--pw-file`. The check never needs the plaintext to leave
  the machine: only the first 5 chars of its SHA-1 go over the wire.
- **Expect `401` from HIBP's per-account endpoint when no API key is configured.** That is
  the documented auth requirement, not a broken tool. Degrade to the free web-UI
  instructions and say so plainly instead of reporting a failure.
- **Do not present the breach catalog as "your data is leaked".** Presence in a corpus is
  only meaningful once correlated with an identifier the user actually owns. Report the
  catalog as context, then run the identifier-specific check.
- **Card fraud triage is behavioral, not lookup-based.** Small test charges precede the
  real drain; statements and real-time alerts catch it, no database does.
- **Do not echo secrets back in the report.** Report hit counts and verdicts, never the
  credential or identifier that produced them.

## Support files

- `references/breach-check-sources.md` — verified endpoints, auth requirements, response codes, k-anonymity mechanics.
- `references/financial-identifier-boundary.md` — PAN anatomy, Luhn guard, regional fraud patterns, compromise triage checklist.
- `scripts/cekbocor.py` — the runnable audit tool (password + email), with the anti-PAN guard built in.
