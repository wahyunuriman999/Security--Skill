# Financial identifier boundary — what a PAN does and does not give you

## Anatomy

A card number is an ISO/IEC 7812 identifier: a 6–8 digit BIN/issuer range, the individual
account digits, then a Luhn check digit. Everything in it describes the **card product and
issuing institution**. Nothing in it describes the **person**.

| Derivable from the number | Not derivable from the number — ever |
|---|---|
| Card brand and product tier | Holder name |
| Issuing bank and country | Date of birth |
| Credit / debit / prepaid | Address, phone, email |
| Luhn validity | Any account or transaction data |

Holder attributes live in the issuer's account record because the holder supplied them at
onboarding. That record is reachable only through the issuer's authenticated channel (app
or call centre), never through a number lookup. Services advertising PAN → identity are
scams, and submitting a PAN to one is the harm.

## Luhn check (the guard)

```python
def looks_like_pan(s: str) -> bool:
    digits = re.sub(r"[\s\-]", "", s)
    if not re.fullmatch(r"\d{12,25}", digits):
        return False
    total, alt = 0, False
    for ch in reversed(digits):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0
```

Run it on every free-text input the tool accepts. A true result means reject the input and
explain why — the guard is what makes the boundary structural rather than discretionary.
Same applies to any other length-and-checksum-bearing identifier (IBAN, national ID).

## Regional fraud patterns — Indonesia (from public reporting)

Name the pattern, because "your data leaked" is rarely the live risk:

1. **Wallet/QRIS-linked card draining.** Unrecognized charges labeled with a digital
   wallet's merchant name, on cards whose owners never opened a wallet account.
2. **OTP routed to recycled phone numbers.** Cards issued or activated without consent;
   the OTP goes to a stale number the carrier reassigned years earlier. KYC data that is
   never refreshed becomes an attacker-controlled second factor.
3. **Alphanumeric sender-ID spoofing.** A phishing SMS lands in the *same* thread as
   genuine bank OTP messages, so thread identity cannot be used as a trust signal.

## Compromise triage checklist

1. Freeze the card in the issuer app.
2. Review statements for low-value test charges — small amounts precede the real drain.
3. Confirm the phone and email on file with every issuer are the ones in use now. A
   recycled number is the highest-impact gap, and refreshing it is the bank's obligation.
4. Enable real-time transaction alerts, not just monthly statements.
5. Use virtual / single-use cards for online merchants; avoid stored cards where possible.
6. Report through the number printed on the card or statement — never a link from an SMS.
7. Dispute with the issuer first, then the wallet/PSP; keep the report reference and
   document each transaction with date, time, amount, and destination.
