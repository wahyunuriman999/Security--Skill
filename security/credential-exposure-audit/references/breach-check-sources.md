# Breach check sources — verified endpoints and their auth

Probe before promising. The codes below are what a working environment returns.

## Pwned Passwords (k-anonymity) — free, no key

```
GET https://api.pwnedpasswords.com/range/{first5ofSHA1}
```

- Hash locally: `hashlib.sha1(pw.encode()).hexdigest().upper()`, send chars 0–4, match the
  returned suffix against chars 5+.
- Response: one `SUFFIX:COUNT` per line. A range returns ~1000–2000 lines regardless of
  input — that bulk is the point: the server cannot tell which suffix is being asked about.
- Verified: range `5BAA6` returned 1977 lines; the password `password` matches with count
  52,372,427.
- Plaintext never leaves the machine. This is the only password check that should ever run.

## Have I Been Pwned — breached account (needs key)

```
GET https://haveibeenpwned.com/api/v3/breachedaccount/{urlencoded-email}
Header: hibp-api-key: <key>
```

- `401` without a key (verified). `404` = address not in any breach. `200` = JSON array of
  breach objects.
- Key at `https://haveibeenpwned.com/API/Key`, ~$3.95/month. Set `HIBP_API_KEY` in the
  environment; the script reads it.
- No key → send the user to the free web UI at `https://haveibeenpwned.com/`. Do not
  silently skip the check.
- Send a `User-Agent` (required) and leave ~1.5 s between requests (rate limited).

## Breach catalog — free, no auth

```
GET https://haveibeenpwned.com/api/v3/breaches
```

- `200` public (verified). ~1038 entries. Fields worth reading: `Title`, `BreachDate`,
  `PwnCount`, `DataClasses`, `Description`.
- Use it to sort recent breaches by date, filter by keyword for the user's region or
  sector, and report which *data classes* leak alongside passwords. DOB, phone, employer,
  and address classes matter more than logins — they drive targeted social engineering.

## Other sources

- Issuer and merchant breach notifications plus statement alerts — the only authoritative
  source for "was my card exposed".
- Wallet / PSP public statements (for example a wallet announcing coordinated refunds for a
  card-draining campaign) — corroborates that a pattern is real and current.
- Public regulator statements — useful for telling the user which channel will actually
  process a refund, and on what timeline.
