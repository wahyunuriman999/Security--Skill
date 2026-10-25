#!/usr/bin/env python3
"""
cekbocor.py - local credential exposure audit. No secret leaves the machine.

DATA POLICY
  PASSWORD : SHA-1 computed LOCALLY. Only the first 5 hash chars go to
             api.pwnedpasswords.com (k-anonymity). Plaintext is never transmitted.
  EMAIL    : sent to HIBP API v3. Requires HIBP_API_KEY (hibp-api-key header).
             Without a key it prints the manual web-UI path, not a silent skip.
  CARD PAN : NOT SUPPORTED, and no such lookup exists. Any 12-25 digit string with a
             valid Luhn check is hard-rejected by the guard below.

USAGE
  python cekbocor.py --selftest
  python cekbocor.py --password "hunter2"        # prefer --pw-file (shell history)
  python cekbocor.py --pw-file password.txt      # one per line, '#' comments ok
  python cekbocor.py --email me@example.com
  python cekbocor.py --email-file email.txt --pw-file password.txt

EXIT CODES  0 = all clean | 1 = usage error or rejected input | 2 = something found
"""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = {"User-Agent": "cekbocor/1.0"}
PWNED_RANGE = "https://api.pwnedpasswords.com/range/{}"
HIBP_ACCOUNT = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"


# ---------- guard: anti-PAN, enforced in code ----------
def looks_like_pan(s: str) -> bool:
    """True if this is plausibly a card number (12-25 digits, valid Luhn)."""
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


def reject_pan(value: str, label: str) -> None:
    if looks_like_pan(value):
        sys.exit(
            f"[DITOLAK] '{label}' terdeteksi sebagai nomor kartu (Luhn valid).\n"
            "          Tidak ada layanan lookup PAN->identitas pemilik. Situs yang\n"
            "          menjanjikan itu adalah penipuan / front carding. Hapus input ini."
        )


# ---------- password: k-anonymity ----------
def check_password(pw: str) -> int:
    """Occurrences in the breach corpus. 0 = not found. Plaintext never transmitted."""
    h = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = h[:5], h[5:]
    req = urllib.request.Request(PWNED_RANGE.format(prefix), headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read().decode("utf-8", "replace")
    for line in body.splitlines():
        part, _, count = line.partition(":")
        if part.strip() == suffix:
            return int(count.strip() or 0)
    return 0


# ---------- email: HIBP ----------
def check_email(email: str, api_key: str | None = None):
    """List of breach names, [] if clean, None if it cannot be checked (needs key)."""
    key = api_key or os.environ.get("HIBP_API_KEY")
    if not key:
        return None
    req = urllib.request.Request(
        HIBP_ACCOUNT.format(urllib.parse.quote(email)),
        headers={**UA, "hibp-api-key": key},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return [b["Name"] for b in json.loads(r.read().decode())]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        if e.code == 401:
            return None
        raise


def verdict(count: int) -> str:
    if count == 0:
        return "BERSIH"
    if count < 10:
        return "BOCOR - ganti sekarang"
    if count < 100_000:
        return "BOCOR PARAH - ganti + aktifkan 2FA"
    return "KRITIS - ada di wordlist semua attacker"


def read_lines(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit kebocoran kredensial, lokal.")
    ap.add_argument("--password", action="append", default=[])
    ap.add_argument("--pw-file")
    ap.add_argument("--email", action="append", default=[])
    ap.add_argument("--email-file")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        assert looks_like_pan("4111 1111 1111 1111") is True   # test PAN
        assert looks_like_pan("1234 5678 9012 3456") is False  # fails Luhn
        assert looks_like_pan("hunter2") is False
        assert hashlib.sha1(b"password").hexdigest().upper().startswith("5BAA6")
        print("selftest OK")
        return 0

    pws = list(a.password)
    if a.pw_file:
        pws += read_lines(a.pw_file)
    emails = list(a.email)
    if a.email_file:
        emails += read_lines(a.email_file)

    if not pws and not emails:
        ap.print_help()
        return 1

    exit_code = 0
    if pws:
        print(f"== PASSWORD ({len(pws)}) ==")
        print(f"{'#':>3}  {'HIT':>12}  VERDICT")
        for i, pw in enumerate(pws, 1):
            reject_pan(pw, f"password #{i}")
            n = check_password(pw)
            print(f"{i:>3}  {n:>12,}  {verdict(n)}")
            if n:
                exit_code = 2
        print("(plaintext tidak keluar dari mesin ini; yang dikirim cuma 5 char hash)")

    if emails:
        print(f"\n== EMAIL ({len(emails)}) ==")
        key_ok = bool(os.environ.get("HIBP_API_KEY"))
        for e in emails:
            if "@" not in e:
                print(f"  {e}: SKIP (bukan email)")
                continue
            res = check_email(e)
            if res is None:
                print(f"  {e}: TIDAK BISA DICEK - butuh HIBP_API_KEY")
                print("       -> manual: https://haveibeenpwned.com/ (gratis di web)")
                print("       -> key:    https://haveibeenpwned.com/API/Key ($3.95/bln)")
            elif not res:
                print(f"  {e}: BERSIH di katalog HIBP")
            else:
                print(f"  {e}: BOCOR di {len(res)} breach -> {', '.join(res[:8])}")
                exit_code = 2
        if not key_ok:
            print("(set HIBP_API_KEY untuk cek otomatis)")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
