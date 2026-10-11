#!/usr/bin/env python3
"""
subs-brute.py — stdlib subdomain brute-forcer.

Fallback when crt.sh is unreachable, the ProjectDiscovery/Chaos API needs a key,
and dnsx/subfaster are absent from the rig. Resolves first (cheap, kills ~90% of
the wordlist via DNS), then probes HTTP only on what resolves.

Usage:
    python3 subs-brute.py example.com words.txt
    cat words.txt | python3 subs-brute.py example.com -

Prints one TAB-separated line per live host: host, ip, http_status, bytes
"""
import sys
import socket
import urllib.request
import urllib.error
import concurrent.futures as cf

TIMEOUT = 10
THREADS = 40
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"}


def probe(sub, domain):
    host = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return None
    for scheme in ("https", "http"):
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(f"{scheme}://{host}/", headers=UA),
                timeout=TIMEOUT,
            )
            return host, ip, r.status, len(r.read())
        except urllib.error.HTTPError as e:
            return host, ip, e.code, len(e.read() or b"")
        except Exception:
            continue
    return host, ip, "no-http", 0


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    domain = sys.argv[1]
    src = sys.argv[2] if len(sys.argv) > 2 else "-"
    stream = sys.stdin if src == "-" else open(src, encoding="utf-8")
    words = [w.strip() for w in stream if w.strip()]
    live = []
    with cf.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for res in ex.map(lambda s: probe(s, domain), words):
            if res:
                live.append(res)
                print(*res, sep="\t")
    print(f"# live: {len(live)} / probed: {len(words)}", file=sys.stderr)


if __name__ == "__main__":
    main()
