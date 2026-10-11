#!/usr/bin/env python3
"""
rat_oob.py — OOB callback toolkit for blind vulnerability testing.

Endpoints: webhook.site (zero-auth, programmatic). Register a fresh token per
engagement, then paste the UUID into TOKEN below — or leave the default and
share it across concurrent tests (tags disambiguate).

Usage:
  python rat_oob.py register          # create a fresh webhook.site token, print URL
  python rat_oob.py gen               # print a fresh tagged callback URL
  python rat_oob.py send <url>        # self-probe: simulate a callback hit
  python rat_oob.py poll              # list captured callbacks (last 10)
  python rat_oob.py wait <tag> [secs] # block until a callback with tag arrives
"""
import httpx
import secrets
import sys
import time

TOKEN = os.environ.get("OOB_TOKEN", "YOUR-WEBHOOK-TOKEN-HERE")  # replace after `register`
BASE = f"https://webhook.site/{TOKEN}"
API = f"https://webhook.site/token/{TOKEN}/requests"


def register():
    with httpx.Client(timeout=20.0) as c:
        r = c.post("https://webhook.site/token", json={"default_status": 200})
        j = r.json()
        print(f"TOKEN = \"{j['uuid']}\"")
        print(f"URL   = https://webhook.site/{j['uuid']}")
        print("Paste the UUID into TOKEN above.")


def gen():
    tag = secrets.token_hex(4)
    print(f"{BASE}?t={tag}")
    return tag


def send(url):
    with httpx.Client(timeout=20.0) as c:
        r = c.get(url, headers={"User-Agent": "rat-oob-selftest"})
        print(f"sent -> {r.status_code}")


def poll(limit=10, quiet=False):
    with httpx.Client(timeout=20.0) as c:
        r = c.get(f"{API}?sorting=newest&page=1&per_page={limit}")
        j = r.json()
        if not quiet:
            print(f"total callbacks: {j.get('total', 0)}")
        rows = []
        for item in j.get("data", [])[:limit]:
            row = {
                "method": item.get("method"),
                "ip": item.get("origin_ip"),
                "ua": (item.get("user_agent") or "")[:60],
                "query": item.get("query"),
                "body": str(item.get("content"))[:200],
                "at": item.get("created_at"),
            }
            rows.append(row)
            if not quiet:
                print(f"  [{row['method']}] ip={row['ip']} query={row['query']} "
                      f"body={row['body'][:80]} at={row['at']}")
        return rows


def wait(tag, timeout=60):
    """Block until a callback containing `tag` hits the endpoint."""
    deadline = time.time() + timeout
    seen = set()
    print(f"waiting for tag '{tag}' (max {timeout}s)...", flush=True)
    while time.time() < deadline:
        for row in poll(quiet=True, limit=25):
            sig = f"{row['at']}|{row['ip']}|{row['method']}"
            if sig in seen:
                continue
            seen.add(sig)
            if tag in str(row["query"]) or tag in str(row["ua"]) or tag in row["body"]:
                print(f"  HIT [{row['method']}] ip={row['ip']} at={row['at']} query={row['query']}")
                return row
        time.sleep(3)
    print("  no hit")
    return None


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "poll"
    if cmd == "register":
        register()
    elif cmd == "gen":
        gen()
    elif cmd == "send":
        send(sys.argv[2])
    elif cmd == "poll":
        poll()
    elif cmd == "wait":
        wait(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 60)
    else:
        print(__doc__)
