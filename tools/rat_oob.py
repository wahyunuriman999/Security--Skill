#!/usr/bin/env python3
"""
rat_oob.py — OOB callback toolkit for blind vulnerability testing.

Live infra:
  webhook.site token: YOUR-WEBHOOK-TOKEN-HERE
  URL: https://webhook.site/YOUR-WEBHOOK-TOKEN-HERE

Usage:
  python rat_oob.py gen                   # print a fresh tagged callback URL
  python rat_oob.py send <url>            # simulate a probe hitting our endpoint
  python rat_oob.py poll                  # list captured callbacks (last 10)
  python rat_oob.py wait <tag> [secs]     # block until a callback with tag arrives
"""
import httpx
import os
import secrets
import sys
import time
from datetime import datetime, timezone

TOKEN = os.environ.get("OOB_TOKEN", "YOUR-WEBHOOK-TOKEN-HERE")
BASE = f"https://webhook.site/{TOKEN}"
API = f"https://webhook.site/token/{TOKEN}/requests"


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
        total = j.get("total", 0)
        if not quiet:
            print(f"total callbacks: {total}")
        rows = []
        for item in j.get("data", [])[:limit]:
            row = {
                "method": item.get("method"),
                "ip": item.get("origin_ip"),
                "ua": (item.get("user_agent") or "")[:60],
                "query": item.get("query"),
                "at": item.get("created_at"),
            }
            rows.append(row)
            if not quiet:
                print(f"  [{row['method']}] ip={row['ip']} ua={row['ua']} "
                      f"query={row['query']} at={row['at']}")
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
            q = row["query"] if isinstance(row["query"], dict) else {}
            if tag in str(q) or tag in str(row["ua"]):
                print(f"  HIT [{row['method']}] ip={row['ip']} at={row['at']} query={q}")
                return row
        time.sleep(3)
    print("  no hit")
    return None


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "poll"
    if cmd == "gen":
        gen()
    elif cmd == "send":
        send(sys.argv[2])
    elif cmd == "poll":
        poll()
    elif cmd == "wait":
        wait(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 60)
    else:
        print(__doc__)
