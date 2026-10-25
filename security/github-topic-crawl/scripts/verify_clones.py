#!/usr/bin/env python3
"""Verify every git clone in a directory resolves a HEAD, and report size.

Usage:
    python verify_clones.py <repos_dir>

Why this exists: on Windows a shallow clone can emit
`git restore --source=HEAD :/` after a *successful* checkout, which looks like
a failure in a clone loop's stderr. Trusting exit codes alone makes you retry
clones that are already fine. This script checks the thing that actually
matters -- does `git rev-parse HEAD` resolve -- and computes size with os.walk
because `du -sh` hangs on directories holding 100+ repos.
"""
import json
import os
import subprocess
import sys


def verify(repos_dir):
    repos = sorted(os.listdir(repos_dir))
    good, broken = [], []
    for name in repos:
        dest = os.path.join(repos_dir, name)
        if not os.path.isdir(dest):
            continue
        p = subprocess.run(
            ["git", "-C", dest, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=120,
        )
        if p.returncode == 0 and p.stdout.strip():
            good.append((name, p.stdout.strip()))
        else:
            broken.append(name)

    total = 0
    for name, _ in good:
        for root, _dirs, files in os.walk(os.path.join(repos_dir, name)):
            if ".git" in root:
                continue
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass

    return {
        "total_dirs": len(repos),
        "good": len(good),
        "broken": broken,
        "working_tree_gb": round(total / 1e9, 2),
    }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    result = verify(target)
    print(json.dumps(result, indent=2))
    if result["broken"]:
        print("\nBROKEN (re-clone these):")
        for b in result["broken"]:
            print("  ", b)
        sys.exit(1)
    print(f"\nAll {result['good']} clones resolve a HEAD. "
          f"Working tree: {result['working_tree_gb']} GB")
