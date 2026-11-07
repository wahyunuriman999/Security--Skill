"""APEX local-only command line interface."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from apex.core.scope import EngagementManifest, ScopePolicyError, authorize_url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="apex", description="APEX local policy validator")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-manifest", help="validate a local engagement JSON file")
    validate.add_argument("manifest")
    check = sub.add_parser("authorize-url", help="check one URL locally; no network request is sent")
    check.add_argument("manifest")
    check.add_argument("url")
    args = parser.parse_args(argv)

    try:
        manifest = EngagementManifest.load(args.manifest)
        if args.command == "validate-manifest":
            result = {"valid": True, "engagement_id": manifest.engagement_id,
                      "assets": len(manifest.assets), "expires_at": manifest.expires_at.isoformat()}
        else:
            decision = authorize_url(manifest, args.url, now=datetime.now(timezone.utc))
            result = {"allowed": decision.allowed, "reason": decision.reason,
                      "engagement_id": decision.engagement_id}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("valid", result.get("allowed", False)) else 2
    except ScopePolicyError as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
