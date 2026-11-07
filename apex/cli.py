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
    knowledge_search = sub.add_parser("knowledge-search", help="search indexed skill metadata without executing it")
    knowledge_search.add_argument("query")
    knowledge_search.add_argument("--root", default=".")
    knowledge_search.add_argument("--limit", type=int, default=10)
    knowledge_show = sub.add_parser("knowledge-show", help="read one skill as untrusted instruction data")
    knowledge_show.add_argument("name")
    knowledge_show.add_argument("--root", default=".")
    args = parser.parse_args(argv)

    try:
        if args.command in {"knowledge-search", "knowledge-show"}:
            from apex.knowledge.registry import KnowledgeRegistry, KnowledgeRegistryError
            registry = KnowledgeRegistry(args.root)
            if args.command == "knowledge-search":
                hits = registry.search(args.query, limit=args.limit)
                result = [{
                    "name": hit.record.name, "path": hit.record.path,
                    "domain": hit.record.domain, "score": hit.score,
                    "description": hit.record.description,
                } for hit in hits]
            else:
                document = registry.read_skill(args.name)
                result = {
                    "name": document.record.name, "path": document.record.path,
                    "sha256": document.sha256, "trust": document.trust,
                    "content": document.content,
                }
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
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
    except (ScopePolicyError, ValueError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
