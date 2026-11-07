"""APEX local-only command line interface."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
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
    knowledge_benchmark = sub.add_parser("knowledge-benchmark", help="measure read-only registry retrieval quality")
    knowledge_benchmark.add_argument("--root", default=".")
    knowledge_benchmark.add_argument("--cases")
    knowledge_benchmark.add_argument("--min-hit-at-5", type=float)
    knowledge_benchmark.add_argument("--min-mrr", type=float)
    args = parser.parse_args(argv)

    try:
        if args.command in {"knowledge-search", "knowledge-show", "knowledge-benchmark"}:
            from apex.knowledge.registry import KnowledgeRegistry
            registry = KnowledgeRegistry(args.root)
            if args.command == "knowledge-search":
                hits = registry.search(args.query, limit=args.limit)
                result = [{
                    "name": hit.record.name, "path": hit.record.path,
                    "domain": hit.record.domain, "score": hit.score,
                    "description": hit.record.description,
                } for hit in hits]
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0
            elif args.command == "knowledge-show":
                document = registry.read_skill(args.name)
                result = {
                    "name": document.record.name, "path": document.record.path,
                    "sha256": document.sha256, "trust": document.trust,
                    "content": document.content,
                }
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0
            else:
                from apex.knowledge.benchmark import evaluate
                cases_path = Path(args.cases) if args.cases else (
                    Path(__file__).resolve().parent / "knowledge" / "benchmark_cases.json"
                )
                benchmark_document = json.loads(cases_path.read_text(encoding="utf-8"))
                if not isinstance(benchmark_document, dict) or benchmark_document.get("schema_version") != 1:
                    raise ValueError("invalid_knowledge_benchmark_document")
                summary = evaluate(
                    registry, benchmark_document.get("cases"),
                    top_k=benchmark_document.get("top_k", 5),
                )
                minimum_hit = (
                    benchmark_document.get("minimum_hit_at_5", 0.90)
                    if args.min_hit_at_5 is None else args.min_hit_at_5
                )
                minimum_mrr = (
                    benchmark_document.get("minimum_mrr", 0.75)
                    if args.min_mrr is None else args.min_mrr
                )
                passed = summary.hit_at_5 >= minimum_hit and summary.mean_reciprocal_rank >= minimum_mrr
                result = {
                    **asdict(summary),
                    "minimum_hit_at_5": minimum_hit,
                    "minimum_mrr": minimum_mrr,
                    "passed": passed,
                }
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0 if passed else 1
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
