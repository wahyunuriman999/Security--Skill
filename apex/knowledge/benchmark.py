"""Deterministic retrieval benchmark for the APEX knowledge registry."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from apex.knowledge.registry import KnowledgeRegistry, KnowledgeRegistryError


@dataclass(frozen=True)
class BenchmarkCaseResult:
    query: str
    expected: tuple[str, ...]
    rank: int | None
    top_results: tuple[str, ...]


@dataclass(frozen=True)
class BenchmarkSummary:
    total: int
    hit_at_1: float
    hit_at_5: float
    mean_reciprocal_rank: float
    misses: tuple[str, ...]
    cases: tuple[BenchmarkCaseResult, ...]


def evaluate(
    registry: KnowledgeRegistry,
    cases: list[dict[str, Any]],
    *,
    top_k: int = 5,
) -> BenchmarkSummary:
    if not isinstance(registry, KnowledgeRegistry):
        raise KnowledgeRegistryError("benchmark_requires_knowledge_registry")
    if not isinstance(cases, list) or not cases:
        raise KnowledgeRegistryError("benchmark_cases_must_be_non_empty_array")
    if type(top_k) is not int or top_k != 5:
        raise KnowledgeRegistryError("benchmark_top_k_must_equal_5")

    results: list[BenchmarkCaseResult] = []
    hit_one = 0
    hit_five = 0
    reciprocal_ranks = []
    misses = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise KnowledgeRegistryError(f"benchmark_case_not_object:{index}")
        query = case.get("query")
        expected = case.get("expected")
        if not isinstance(query, str) or not query.strip():
            raise KnowledgeRegistryError(f"benchmark_query_invalid:{index}")
        if not isinstance(expected, list) or not expected or any(
            not isinstance(name, str) or not name.strip() for name in expected
        ):
            raise KnowledgeRegistryError(f"benchmark_expected_invalid:{index}")
        for name in expected:
            registry.get(name)
        hits = registry.search(query, limit=top_k)
        names = tuple(hit.record.name for hit in hits)
        rank = next((position for position, name in enumerate(names, start=1)
                     if name in expected), None)
        if rank == 1:
            hit_one += 1
        if rank is not None:
            hit_five += 1
            reciprocal_ranks.append(1.0 / rank)
        else:
            reciprocal_ranks.append(0.0)
            misses.append(query)
        results.append(BenchmarkCaseResult(query, tuple(expected), rank, names))

    total = len(results)
    return BenchmarkSummary(
        total=total,
        hit_at_1=hit_one / total,
        hit_at_5=hit_five / total,
        mean_reciprocal_rank=sum(reciprocal_ranks) / total,
        misses=tuple(misses),
        cases=tuple(results),
    )
