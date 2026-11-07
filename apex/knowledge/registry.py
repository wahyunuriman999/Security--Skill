"""Read-only registry for the preserved Security--Skill knowledge corpus.

Skill files are treated as untrusted instruction data. This registry indexes and
returns content; it never imports, evaluates, or executes a skill or tool.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


_ALLOWED_ROOTS = frozenset({"security", "security-atlas", "security-atlas-roadmap"})
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
_TOKEN = re.compile(r"[a-z0-9]+")


class KnowledgeRegistryError(ValueError):
    pass


@dataclass(frozen=True)
class SkillRecord:
    name: str
    path: str
    domain: str
    description: str
    triggers: tuple[str, ...]
    lines: int


@dataclass(frozen=True)
class SkillDocument:
    record: SkillRecord
    content: str
    sha256: str
    trust: str = "untrusted_instruction_data"


@dataclass(frozen=True)
class SearchHit:
    record: SkillRecord
    score: int


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise KnowledgeRegistryError(f"duplicate_routing_key:{key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise KnowledgeRegistryError(f"invalid_routing_constant:{value}")


class KnowledgeRegistry:
    """Validated metadata index over the existing routing.json and SKILL.md corpus."""

    def __init__(self, root: str | Path, manifest_path: str | Path | None = None):
        self.root = Path(root).resolve(strict=True)
        self.manifest_path = (
            Path(manifest_path).resolve(strict=True)
            if manifest_path is not None else self.root / "routing.json"
        )
        if not self.manifest_path.is_file() or not self.manifest_path.is_relative_to(self.root):
            raise KnowledgeRegistryError("routing_manifest_must_be_inside_repository")
        self._records: dict[str, SkillRecord] = {}
        self._by_path: dict[str, SkillRecord] = {}
        self._load()

    @staticmethod
    def _safe_relative_path(value: Any) -> str:
        if not isinstance(value, str) or "\\" in value:
            raise KnowledgeRegistryError("skill_path_must_be_posix_relative_path")
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
            raise KnowledgeRegistryError("skill_path_traversal_rejected")
        if path.parts[0] not in _ALLOWED_ROOTS or path.name != "SKILL.md":
            raise KnowledgeRegistryError("skill_path_outside_knowledge_roots")
        return path.as_posix()

    def _resolve_skill_path(self, relative: str) -> Path:
        candidate = self.root.joinpath(*PurePosixPath(relative).parts)
        current = self.root
        for part in PurePosixPath(relative).parts:
            current = current / part
            if current.is_symlink():
                raise KnowledgeRegistryError(f"symlink_skill_path_rejected:{relative}")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise KnowledgeRegistryError(f"skill_file_unavailable:{relative}") from exc
        if not resolved.is_relative_to(self.root) or not resolved.is_file():
            raise KnowledgeRegistryError(f"skill_path_escapes_repository:{relative}")
        return resolved

    def _load(self) -> None:
        try:
            document = json.loads(
                self.manifest_path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise KnowledgeRegistryError(f"cannot_read_routing_manifest:{exc}") from exc
        if not isinstance(document, dict) or type(document.get("total")) is not int:
            raise KnowledgeRegistryError("routing_manifest_invalid_root_or_total")
        entries = document.get("skills")
        if not isinstance(entries, list) or document["total"] != len(entries):
            raise KnowledgeRegistryError("routing_manifest_total_mismatch")

        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise KnowledgeRegistryError(f"skill_entry_not_object:{index}")
            name = entry.get("name")
            domain = entry.get("domain")
            description = entry.get("description")
            triggers = entry.get("triggers")
            lines = entry.get("lines")
            if not isinstance(name, str) or not _NAME.fullmatch(name):
                raise KnowledgeRegistryError(f"invalid_skill_name:{index}")
            if not isinstance(domain, str) or not domain.strip():
                raise KnowledgeRegistryError(f"invalid_skill_domain:{name}")
            if not isinstance(description, str) or not description.strip():
                raise KnowledgeRegistryError(f"invalid_skill_description:{name}")
            if not isinstance(triggers, list) or any(
                not isinstance(item, str) or not item.strip() for item in triggers
            ):
                raise KnowledgeRegistryError(f"invalid_skill_triggers:{name}")
            if type(lines) is not int or lines < 1:
                raise KnowledgeRegistryError(f"invalid_skill_line_count:{name}")
            relative = self._safe_relative_path(entry.get("path"))
            if name in self._records:
                raise KnowledgeRegistryError(f"duplicate_skill_name:{name}")
            if relative in self._by_path:
                raise KnowledgeRegistryError(f"duplicate_skill_path:{relative}")
            self._resolve_skill_path(relative)
            record = SkillRecord(
                name=name, path=relative, domain=domain.strip(),
                description=description.strip(),
                triggers=tuple(dict.fromkeys(item.strip().lower() for item in triggers)),
                lines=lines,
            )
            self._records[name] = record
            self._by_path[relative] = record

        actual_paths = set()
        for root_name in _ALLOWED_ROOTS:
            directory = self.root / root_name
            if not directory.exists():
                continue
            for candidate in directory.rglob("SKILL.md"):
                relative = candidate.relative_to(self.root).as_posix()
                if candidate.is_symlink():
                    raise KnowledgeRegistryError(f"symlink_skill_path_rejected:{relative}")
                actual_paths.add(relative)
        indexed_paths = set(self._by_path)
        if actual_paths != indexed_paths:
            missing = sorted(actual_paths - indexed_paths)[:10]
            stale = sorted(indexed_paths - actual_paths)[:10]
            raise KnowledgeRegistryError(
                f"routing_inventory_mismatch:unindexed={missing}:missing_files={stale}"
            )

    @property
    def count(self) -> int:
        return len(self._records)

    def get(self, name: str) -> SkillRecord:
        try:
            return self._records[name]
        except KeyError as exc:
            raise KnowledgeRegistryError(f"skill_not_found:{name}") from exc

    def search(self, query: str, *, limit: int = 10) -> list[SearchHit]:
        if not isinstance(query, str) or not query.strip():
            raise KnowledgeRegistryError("search_query_required")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise KnowledgeRegistryError("search_limit_must_be_1_to_100")
        normalized = query.strip().lower()
        tokens = set(_TOKEN.findall(normalized))
        if not tokens:
            return []
        hits = []
        for record in self._records.values():
            name_text = record.name.replace("-", " ")
            name_tokens = set(_TOKEN.findall(name_text))
            domain_tokens = set(_TOKEN.findall(record.domain))
            trigger_tokens = {
                token for trigger in record.triggers
                for token in _TOKEN.findall(trigger.lower())
            }
            description_tokens = set(_TOKEN.findall(record.description.lower()))
            score = 0
            if normalized == record.name:
                score += 1000
            if normalized in record.name:
                score += 80
            if normalized in record.description.lower():
                score += 20
            for token in tokens:
                if token in name_tokens:
                    score += 12
                if token in trigger_tokens:
                    score += 8
                if token in domain_tokens:
                    score += 5
                if token in description_tokens:
                    score += 2
            if score:
                hits.append(SearchHit(record, score))
        hits.sort(key=lambda hit: (-hit.score, hit.record.name))
        return hits[:limit]

    def read_skill(self, name: str) -> SkillDocument:
        record = self.get(name)
        path = self._resolve_skill_path(record.path)
        try:
            raw = path.read_bytes()
            content = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise KnowledgeRegistryError(f"cannot_read_skill:{name}") from exc
        digest = hashlib.sha256(raw).hexdigest()
        return SkillDocument(record=record, content=content, sha256=digest)
