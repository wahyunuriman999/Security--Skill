#!/usr/bin/env python3
"""Validate Security--Skill without changing it.

Checks (exit 1 on any failure):
  - exactly the SKILL.md files listed in routing.json, and vice versa
  - every SKILL.md has frontmatter name + description + version + license
  - no duplicate skill names, no name/directory mismatch
  - no broken internal .md links, except output-file references a skill
    itself generates (currently: invariants.md inside security/x-ray,
    which the skill writes as its own report file, not a repo file)

Usage: python3 scripts/validate.py   (run from repo root)
"""
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOWED_MISSING = {("security/x-ray/SKILL.md", "invariants.md")}

def main() -> int:
    skills = sorted(p for p in ROOT.rglob("SKILL.md")
                    if p.relative_to(ROOT).parts[0] in
                    ("security", "security-atlas", "security-atlas-roadmap"))
    errors = []
    names = {}
    for p in skills:
        rel = str(p.relative_to(ROOT))
        text = p.read_text(errors="ignore")
        m = re.match(r"---\n(.*?)\n---\n", text, re.S)
        if not m:
            errors.append(f"{rel}: missing frontmatter"); continue
        fields = {}
        for line in m.group(1).splitlines():
            if line and not line[0].isspace() and ":" in line:
                k, v = line.split(":", 1); fields[k.strip()] = v.strip()
        for f in ("name", "description", "version", "license"):
            if not fields.get(f):
                errors.append(f"{rel}: missing {f}")
        name = fields.get("name")
        if name:
            if name in names:
                errors.append(f"{rel}: duplicate name {name} (also {names[name]})")
            names[name] = rel
            if p.parent.name != name and p.parent.name != "security-atlas-roadmap":
                errors.append(f"{rel}: name {name} != directory {p.parent.name}")
        for link in re.findall(r"\]\(([^)]+\.md[^)]*)\)", text):
            target = link.split("#")[0]
            if target.startswith("http"):
                continue
            if (rel, target) in ALLOWED_MISSING:
                continue
            if not (p.parent / target).exists() and not (ROOT / target.lstrip("/")).exists():
                errors.append(f"{rel}: broken link {link}")
    manifest = json.loads((ROOT / "routing.json").read_text())
    manifest_names = {s["name"] for s in manifest["skills"]}
    if manifest_names != set(names):
        errors.append(f"routing.json mismatch: manifest={len(manifest_names)} "
                      f"actual={len(names)} "
                      f"missing={sorted(set(names) - manifest_names)[:10]} "
                      f"extra={sorted(manifest_names - set(names))[:10]}")
    if manifest.get("total") != len(skills):
        errors.append(f"routing.json total {manifest.get('total')} != {len(skills)}")
    print(f"skills: {len(skills)}  errors: {len(errors)}")
    for e in errors[:50]:
        print(" -", e)
    return 1 if errors else 0

if __name__ == "__main__":
    raise SystemExit(main())
