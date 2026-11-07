"""Guard the APEX core's no-network/no-legacy-import boundary."""
from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_ROOTS = {
    "socket", "subprocess", "requests", "httpx", "urllib3", "aiohttp",
    "aioquic", "ftplib", "telnetlib", "paramiko",
}
FORBIDDEN_LEGACY_ROOTS = {"security", "tools"}


class TestRuntimeBoundary(unittest.TestCase):
    def test_runtime_modules_do_not_import_network_or_legacy_packages(self):
        violations = []
        for source in ROOT.rglob("*.py"):
            if "tests" in source.parts:
                continue
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            for node in ast.walk(tree):
                imported = []
                if isinstance(node, ast.Import):
                    imported.extend(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.append(node.module.split(".")[0])
                for root in imported:
                    if root in FORBIDDEN_ROOTS or root in FORBIDDEN_LEGACY_ROOTS:
                        violations.append(f"{source.relative_to(ROOT)}:{node.lineno}: {root}")
        self.assertEqual(violations, [], "forbidden imports found:\n" + "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
