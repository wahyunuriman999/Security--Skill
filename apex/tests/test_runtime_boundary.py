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
FORBIDDEN_MODULE_PREFIXES = {
    "urllib.request", "http.client", "importlib", "runpy", "ctypes",
    "multiprocessing", "webbrowser",
}
FORBIDDEN_LEGACY_ROOTS = {"security", "tools"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}


def _attribute_path(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def find_boundary_violations(tree: ast.AST, label: str = "<source>") -> list[str]:
    violations = []
    for node in ast.walk(tree):
        imported = []
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
        for module in imported:
            root = module.split(".")[0]
            forbidden_prefix = any(
                module == prefix or module.startswith(prefix + ".")
                for prefix in FORBIDDEN_MODULE_PREFIXES
            )
            if root in FORBIDDEN_ROOTS or root in FORBIDDEN_LEGACY_ROOTS or forbidden_prefix:
                violations.append(f"{label}:{node.lineno}: forbidden import {module}")
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
                violations.append(f"{label}:{node.lineno}: forbidden dynamic call {node.func.id}")
            path = _attribute_path(node.func)
            if path and (path in {"os.system", "os.popen"} or path.startswith("os.exec")):
                violations.append(f"{label}:{node.lineno}: forbidden process call {path}")
    return violations


class TestRuntimeBoundary(unittest.TestCase):
    def test_runtime_modules_do_not_import_network_or_legacy_packages(self):
        violations = []
        for source in ROOT.rglob("*.py"):
            if "tests" in source.parts:
                continue
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            violations.extend(find_boundary_violations(tree, str(source.relative_to(ROOT))))
        self.assertEqual(violations, [], "boundary violations found:\\n" + "\\n".join(violations))

    def test_network_transport_imports_are_blocked(self):
        for source in ("import urllib.request", "from http.client import HTTPConnection",
                       "import importlib"):
            with self.subTest(source=source):
                self.assertTrue(find_boundary_violations(ast.parse(source)))

    def test_dynamic_execution_and_os_process_launch_are_blocked(self):
        for source in ("eval('1 + 1')", "exec('pass')", "os.system('echo unsafe')",
                       "__import__('socket')"):
            with self.subTest(source=source):
                self.assertTrue(find_boundary_violations(ast.parse(source)))


if __name__ == "__main__":
    unittest.main()
