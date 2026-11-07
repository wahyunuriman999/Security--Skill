import json
import os
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from apex.knowledge.registry import KnowledgeRegistry, KnowledgeRegistryError
from apex.cli import main as cli_main


class TestKnowledgeRegistry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        skill = self.root / "security" / "web" / "hunt-xss" / "SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_bytes(b"---\nname: hunt-xss\ndescription: XSS research\n---\n# XSS\n")
        (self.root / "routing.json").write_text(json.dumps({
            "total": 1,
            "generated_from": "test fixture",
            "skills": [{
                "name": "hunt-xss",
                "path": "security/web/hunt-xss/SKILL.md",
                "domain": "web-appsec",
                "description": "Cross-site scripting research and validation",
                "triggers": ["xss", "cross site scripting", "web"],
                "lines": 5,
            }],
        }), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_load_search_and_read_skill_as_untrusted_data(self):
        registry = KnowledgeRegistry(self.root)
        self.assertEqual(registry.count, 1)
        hits = registry.search("cross site scripting")
        self.assertEqual(hits[0].record.name, "hunt-xss")
        document = registry.read_skill("hunt-xss")
        self.assertIn("# XSS", document.content)
        self.assertEqual(document.trust, "untrusted_instruction_data")
        self.assertEqual(len(document.sha256), 64)

    def test_exact_name_search_ranks_first(self):
        registry = KnowledgeRegistry(self.root)
        self.assertGreaterEqual(registry.search("hunt-xss")[0].score, 1000)

    def test_manifest_total_mismatch_rejected(self):
        data = json.loads((self.root / "routing.json").read_text())
        data["total"] = 2
        (self.root / "routing.json").write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(KnowledgeRegistryError, "total_mismatch"):
            KnowledgeRegistry(self.root)

    def test_unindexed_skill_file_rejected(self):
        extra = self.root / "security" / "web" / "extra" / "SKILL.md"
        extra.parent.mkdir(parents=True)
        extra.write_text("# unindexed", encoding="utf-8")
        with self.assertRaisesRegex(KnowledgeRegistryError, "inventory_mismatch"):
            KnowledgeRegistry(self.root)

    def test_path_traversal_rejected(self):
        data = json.loads((self.root / "routing.json").read_text())
        data["skills"][0]["path"] = "../outside/SKILL.md"
        (self.root / "routing.json").write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(KnowledgeRegistryError, "traversal"):
            KnowledgeRegistry(self.root)

    def test_duplicate_skill_names_rejected(self):
        data = json.loads((self.root / "routing.json").read_text())
        data["total"] = 2
        data["skills"].append(dict(data["skills"][0]))
        (self.root / "routing.json").write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(KnowledgeRegistryError, "duplicate_skill_name"):
            KnowledgeRegistry(self.root)

    def test_symlink_skill_file_rejected(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        original = self.root / "security" / "web" / "hunt-xss" / "SKILL.md"
        target = self.root / "outside.md"
        target.write_text("# outside", encoding="utf-8")
        original.unlink()
        try:
            original.symlink_to(target)
        except OSError:
            self.skipTest("symlink creation not permitted")
        with self.assertRaisesRegex(KnowledgeRegistryError, "symlink_skill_path_rejected"):
            KnowledgeRegistry(self.root)

    def test_invalid_search_arguments_rejected(self):
        registry = KnowledgeRegistry(self.root)
        with self.assertRaisesRegex(KnowledgeRegistryError, "search_query_required"):
            registry.search(" ")
        with self.assertRaisesRegex(KnowledgeRegistryError, "search_limit"):
            registry.search("xss", limit=0)

    def test_cli_knowledge_search_returns_json_results(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = cli_main(["knowledge-search", "xss", "--root", str(self.root)])
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload[0]["name"], "hunt-xss")

    def test_cli_knowledge_show_marks_content_untrusted(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = cli_main(["knowledge-show", "hunt-xss", "--root", str(self.root)])
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["trust"], "untrusted_instruction_data")
        self.assertIn("# XSS", payload["content"])


if __name__ == "__main__":
    unittest.main()
