import json
from pathlib import Path
import tempfile
import unittest
from security_agent.core.source_tools import SourceAccess, numbered


class SourceToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.journal = Path(self.temp.name) / "tools.jsonl"
        self.sources = {"a.cpp": "int *get();\n", "b.cpp": "int *get() { return nullptr; }\n"}

    def test_search_then_read_uses_only_frozen_files(self):
        access = SourceAccess(self.sources, "a.cpp", 3, 10000, self.journal)
        result = access.search("get")
        self.assertEqual(result["total_matches"], 2)
        self.assertFalse(result["truncated"])
        self.assertEqual(access.read("b.cpp")["source"], numbered(self.sources["b.cpp"]))
        self.assertIn("error", access.read("/etc/passwd"))
        self.assertEqual(len(self.journal.read_text().splitlines()), 3)

    def test_tool_budget_is_enforced(self):
        access = SourceAccess(self.sources, "a.cpp", 1, 10000, self.journal)
        access.search("get")
        self.assertIn("error", access.read("b.cpp"))
        self.assertTrue(access.exhausted)

    def test_byte_budget_returns_no_partial_source(self):
        access = SourceAccess(self.sources, "a.cpp", 5, 15, self.journal)
        result = access.read("b.cpp")
        self.assertIn("error", result)
        self.assertNotIn("source", result)
        self.assertTrue(access.exhausted)
        record = json.loads(self.journal.read_text())
        self.assertEqual(record["response"], result)

    def test_search_truncation_is_explicit(self):
        sources = {"a.cpp": "needle\n" * 150}
        access = SourceAccess(sources, "a.cpp", 2, 50000, self.journal)
        result = access.search("needle")
        self.assertEqual(len(result["hits"]), 100)
        self.assertEqual(result["total_matches"], 150)
        self.assertTrue(result["truncated"])

    def test_target_is_not_resent_and_ranges_keep_original_line_numbers(self):
        sources = {"a.cpp": "one\ntwo\nthree\n", "b.cpp": "a\nb\nc\n"}
        access = SourceAccess(sources, "a.cpp", 5, 10000, self.journal)
        self.assertTrue(access.read("a.cpp")["already_provided"])
        self.assertEqual(access.read("b.cpp", 2, 3)["source"], "2: b\n3: c")
        self.assertIn("error", access.read("b.cpp", 3, 1))
