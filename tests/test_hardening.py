"""Hardening tests: error paths, edge cases, and input validation."""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from subhunt.core import (
    aggregate,
    in_scope,
    normalize_host,
    parse_source,
    scan,
    to_json,
    AggregateResult,
)
from subhunt.cli import main


class TestNormalizeHostEdgeCases(unittest.TestCase):
    """normalize_host should handle non-string inputs and weird values."""

    def test_none_returns_none(self):
        self.assertIsNone(normalize_host(None))

    def test_integer_coerced(self):
        # Integers like 12345 produce a single-label string; normalize returns
        # it but is_valid_hostname will later reject it — the key point is no crash.
        result = normalize_host(12345)
        self.assertIsInstance(result, (str, type(None)))

    def test_bytes_decoded(self):
        result = normalize_host(b"api.example.com")
        self.assertEqual(result, "api.example.com")

    def test_empty_bytes(self):
        self.assertIsNone(normalize_host(b""))

    def test_only_wildcards(self):
        # A string that reduces to nothing after wildcard stripping.
        self.assertIsNone(normalize_host("*."))

    def test_only_dots(self):
        self.assertIsNone(normalize_host("..."))


class TestInScopeEdgeCases(unittest.TestCase):
    """in_scope should tolerate unusual scope values."""

    def test_empty_scope_always_true(self):
        self.assertTrue(in_scope("anything.example.com", ""))

    def test_none_scope_always_true(self):
        # None is treated as empty scope — keep everything.
        self.assertTrue(in_scope("anything.example.com", None))  # type: ignore[arg-type]

    def test_scope_with_leading_dot(self):
        self.assertTrue(in_scope("api.example.com", ".example.com"))

    def test_scope_with_whitespace(self):
        self.assertTrue(in_scope("api.example.com", "  example.com  "))

    def test_none_host_not_in_scope(self):
        self.assertFalse(in_scope(None, "example.com"))  # type: ignore[arg-type]

    def test_prefix_not_matched(self):
        # "notexample.com" must not match scope "example.com".
        self.assertFalse(in_scope("notexample.com", "example.com"))


class TestParseSourceEdgeCases(unittest.TestCase):
    """parse_source must survive bad input."""

    def test_empty_string(self):
        self.assertEqual(parse_source(""), [])

    def test_none_input(self):
        self.assertEqual(parse_source(None), [])  # type: ignore[arg-type]

    def test_all_comments(self):
        self.assertEqual(parse_source("# comment\n# another"), [])

    def test_only_blank_lines(self):
        self.assertEqual(parse_source("\n\n\n"), [])


class TestAggregateEdgeCases(unittest.TestCase):
    """aggregate() should raise clearly on bad paths and handle empty input."""

    def test_missing_file_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            aggregate(["/tmp/nonexistent-subhunt-XXXXX.txt"])
        self.assertIn("no such file or directory", str(ctx.exception).lower())

    def test_empty_path_list_returns_empty_result(self):
        result = aggregate([])
        self.assertEqual(result.unique_count, 0)
        self.assertEqual(result.total_lines, 0)

    def test_none_paths_raises_type_error(self):
        with self.assertRaises(TypeError):
            aggregate(None)  # type: ignore[arg-type]

    def test_empty_directory_returns_empty_result(self):
        with tempfile.TemporaryDirectory() as d:
            result = aggregate([d])
        self.assertEqual(result.unique_count, 0)

    def test_scope_strips_leading_trailing_whitespace(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("api.example.com\nwww.example.com\nother.evil.com\n")
            fname = f.name
        try:
            result = aggregate([fname], scope="  example.com  ")
            hosts = {s.host for s in result.subdomains}
            self.assertIn("api.example.com", hosts)
            self.assertNotIn("other.evil.com", hosts)
        finally:
            os.unlink(fname)

    def test_all_invalid_lines_counts_correctly(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("not-a-hostname\nlocalhost\n203.0.113.1\n")
            fname = f.name
        try:
            result = aggregate([fname])
            self.assertEqual(result.unique_count, 0)
            self.assertEqual(result.invalid, 3)
        finally:
            os.unlink(fname)


class TestScanAndToJson(unittest.TestCase):
    """scan() and to_json() are the MCP-facing API."""

    def test_scan_missing_path_raises(self):
        with self.assertRaises(ValueError):
            scan("/tmp/totally-nonexistent-subhunt.txt")

    def test_scan_empty_target_raises(self):
        with self.assertRaises(ValueError):
            scan("")

    def test_scan_none_raises(self):
        with self.assertRaises(ValueError):
            scan(None)  # type: ignore[arg-type]

    def test_to_json_returns_valid_json(self):
        result = AggregateResult(scope="example.com")
        out = to_json(result)
        parsed = json.loads(out)
        self.assertEqual(parsed["scope"], "example.com")

    def test_to_json_rejects_non_result(self):
        with self.assertRaises(TypeError):
            to_json({"not": "a result"})  # type: ignore[arg-type]


class TestCliMissingFile(unittest.TestCase):
    """CLI must exit 2 with a message on missing source files."""

    def test_missing_file_exit_2(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = main(["merge", "/tmp/definitely-does-not-exist-subhunt.txt"])
        self.assertEqual(rc, 2)
        self.assertIn("error", err.getvalue().lower())

    def test_missing_file_message_contains_filename(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            main(["merge", "/tmp/definitely-does-not-exist-subhunt.txt"])
        self.assertIn("definitely-does-not-exist-subhunt", err.getvalue())

    def test_empty_dir_exit_zero(self):
        with tempfile.TemporaryDirectory() as d:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["merge", d])
        self.assertEqual(rc, 0)

    def test_json_output_empty_dir(self):
        with tempfile.TemporaryDirectory() as d:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["merge", d, "-f", "json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["stats"]["unique"], 0)


class TestMcpServerImport(unittest.TestCase):
    """mcp_server must import cleanly (scan + to_json are now defined)."""

    def test_import_does_not_crash(self):
        # If this import fails, mcp_server has broken references.
        import importlib
        mod = importlib.import_module("subhunt.mcp_server")
        self.assertTrue(callable(mod.serve))


if __name__ == "__main__":
    unittest.main()
