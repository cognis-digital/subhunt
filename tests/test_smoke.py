"""Smoke tests for SUBHUNT. No network."""
import io
import json
import os
import sys
import unittest
import contextlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from subhunt import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    normalize_host,
    is_valid_hostname,
    in_scope,
    parse_source,
    aggregate,
)
from subhunt.cli import main  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic",
)


class TestNormalize(unittest.TestCase):
    def test_scheme_port_path(self):
        self.assertEqual(
            normalize_host("https://api.example.com:8443/v1?x=1"),
            "api.example.com",
        )

    def test_wildcard_and_dot(self):
        self.assertEqual(normalize_host("*.dev.example.com"), "dev.example.com")
        self.assertEqual(normalize_host("WWW.Example.com."), "www.example.com")

    def test_userinfo(self):
        self.assertEqual(normalize_host("user@host.example.com"), "host.example.com")

    def test_empty(self):
        self.assertIsNone(normalize_host(""))
        self.assertIsNone(normalize_host("   "))


class TestValidate(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(is_valid_hostname("a.example.com"))
        self.assertTrue(is_valid_hostname("x-y.sub.example.com"))

    def test_invalid(self):
        self.assertFalse(is_valid_hostname("localhost"))      # single label
        self.assertFalse(is_valid_hostname("not a host"))     # space
        self.assertFalse(is_valid_hostname("203.0.113.10"))   # bare ipv4
        self.assertFalse(is_valid_hostname("-bad.example.com"))
        self.assertFalse(is_valid_hostname(""))


class TestScope(unittest.TestCase):
    def test_in_scope(self):
        self.assertTrue(in_scope("a.example.com", "example.com"))
        self.assertTrue(in_scope("example.com", "example.com"))
        self.assertFalse(in_scope("a.evil-corp.com", "example.com"))
        self.assertFalse(in_scope("notexample.com", "example.com"))


class TestParse(unittest.TestCase):
    def test_csv_and_comments(self):
        toks = parse_source("# c\nhost.example.com,1.2.3.4\n\nfoo.example.com\n")
        self.assertEqual(toks, ["host.example.com", "foo.example.com"])


class TestAggregate(unittest.TestCase):
    def test_demo_merge(self):
        res = aggregate([DEMO], scope="example.com")
        hosts = {s.host for s in res.subdomains}
        self.assertIn("www.example.com", hosts)
        self.assertIn("api.example.com", hosts)
        self.assertIn("dev.example.com", hosts)        # from wildcard
        self.assertIn("cdn.assets.example.com", hosts)
        self.assertNotIn("shop.evil-corp.com", hosts)  # out of scope
        self.assertTrue(res.out_of_scope >= 1)
        self.assertTrue(res.invalid >= 1)
        self.assertTrue(res.duplicates >= 1)
        # www reported by subfinder + amass + assetfinder
        www = next(s for s in res.subdomains if s.host == "www.example.com")
        self.assertGreaterEqual(www.source_count, 2)
        # sorted by depth then name
        depths = [s.depth for s in res.subdomains]
        self.assertEqual(depths, sorted(depths))


class TestCli(unittest.TestCase):
    def test_json_output_and_exit(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["merge", DEMO, "-s", "example.com", "-f", "json"])
        self.assertEqual(rc, 1)  # findings -> non-zero
        data = json.loads(buf.getvalue())
        self.assertEqual(data["scope"], "example.com")
        self.assertGreater(data["stats"]["unique"], 0)

    def test_empty_exit_zero(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "empty.txt")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("# nothing here\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["merge", p, "-f", "json"])
            self.assertEqual(rc, 0)

    def test_version_constants(self):
        self.assertEqual(TOOL_NAME, "subhunt")
        self.assertTrue(TOOL_VERSION)


if __name__ == "__main__":
    unittest.main()
