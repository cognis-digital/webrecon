"""Smoke tests for WEBRECON. No network access."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from webrecon import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    fingerprint,
    fingerprint_response,
    load_response,
)
from webrecon.cli import main  # noqa: E402


DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic", "sample_response.http",
)


def _names(result):
    return {f.name for f in result.findings}


class TestExports(unittest.TestCase):
    def test_tool_metadata(self):
        self.assertEqual(TOOL_NAME, "webrecon")
        self.assertTrue(TOOL_VERSION)


class TestHeaderFingerprint(unittest.TestCase):
    def test_nginx_and_php_from_headers(self):
        result = fingerprint(
            headers={"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.12"},
            body="",
            status=200,
        )
        names = _names(result)
        self.assertIn("nginx", names)
        self.assertIn("PHP", names)
        nginx = next(f for f in result.findings if f.name == "nginx")
        self.assertEqual(nginx.version, "1.24.0")
        php = next(f for f in result.findings if f.name == "PHP")
        self.assertEqual(php.version, "8.2.12")

    def test_cloudflare_from_cf_ray(self):
        result = fingerprint(headers={"CF-RAY": "abc-IAD"})
        self.assertIn("Cloudflare", _names(result))

    def test_cookie_signatures(self):
        result = fingerprint(
            headers={"Set-Cookie": "JSESSIONID=xyz; path=/"},
        )
        self.assertIn("Java", _names(result))

    def test_no_match_returns_note(self):
        result = fingerprint(headers={"X-Foo": "bar"}, body="<html></html>")
        self.assertEqual(result.findings, [])
        self.assertTrue(result.notes)


class TestBodyFingerprint(unittest.TestCase):
    def test_wordpress_generator_version(self):
        body = '<meta name="generator" content="WordPress 6.5.3">'
        result = fingerprint(body=body)
        wp = next(f for f in result.findings if f.name == "WordPress")
        self.assertEqual(wp.version, "6.5.3")
        self.assertGreaterEqual(wp.confidence, 90)

    def test_jquery_version_from_script(self):
        body = '<script src="/js/jquery-3.7.1.min.js"></script>'
        result = fingerprint(body=body)
        jq = next(f for f in result.findings if f.name == "jQuery")
        self.assertEqual(jq.version, "3.7.1")


class TestRawResponseParsing(unittest.TestCase):
    def test_load_response_splits_status_headers_body(self):
        raw = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html></html>"
        headers, body, status = load_response(raw)
        self.assertEqual(status, 200)
        self.assertEqual(headers["server"], "nginx")
        self.assertIn("<html>", body)

    def test_multiple_set_cookie_folded(self):
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: a=1\r\n"
            "Set-Cookie: PHPSESSID=2\r\n"
            "\r\nbody"
        )
        result = fingerprint_response(raw)
        self.assertIn("PHP", _names(result))


class TestDemoAndCli(unittest.TestCase):
    def test_demo_file_exists(self):
        self.assertTrue(os.path.exists(DEMO))

    def test_demo_full_stack_detected(self):
        with open(DEMO, "r", encoding="utf-8") as fh:
            result = fingerprint_response(fh.read())
        names = _names(result)
        for expected in ("nginx", "PHP", "WordPress", "Cloudflare", "jQuery"):
            self.assertIn(expected, names)
        self.assertEqual(result.status, 200)

    def test_cli_json_exit_code_on_findings(self):
        rc = main(["scan", DEMO, "--format", "json"])
        self.assertEqual(rc, 1)

    def test_cli_table_runs(self):
        rc = main(["scan", DEMO])
        self.assertEqual(rc, 1)

    def test_cli_no_args_returns_usage_code(self):
        rc = main([])
        self.assertEqual(rc, 2)

    def test_json_is_valid(self):
        with open(DEMO, "r", encoding="utf-8") as fh:
            result = fingerprint_response(fh.read())
        payload = json.loads(json.dumps(result.to_dict()))
        self.assertIn("findings", payload)


if __name__ == "__main__":
    unittest.main()
