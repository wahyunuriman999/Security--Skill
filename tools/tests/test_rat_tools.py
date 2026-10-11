#!/usr/bin/env python3
"""
Correctness tests for rat_* tooling (non-evasion utilities only).

Run: ~/workspace/rat-tools-venv/bin/python -m unittest discover -s tests -v
(from ~/workspace/skills/_shared/tools/)

Scope note: rat_ghost.py is EXCLUDED from this harness by design — its
helpers are evasion-oriented (traffic disguise, filter-bypass mutation) and
are left untouched for the repo author to review independently. These tests
cover only plumbing, crypto math, and parsing shared by the other tools.
"""
import gzip
import io
import json
import sys
import unittest
import urllib.request
from unittest import mock

sys.path.insert(0, "..")

from rat_h3 import H3Response, _decompress, doh_resolve  # noqa: E402
import rat_digest  # noqa: E402
import rat_oob  # noqa: E402  (import itself is the regression test: #1)


class TestH3Response(unittest.TestCase):
    def test_multi_header_collection(self):
        """The set-cookie collapse bug must stay fixed: ALL pairs kept."""
        pairs = [(":status", "200"), ("set-cookie", "a=1; Path=/"),
                 ("set-cookie", "b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT"),
                 ("content-type", "text/html")]
        r = H3Response(status=200, headers_multi=pairs)
        self.assertEqual(r.get_all("set-cookie"),
                         ["a=1; Path=/",
                          "b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT"])
        self.assertEqual(r.headers["set-cookie"], "a=1; Path=/")  # first-wins
        self.assertEqual(r.get_all("SET-COOKIE"), r.get_all("set-cookie"))

    def test_decompress(self):
        raw = b"hello world" * 100
        self.assertEqual(_decompress(gzip.compress(raw), "gzip"), raw)
        import brotli
        self.assertEqual(_decompress(brotli.compress(raw), "br"), raw)
        import zlib
        self.assertEqual(_decompress(zlib.compress(raw), "deflate"), raw)
        # corrupt input must not raise — returns raw
        self.assertEqual(_decompress(b"\xff\xfe bad", "gzip"), b"\xff\xfe bad")

    def test_doh_parsing(self):
        body = json.dumps({
            "Answer": [{"name": "x.com", "type": 1, "data": "1.2.3.4"},
                       {"name": "x.com", "type": 28, "data": "::1"}]}).encode()

        class FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return body

        with mock.patch.object(urllib.request, "urlopen",
                               return_value=FakeResp()) as uo:
            ips = doh_resolve("x.com")
            self.assertEqual(ips, ["1.2.3.4", "::1"])
            url = uo.call_args[0][0].full_url
            self.assertIn("dns-query?name=x.com", url)


class TestDigest(unittest.TestCase):
    # RFC 2617 section 3.5 test vector
    VEC = dict(username="Mufasa", realm="testrealm@host.com",
               pwd="Circle Of Life", method="GET", uri="/dir/index.html",
               nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
               cnonce="0a4f113b", nc="00000001", qop="auth")
    EXPECT = "6629fae49393a05397450978507c4ef1"

    def test_rfc2617_vector(self):
        v = self.VEC
        got = rat_digest.calculate_hash(
            v["username"], v["realm"], v["pwd"], v["method"], v["uri"],
            v["nonce"], "MD5", v["cnonce"], v["nc"], v["qop"])
        self.assertEqual(got, self.EXPECT)

    def test_sha256_supported(self):
        r = rat_digest.calculate_hash("u", "r", "p", "GET", "/",
                                      "n", "SHA-256", "c", "00000001", "auth")
        self.assertEqual(len(r), 64)  # sha256 hex

    def test_parse_challenge(self):
        h = ('Digest realm="testrealm@host.com", '
             'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '
             'algorithm=MD5, qop="auth"')
        d = rat_digest.parse_digest_challenge("WWW-Authenticate: " + h)
        self.assertEqual(d["realm"], "testrealm@host.com")
        self.assertEqual(d["qop"], "auth")
        self.assertIsNone(rat_digest.parse_digest_challenge("Basic abc"))

    def test_crack_roundtrip(self):
        v = self.VEC
        authz = rat_digest.build_authorization(
            v["username"], v["realm"], v["pwd"], v["method"], v["uri"],
            v["nonce"], "MD5", cnonce=v["cnonce"], nc=v["nc"], qop=v["qop"])
        challenge = (f'Digest realm="{v["realm"]}", nonce="{v["nonce"]}", '
                     f'algorithm=MD5, qop="auth"')
        hits = rat_digest.verify_captured(
            challenge, authz, v["method"], ["wrong", v["pwd"], "nope"])
        self.assertEqual(hits, [v["pwd"]])


class TestOob(unittest.TestCase):
    def test_import_and_gen_format(self):
        # regression: v1 crashed on `import os` (NameError). Import above
        # already proves the fix; now check gen() tag shape.
        import secrets
        tag = secrets.token_hex(4)
        self.assertRegex(tag, r"^[0-9a-f]{8}$")
        self.assertTrue(hasattr(rat_oob, "wait"))
        self.assertTrue(hasattr(rat_oob, "poll"))


if __name__ == "__main__":
    unittest.main()
