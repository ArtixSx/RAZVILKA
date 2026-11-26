#!/usr/bin/env python3
"""Offline regression for the bounded official .deb fallback."""
import hashlib
import importlib.util
import io
from pathlib import Path
import ssl
import unittest
import urllib.error
from unittest.mock import call, patch


spec = importlib.util.spec_from_file_location("fixture", Path(__file__).with_name("check-classic-save-pinned-fixture.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

filename = "iptables_1.8.11-2ubuntu3_amd64.deb"
snapshot = "https://snapshot.ubuntu.com/ubuntu/20261117T000000Z/pool/main/i/iptables/" + filename
launchpad = "https://launchpad.net/ubuntu/+archive/primary/+files/" + filename
published = "https://launchpadlibrarian.net/123/" + filename
body = b"synthetic archive"
package = dict(name="iptables", version="1.8.11-2ubuntu3", architecture="amd64",
               url=snapshot, bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def response(url, content=body):
    stream = io.BytesIO(content)
    stream.url = url
    return stream


class Acquisition(unittest.TestCase):
    def http_error(self, code):
        err = urllib.error.HTTPError(snapshot, code, "fixture", {}, io.BytesIO())
        self.addCleanup(err.close)
        return err

    def test_snapshot(self):
        with patch("urllib.request.urlopen", return_value=response(snapshot)) as fetch:
            self.assertEqual(fixture.read_pinned_archive(package), body)
            fetch.assert_called_once_with(snapshot, timeout=30)

    def test_transient_retries_exact_official_file_once(self):
        for error in (self.http_error(502), TimeoutError(), urllib.error.URLError(ConnectionResetError())):
            with self.subTest(error=error), patch("urllib.request.urlopen", side_effect=[error, response(published)]) as fetch:
                self.assertEqual(fixture.read_pinned_archive(package), body)
                self.assertEqual(fetch.call_args_list, [call(snapshot, timeout=30), call(launchpad, timeout=30)])
        with patch("urllib.request.urlopen", side_effect=[self.http_error(503), self.http_error(503)]) as fetch:
            with self.assertRaises(urllib.error.HTTPError):
                fixture.read_pinned_archive(package)
            self.assertEqual(fetch.call_count, 2)

    def test_nontransient_does_not_retry(self):
        for error in (self.http_error(403), self.http_error(404), urllib.error.URLError(ssl.SSLCertVerificationError())):
            with self.subTest(error=error), patch("urllib.request.urlopen", side_effect=error) as fetch:
                with self.assertRaises(urllib.error.URLError):
                    fixture.read_pinned_archive(package)
                self.assertEqual(fetch.call_count, 1)

    def test_each_source_verifies_size_digest_and_location(self):
        for fallback in (False, True):
            host = published if fallback else snapshot
            for invalid in (response(host, b"x" * len(body)), response(host, body[:-1]),
                            response(host, body + b"x"), response("https://example.org/file"),
                            response(host.replace("https:", "http:"))):
                attempts = [self.http_error(502), invalid] if fallback else [invalid]
                with self.subTest(fallback=fallback, location=invalid.url), patch("urllib.request.urlopen", side_effect=attempts) as fetch:
                    with self.assertRaises(SystemExit):
                        fixture.read_pinned_archive(package)
                    self.assertEqual(fetch.call_count, len(attempts))


if __name__ == "__main__":
    unittest.main()
