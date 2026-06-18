from __future__ import annotations

import unittest
from pathlib import Path
import tempfile

from cloud_egress_ip_ranges.builder import build_from_fixtures, write_artifacts
from cloud_egress_ip_ranges.explain import explain_lookup
from cloud_egress_ip_ranges.feed import load_feed
from cloud_egress_ip_ranges.lookup import lookup_ip


class LookupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.output = Path(self.temp.name)
        write_artifacts(build_from_fixtures(), self.output, offline=True)
        self.feed = load_feed(self.output / "cloud-egress-ip-ranges.json")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_feed_counts(self) -> None:
        self.assertEqual(self.feed.provider_counts["cloudflare"], 5)
        self.assertEqual(self.feed.source_counts["aws_ip_ranges_json"], 3)
        self.assertIn("cloudflare_edge", self.feed.service_counts)

    def test_ipv4_lookup(self) -> None:
        result = lookup_ip(self.feed, "1.1.1.1")
        self.assertGreater(len(result.matches), 0)
        self.assertEqual(result.matches[0].provider, "cloudflare")

    def test_ipv6_lookup(self) -> None:
        result = lookup_ip(self.feed, "2606:4700::1")
        self.assertGreater(len(result.matches), 0)
        self.assertEqual(result.matches[0].provider, "cloudflare")

    def test_no_match(self) -> None:
        result = lookup_ip(self.feed, "203.0.113.1")
        self.assertEqual(result.matches, ())

    def test_invalid_ip(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid IP address"):
            lookup_ip(self.feed, "not-an-ip")

    def test_explanation_includes_limits(self) -> None:
        result = lookup_ip(self.feed, "1.1.1.1")
        text = explain_lookup(result)
        self.assertIn("serverless possible", text)
        self.assertIn("edge possible", text)
        self.assertIn("exact serverless attribution is not claimed", text)
        self.assertIn("confidence=", text)


if __name__ == "__main__":
    unittest.main()
