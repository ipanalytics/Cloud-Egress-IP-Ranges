from __future__ import annotations

from pathlib import Path
import unittest

from cloud_egress_ip_ranges.sources.aws import parse_aws_ip_ranges
from cloud_egress_ip_ranges.sources.azure import parse_azure_service_tags
from cloud_egress_ip_ranges.sources.cloudflare import parse_cloudflare_api, parse_cloudflare_text
from cloud_egress_ip_ranges.sources.common import build_request
from cloud_egress_ip_ranges.sources.google import parse_google_ranges
from cloud_egress_ip_ranges.sources.platforms import platform_metadata

FIXTURES = Path(__file__).parent / "fixtures"


class SourceParserTests(unittest.TestCase):
    def test_aws_parser_preserves_service_region_and_border_group(self) -> None:
        records = parse_aws_ip_ranges(FIXTURES / "aws-ip-ranges.json")
        self.assertEqual(len(records), 3)
        first = records[0]
        self.assertEqual(first.provider, "aws")
        self.assertEqual(first.service_hint, "AMAZON")
        self.assertEqual(first.region, "ap-northeast-2")
        self.assertEqual(first.network_border_group, "ap-northeast-2")
        self.assertFalse(first.serverless_exact)

    def test_google_parser_distinguishes_cloud_and_goog(self) -> None:
        cloud = parse_google_ranges(FIXTURES / "google-cloud.json", feed_kind="cloud")
        goog = parse_google_ranges(FIXTURES / "google-goog.json", feed_kind="goog")
        self.assertEqual(len(cloud), 2)
        self.assertEqual(len(goog), 1)
        self.assertEqual(cloud[0].provider, "google_cloud")
        self.assertTrue(cloud[0].serverless_possible)
        self.assertEqual(goog[0].provider, "google")
        self.assertFalse(goog[0].serverless_possible)

    def test_azure_parser_maps_tags_and_regions(self) -> None:
        records = parse_azure_service_tags(FIXTURES / "azure-service-tags.json")
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0].provider, "azure")
        self.assertEqual(records[0].service_hint, "AzureCloud.westeurope")
        self.assertEqual(records[0].region, "westeurope")
        self.assertTrue(records[0].serverless_possible)

    def test_cloudflare_text_and_api(self) -> None:
        text_records = parse_cloudflare_text(FIXTURES / "cloudflare-ips-v4.txt")
        text_records += parse_cloudflare_text(FIXTURES / "cloudflare-ips-v6.txt")
        api_records = parse_cloudflare_api(FIXTURES / "cloudflare-api.json")
        self.assertEqual(len(text_records), 3)
        self.assertEqual(len(api_records), 2)
        self.assertTrue(all(record.edge_possible for record in text_records + api_records))
        self.assertTrue(all(record.provider == "cloudflare" for record in text_records + api_records))

    def test_platform_metadata_has_no_fake_cidrs(self) -> None:
        metadata = platform_metadata()
        self.assertEqual({item["provider"] for item in metadata}, {"vercel", "netlify"})
        self.assertTrue(all("cidr" not in item for item in metadata))
        self.assertTrue(all(item["public_ranges_available"] is False for item in metadata))

    def test_live_fetch_request_uses_provider_friendly_headers(self) -> None:
        request = build_request("https://download.microsoft.com/example.json")
        self.assertIn("cloud-egress-ip-ranges", request.headers["User-agent"])
        self.assertIn("application/json", request.headers["Accept"])


if __name__ == "__main__":
    unittest.main()
