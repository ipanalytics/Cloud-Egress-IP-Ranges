from __future__ import annotations

from pathlib import Path
import unittest

from cloud_egress_ip_ranges.sources.aws import parse_aws_ip_ranges
from cloud_egress_ip_ranges.sources.asn_bgp import (
    ASN_PROVIDER_SPECS,
    fetch_ripe_stat_asn_records,
    parse_ripe_stat_announced_prefixes,
)
from cloud_egress_ip_ranges.sources.azure import parse_azure_service_tags
from cloud_egress_ip_ranges.sources.atlassian import parse_atlassian_ip_ranges
from cloud_egress_ip_ranges.sources.cloudflare import parse_cloudflare_api, parse_cloudflare_text
from cloud_egress_ip_ranges.sources.common import build_request, normalize_url
from cloud_egress_ip_ranges.sources.fastly import parse_fastly_public_ip_list
from cloud_egress_ip_ranges.sources.github import parse_github_meta
from cloud_egress_ip_ranges.sources.gitlab import parse_gitlab_com_docs
from cloud_egress_ip_ranges.sources.google import parse_google_ranges
from cloud_egress_ip_ranges.sources.oracle import parse_oracle_public_ip_ranges
from cloud_egress_ip_ranges.sources.platforms import platform_metadata
from cloud_egress_ip_ranges.sources.stripe import parse_stripe_ips

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

    def test_oracle_parser(self) -> None:
        records = parse_oracle_public_ip_ranges(FIXTURES / "oracle-public-ip-ranges.json")
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].provider, "oracle_cloud")
        self.assertEqual(records[0].region, "eu-frankfurt-1")
        self.assertIn("OCI", records[0].service_hint)

    def test_fastly_parser(self) -> None:
        records = parse_fastly_public_ip_list(FIXTURES / "fastly-public-ip-list.json")
        self.assertEqual(len(records), 3)
        self.assertTrue(all(record.provider == "fastly" for record in records))
        self.assertTrue(all(record.edge_possible for record in records))

    def test_github_parser(self) -> None:
        records = parse_github_meta(FIXTURES / "github-meta.json")
        services = {record.service_hint for record in records}
        self.assertIn("github_actions", services)
        self.assertIn("github_hooks", services)
        self.assertIn("github_pages", services)

    def test_gitlab_docs_parser(self) -> None:
        records = parse_gitlab_com_docs(FIXTURES / "gitlab-com.html")
        self.assertEqual({record.cidr for record in records}, {"34.74.90.64/28", "34.74.226.0/24"})
        self.assertTrue(all(record.source_type == "official_docs" for record in records))

    def test_atlassian_parser_filters_egress_ranges(self) -> None:
        records = parse_atlassian_ip_ranges(FIXTURES / "atlassian-ip-ranges.json")
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].provider, "atlassian")
        self.assertEqual(records[0].source, "atlassian_ip_ranges_json")
        self.assertTrue(all(record.source_type == "official_feed" for record in records))

    def test_stripe_parser_normalizes_ips_to_cidr(self) -> None:
        records = parse_stripe_ips(
            FIXTURES / "stripe-webhook-ips.json",
            group="WEBHOOKS",
            source_label="stripe_webhook_ips_json",
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].provider, "stripe")
        self.assertEqual(records[0].cidr, "3.18.12.63/32")
        self.assertEqual(records[0].service_hint, "stripe_webhooks")

    def test_ripe_stat_asn_bgp_parser_marks_weak_inference(self) -> None:
        records = parse_ripe_stat_announced_prefixes(
            FIXTURES / "ripe-announced-prefixes.json",
            ASN_PROVIDER_SPECS[0],
            ASN_PROVIDER_SPECS[0].asns[0],
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].source, "ripe_stat_announced_prefixes")
        self.assertEqual(records[0].source_type, "asn_bgp")
        self.assertEqual(records[0].precision_level, "L5")
        self.assertIn("AS", records[0].network_border_group)

    def test_ripe_stat_fetch_skips_empty_asn_results(self) -> None:
        empty = FIXTURES / "ripe-announced-prefixes-empty.json"
        spec = ASN_PROVIDER_SPECS[0]
        try:
            import cloud_egress_ip_ranges.sources.asn_bgp as asn_bgp

            original = asn_bgp.RIPESTAT_ANNOUNCED_PREFIXES_URL
            asn_bgp.RIPESTAT_ANNOUNCED_PREFIXES_URL = str(empty)
            self.assertEqual(fetch_ripe_stat_asn_records((spec,)), [])
        finally:
            asn_bgp.RIPESTAT_ANNOUNCED_PREFIXES_URL = original

    def test_platform_metadata_has_no_fake_cidrs(self) -> None:
        metadata = platform_metadata()
        self.assertEqual({item["provider"] for item in metadata}, {"vercel", "netlify"})
        self.assertTrue(all("cidr" not in item for item in metadata))
        self.assertTrue(all(item["public_ranges_available"] is False for item in metadata))

    def test_live_fetch_request_uses_provider_friendly_headers(self) -> None:
        request = build_request("https://download.microsoft.com/example.json")
        self.assertIn("cloud-egress-ip-ranges", request.headers["User-agent"])
        self.assertIn("application/json", request.headers["Accept"])

    def test_markdown_url_is_normalized_before_fetch(self) -> None:
        url = "https://download.microsoft.com/download/example/ServiceTags_Public_20260608.json"
        markdown_url = f"[{url}]({url})"
        self.assertEqual(normalize_url(markdown_url), url)
        self.assertEqual(build_request(markdown_url).full_url, url)


if __name__ == "__main__":
    unittest.main()
