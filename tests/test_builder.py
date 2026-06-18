from __future__ import annotations

import csv
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cloud_egress_ip_ranges.builder import (
    EGRESS_CAPABILITIES_JSON,
    LATEST_JSON,
    PROVIDER_CATALOG_JSON,
    PROVIDER_CATALOG_MARKDOWN,
    PROVIDERS_YAML,
    ROOT_CSV,
    ROOT_DUCKDB,
    ROOT_JSON,
    ROOT_JSONL,
    ROOT_PARQUET,
    ROOT_SQLITE,
    SOURCES_MARKDOWN,
    build_from_fixtures,
    write_artifacts,
)
from cloud_egress_ip_ranges.sources.aws import parse_aws_ip_ranges


class BuilderTests(unittest.TestCase):
    def test_build_writes_root_and_classified_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            manifest = write_artifacts(build_from_fixtures(), output, offline=True)
            self.assertTrue((output / ROOT_JSON).exists())
            self.assertTrue((output / ROOT_CSV).exists())
            self.assertTrue((output / ROOT_JSONL).exists())
            self.assertTrue((output / ROOT_PARQUET).exists())
            self.assertTrue((output / ROOT_SQLITE).exists())
            self.assertTrue((output / ROOT_DUCKDB).exists())
            self.assertTrue((output / "manifest.json").exists())
            self.assertTrue((output / LATEST_JSON).exists())
            self.assertTrue((output / "diff" / LATEST_JSON).exists())
            self.assertTrue((output / PROVIDERS_YAML).exists())
            self.assertTrue((output / EGRESS_CAPABILITIES_JSON).exists())
            self.assertTrue((output / SOURCES_MARKDOWN).exists())
            self.assertTrue((output / PROVIDER_CATALOG_JSON).exists())
            self.assertTrue((output / PROVIDER_CATALOG_MARKDOWN).exists())
            self.assertTrue((output / "classified" / "provider" / "aws.json").exists())
            self.assertTrue((output / "integrations" / "nginx" / "geo.conf").exists())
            self.assertTrue((output / "integrations" / "cloudflare" / "ip-list.txt").exists())
            self.assertTrue((output / "integrations" / "splunk" / "cloud_egress_lookup.csv").exists())
            self.assertTrue((output / "integrations" / "elastic" / "bulk.ndjson").exists())
            self.assertTrue((output / "integrations" / "clickhouse" / "cloud_egress_ip_ranges.sql").exists())
            self.assertGreater(manifest["total_records"], 0)
            self.assertGreater(len(manifest["classified"]), 0)
            self.assertEqual(len(manifest["integrations"]), 5)
            self.assertGreater(len(manifest["source_catalog"]), 0)
            self.assertGreater(manifest["provider_catalog_coverage"]["catalog_providers"], 100)
            self.assertGreaterEqual(manifest["provider_catalog_coverage"]["providers_with_cidr_records"], 19)

    def test_json_and_csv_counts_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            write_artifacts(build_from_fixtures(), output, offline=True)
            payload = json.loads((output / ROOT_JSON).read_text(encoding="utf-8"))
            with (output / ROOT_CSV).open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(payload["records"]), len(rows))
            self.assertEqual(len((output / ROOT_JSONL).read_text(encoding="utf-8").splitlines()), len(rows))

    def test_columnar_and_database_outputs_are_readable(self) -> None:
        import duckdb
        import pyarrow.parquet as pq

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            manifest = write_artifacts(build_from_fixtures(), output, offline=True)
            with sqlite3.connect(output / ROOT_SQLITE) as conn:
                count = conn.execute("select count(*) from egress_ranges").fetchone()[0]
            self.assertEqual(pq.read_table(output / ROOT_PARQUET).num_rows, manifest["total_records"])
            self.assertEqual(count, manifest["total_records"])
            with duckdb.connect(str(output / ROOT_DUCKDB)) as conn:
                count = conn.execute("select count(*) from egress_ranges").fetchone()[0]
            self.assertEqual(count, manifest["total_records"])

    def test_offline_build_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as left, tempfile.TemporaryDirectory() as right:
            write_artifacts(build_from_fixtures(), Path(left), offline=True)
            write_artifacts(build_from_fixtures(), Path(right), offline=True)
            self.assertEqual((Path(left) / ROOT_JSON).read_bytes(), (Path(right) / ROOT_JSON).read_bytes())
            self.assertEqual((Path(left) / ROOT_CSV).read_bytes(), (Path(right) / ROOT_CSV).read_bytes())
            self.assertEqual((Path(left) / ROOT_JSONL).read_bytes(), (Path(right) / ROOT_JSONL).read_bytes())
            self.assertEqual((Path(left) / PROVIDERS_YAML).read_bytes(), (Path(right) / PROVIDERS_YAML).read_bytes())

    def test_classified_files_match_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            write_artifacts(build_from_fixtures(), output, offline=True)
            provider_payload = json.loads(
                (output / "classified" / "provider" / "cloudflare.json").read_text(encoding="utf-8")
            )
            self.assertEqual(provider_payload["classification"], {"kind": "provider", "value": "cloudflare"})
            self.assertTrue(all(row["provider"] == "cloudflare" for row in provider_payload["records"]))

    def test_malformed_fixture_failure_is_actionable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            bad = Path(temp) / "bad-aws.json"
            bad.write_text('{"prefixes": []}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "aws_ip_ranges_json"):
                parse_aws_ip_ranges(bad)

    def test_sources_markdown_contains_provider_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            write_artifacts(build_from_fixtures(), output, offline=True)
            text = (output / SOURCES_MARKDOWN).read_text(encoding="utf-8")
            self.assertIn("AWS ip-ranges.json", text)
            self.assertIn("Google Cloud cloud.json", text)
            self.assertIn("Azure Public Service Tags JSON", text)
            self.assertIn("Cloudflare IPv4 ranges", text)

    def test_provider_catalog_markdown_reports_unimplemented_providers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            manifest = write_artifacts(build_from_fixtures(), output, offline=True)
            text = (output / PROVIDER_CATALOG_MARKDOWN).read_text(encoding="utf-8")
            registry = (output / PROVIDERS_YAML).read_text(encoding="utf-8")
            self.assertIn("hetzner", text)
            self.assertIn("id: hetzner", registry)
            self.assertIn("asn_bgp", text)
            self.assertIn("Providers not in the CIDR feed yet", text)
            self.assertNotIn("akamai", manifest["provider_catalog_coverage"]["not_in_cidr_feed"])

    def test_diff_uses_previous_feed_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as previous_dir, tempfile.TemporaryDirectory() as current_dir:
            previous = Path(previous_dir)
            current = Path(current_dir)
            records = build_from_fixtures()
            write_artifacts(records[:-1], previous, offline=True)
            write_artifacts(records, current, offline=True, previous_feed=previous / ROOT_JSON)
            diff = json.loads((current / "diff" / LATEST_JSON).read_text(encoding="utf-8"))
            self.assertEqual(diff["added_count"], 1)
            self.assertEqual(diff["removed_count"], 0)


if __name__ == "__main__":
    unittest.main()
