from __future__ import annotations

import csv
import hashlib
import json
import shutil
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

from .models import EgressRangeRecord, SCHEMA_VERSION, utc_now_iso
from .provider_catalog import provider_catalog
from .sources.asn_bgp import RIPESTAT_ANNOUNCED_PREFIXES_URL, fetch_ripe_stat_asn_records, parse_ripe_stat_announced_prefixes, ASN_PROVIDER_SPECS
from .sources.atlassian import parse_atlassian_ip_ranges
from .sources.aws import parse_aws_ip_ranges
from .sources.azure import parse_azure_service_tags
from .sources.cloudflare import parse_cloudflare_api, parse_cloudflare_text
from .sources.fastly import parse_fastly_public_ip_list
from .sources.github import parse_github_meta
from .sources.gitlab import parse_gitlab_com_docs
from .sources.google import parse_google_ranges
from .sources.oracle import parse_oracle_public_ip_ranges
from .sources.stripe import parse_stripe_ips

FIXED_OFFLINE_TIMESTAMP = "2026-06-18T00:00:00Z"
AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GOOGLE_CLOUD_URL = "https://www.gstatic.com/ipranges/cloud.json"
GOOGLE_GOOG_URL = "https://www.gstatic.com/ipranges/goog.json"
CLOUDFLARE_V4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_V6_URL = "https://www.cloudflare.com/ips-v6"
ORACLE_URL = "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"
FASTLY_URL = "https://api.fastly.com/public-ip-list"
GITHUB_META_URL = "https://api.github.com/meta"
GITLAB_DOCS_URL = "https://docs.gitlab.com/user/gitlab_com/"
ATLASSIAN_URL = "https://ip-ranges.atlassian.com/"
STRIPE_WEBHOOKS_URL = "https://stripe.com/files/ips/ips_webhooks.json"
STRIPE_API_URL = "https://stripe.com/files/ips/ips_api.json"
ROOT_JSON = "cloud-egress-ip-ranges.json"
ROOT_CSV = "cloud-egress-ip-ranges.csv"
ROOT_JSONL = "cloud-egress-ip-ranges.jsonl"
ROOT_PARQUET = "cloud-egress-ip-ranges.parquet"
ROOT_SQLITE = "cloud-egress-ip-ranges.sqlite"
ROOT_DUCKDB = "cloud-egress-ip-ranges.duckdb"
MANIFEST = "manifest.json"
SOURCES_MARKDOWN = "sources.md"
LATEST_JSON = "latest.json"
PROVIDERS_YAML = "providers.yaml"
EGRESS_CAPABILITIES_JSON = "egress-capabilities.json"
PROVIDER_CATALOG_JSON = "provider-catalog.json"
PROVIDER_CATALOG_MARKDOWN = "provider-catalog.md"
SOURCE_CATALOG = [
    {
        "provider": "aws",
        "feed": "AWS ip-ranges.json",
        "source_id": "aws_ip_ranges_json",
        "url": AWS_URL,
        "classification": "cloud and AWS service ranges",
        "live": True,
    },
    {
        "provider": "google_cloud",
        "feed": "Google Cloud cloud.json",
        "source_id": "google_cloud_json",
        "url": GOOGLE_CLOUD_URL,
        "classification": "Google Cloud customer external IP ranges",
        "live": True,
    },
    {
        "provider": "google",
        "feed": "Google goog.json",
        "source_id": "google_goog_json",
        "url": GOOGLE_GOOG_URL,
        "classification": "Google-owned provider ranges",
        "live": True,
    },
    {
        "provider": "azure",
        "feed": "Azure Public Service Tags JSON",
        "source_id": "azure_service_tags_public_json",
        "url": "resolved daily from Microsoft Download Center",
        "classification": "Azure service-tag and regional ranges",
        "live": True,
    },
    {
        "provider": "oracle_cloud",
        "feed": "Oracle OCI public_ip_ranges.json",
        "source_id": "oracle_public_ip_ranges_json",
        "url": ORACLE_URL,
        "classification": "Oracle Cloud regional public IP ranges",
        "live": True,
    },
    {
        "provider": "cloudflare",
        "feed": "Cloudflare IPv4 ranges",
        "source_id": "cloudflare_ips_v4",
        "url": CLOUDFLARE_V4_URL,
        "classification": "Cloudflare edge network ranges",
        "live": True,
    },
    {
        "provider": "cloudflare",
        "feed": "Cloudflare IPv6 ranges",
        "source_id": "cloudflare_ips_v6",
        "url": CLOUDFLARE_V6_URL,
        "classification": "Cloudflare edge network ranges",
        "live": True,
    },
    {
        "provider": "fastly",
        "feed": "Fastly public IP list",
        "source_id": "fastly_public_ip_list",
        "url": FASTLY_URL,
        "classification": "Fastly edge/CDN and Compute possible ranges",
        "live": True,
    },
    {
        "provider": "github",
        "feed": "GitHub Meta API",
        "source_id": "github_meta_api",
        "url": GITHUB_META_URL,
        "classification": "GitHub Actions, hooks, pages, API, git, and web ranges",
        "live": True,
    },
    {
        "provider": "gitlab",
        "feed": "GitLab.com IP range docs",
        "source_id": "gitlab_com_docs",
        "url": GITLAB_DOCS_URL,
        "classification": "GitLab.com Web/API and webhook source ranges",
        "live": True,
    },
    {
        "provider": "atlassian",
        "feed": "Atlassian Cloud IP ranges",
        "source_id": "atlassian_ip_ranges_json",
        "url": ATLASSIAN_URL,
        "classification": "Atlassian Cloud egress ranges",
        "live": True,
    },
    {
        "provider": "stripe",
        "feed": "Stripe webhook IPs",
        "source_id": "stripe_webhook_ips_json",
        "url": STRIPE_WEBHOOKS_URL,
        "classification": "Stripe webhook source IPs",
        "live": True,
    },
    {
        "provider": "stripe",
        "feed": "Stripe API IPs",
        "source_id": "stripe_api_ips_json",
        "url": STRIPE_API_URL,
        "classification": "Stripe API source IPs",
        "live": True,
    },
    {
        "provider": "multi_provider",
        "feed": "RIPEstat announced-prefixes",
        "source_id": "ripe_stat_announced_prefixes",
        "url": RIPESTAT_ANNOUNCED_PREFIXES_URL,
        "classification": "ASN/BGP announced prefixes for curated providers",
        "live": True,
    },
]
CSV_FIELDS = [
    "cidr",
    "provider",
    "platform_family",
    "service_hint",
    "serverless_possible",
    "serverless_exact",
    "edge_possible",
    "region",
    "country_hint",
    "source",
    "source_type",
    "confidence",
    "recommended_action",
    "false_positive_risk",
    "last_seen",
    "last_updated",
    "precision_level",
    "network_border_group",
]


def build_from_fixtures(fixtures_dir: Path | str = "tests/fixtures") -> list[EgressRangeRecord]:
    fixtures = Path(fixtures_dir)
    records: list[EgressRangeRecord] = []
    records.extend(parse_aws_ip_ranges(fixtures / "aws-ip-ranges.json"))
    records.extend(parse_google_ranges(fixtures / "google-cloud.json", feed_kind="cloud"))
    records.extend(parse_google_ranges(fixtures / "google-goog.json", feed_kind="goog"))
    records.extend(parse_azure_service_tags(fixtures / "azure-service-tags.json"))
    records.extend(parse_oracle_public_ip_ranges(fixtures / "oracle-public-ip-ranges.json"))
    records.extend(parse_cloudflare_text(fixtures / "cloudflare-ips-v4.txt", source_label="cloudflare_ips_v4"))
    records.extend(parse_cloudflare_text(fixtures / "cloudflare-ips-v6.txt", source_label="cloudflare_ips_v6"))
    records.extend(parse_cloudflare_api(fixtures / "cloudflare-api.json"))
    records.extend(parse_fastly_public_ip_list(fixtures / "fastly-public-ip-list.json"))
    records.extend(parse_github_meta(fixtures / "github-meta.json"))
    records.extend(parse_gitlab_com_docs(fixtures / "gitlab-com.html"))
    records.extend(parse_atlassian_ip_ranges(fixtures / "atlassian-ip-ranges.json"))
    records.extend(parse_stripe_ips(fixtures / "stripe-webhook-ips.json", group="WEBHOOKS", source_label="stripe_webhook_ips_json"))
    records.extend(parse_stripe_ips(fixtures / "stripe-api-ips.json", group="API", source_label="stripe_api_ips_json"))
    for spec in ASN_PROVIDER_SPECS[:8]:
        records.extend(parse_ripe_stat_announced_prefixes(fixtures / "ripe-announced-prefixes.json", spec, spec.asns[0]))
    return sort_records(records)


def build_from_live_sources(
    *,
    azure_service_tags_url: str,
    aws_url: str = AWS_URL,
    google_cloud_url: str = GOOGLE_CLOUD_URL,
    google_goog_url: str = GOOGLE_GOOG_URL,
    cloudflare_v4_url: str = CLOUDFLARE_V4_URL,
    cloudflare_v6_url: str = CLOUDFLARE_V6_URL,
    oracle_url: str = ORACLE_URL,
    fastly_url: str = FASTLY_URL,
    github_meta_url: str = GITHUB_META_URL,
    gitlab_docs_url: str = GITLAB_DOCS_URL,
    atlassian_url: str = ATLASSIAN_URL,
    stripe_webhooks_url: str = STRIPE_WEBHOOKS_URL,
    stripe_api_url: str = STRIPE_API_URL,
) -> list[EgressRangeRecord]:
    if not azure_service_tags_url:
        raise ValueError("live build requires --azure-service-tags-url")
    records: list[EgressRangeRecord] = []
    records.extend(parse_aws_ip_ranges(aws_url))
    records.extend(parse_google_ranges(google_cloud_url, feed_kind="cloud"))
    records.extend(parse_google_ranges(google_goog_url, feed_kind="goog"))
    records.extend(parse_azure_service_tags(azure_service_tags_url))
    records.extend(parse_oracle_public_ip_ranges(oracle_url))
    records.extend(parse_cloudflare_text(cloudflare_v4_url, source_label="cloudflare_ips_v4"))
    records.extend(parse_cloudflare_text(cloudflare_v6_url, source_label="cloudflare_ips_v6"))
    records.extend(parse_fastly_public_ip_list(fastly_url))
    records.extend(parse_github_meta(github_meta_url))
    records.extend(parse_gitlab_com_docs(gitlab_docs_url))
    records.extend(parse_atlassian_ip_ranges(atlassian_url))
    records.extend(parse_stripe_ips(stripe_webhooks_url, group="WEBHOOKS", source_label="stripe_webhook_ips_json"))
    records.extend(parse_stripe_ips(stripe_api_url, group="API", source_label="stripe_api_ips_json"))
    records.extend(fetch_ripe_stat_asn_records())
    return sort_records(records)


def sort_records(records: Iterable[EgressRangeRecord]) -> list[EgressRangeRecord]:
    return sorted(
        records,
        key=lambda record: (
            record.provider,
            record.platform_family,
            record.service_hint,
            record.network.version,
            int(record.network.network_address),
            record.network.prefixlen,
            record.cidr,
        ),
    )


def write_artifacts(
    records: list[EgressRangeRecord],
    output_dir: Path,
    *,
    offline: bool,
    previous_feed: Path | None = None,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    classified_dir = output_dir / "classified"
    if classified_dir.exists():
        shutil.rmtree(classified_dir)
    classified_dir.mkdir()
    integrations_dir = output_dir / "integrations"
    if integrations_dir.exists():
        shutil.rmtree(integrations_dir)
    integrations_dir.mkdir()
    diff_dir = output_dir / "diff"
    if diff_dir.exists():
        shutil.rmtree(diff_dir)
    diff_dir.mkdir()

    data = [record.to_dict() for record in sort_records(records)]
    timestamp = FIXED_OFFLINE_TIMESTAMP if offline else utc_now_iso()
    write_json(output_dir / ROOT_JSON, {"schema_version": SCHEMA_VERSION, "generated_at": timestamp, "records": data})
    write_csv(output_dir / ROOT_CSV, data)
    write_jsonl(output_dir / ROOT_JSONL, data)
    write_parquet(output_dir / ROOT_PARQUET, data)
    write_sqlite(output_dir / ROOT_SQLITE, data)
    write_duckdb(output_dir / ROOT_DUCKDB, data)
    classified = write_classified(classified_dir, data)
    integrations = write_integrations(integrations_dir, data)
    write_sources_markdown(output_dir / SOURCES_MARKDOWN, data, timestamp)
    catalog = provider_catalog()
    write_json(output_dir / PROVIDER_CATALOG_JSON, {"generated_at": timestamp, "providers": catalog})
    write_providers_yaml(output_dir / PROVIDERS_YAML, catalog)
    write_egress_capabilities(output_dir / EGRESS_CAPABILITIES_JSON, catalog)
    write_provider_catalog_markdown(output_dir / PROVIDER_CATALOG_MARKDOWN, catalog, data, timestamp)
    write_latest_json(output_dir / LATEST_JSON, data, timestamp)
    diff = build_diff(data, previous_feed)
    write_json(diff_dir / LATEST_JSON, {"generated_at": timestamp, **diff})

    manifest = build_manifest(output_dir, data, classified, integrations, timestamp)
    write_json(output_dir / MANIFEST, manifest)
    manifest["checksums"][MANIFEST] = sha256_file(output_dir / MANIFEST)
    write_json(output_dir / MANIFEST, manifest)
    return manifest


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, data: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in data:
            writer.writerow(row)


def write_jsonl(path: Path, data: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in data) + "\n", encoding="utf-8")


def write_parquet(path: Path, data: list[dict]) -> None:
    import pyarrow as pa
    import pyarrow.parquet as pq

    pq.write_table(pa.Table.from_pylist(flatten_for_tables(data), schema=table_schema()), path)


def write_sqlite(path: Path, data: list[dict]) -> None:
    if path.exists():
        path.unlink()
    with sqlite3.connect(path) as conn:
        conn.execute(table_sql("egress_ranges"))
        conn.executemany(insert_sql("egress_ranges"), table_rows(data))
        conn.execute("create index idx_egress_provider on egress_ranges(provider)")
        conn.execute("create index idx_egress_source on egress_ranges(source)")
        conn.execute("create index idx_egress_service on egress_ranges(service_hint)")


def write_duckdb(path: Path, data: list[dict]) -> None:
    import duckdb

    if path.exists():
        path.unlink()
    with duckdb.connect(str(path)) as conn:
        conn.execute(table_sql("egress_ranges").replace("text", "varchar").replace("integer", "bigint"))
        conn.executemany(insert_sql("egress_ranges"), table_rows(data))


def flatten_for_tables(data: list[dict]) -> list[dict]:
    rows = []
    for row in data:
        item = {field: row.get(field) for field in CSV_FIELDS}
        item["notes"] = json.dumps(row.get("notes", []), sort_keys=True)
        rows.append(item)
    return rows


def table_schema():
    import pyarrow as pa

    fields = []
    for field in CSV_FIELDS:
        if field in {"serverless_possible", "serverless_exact", "edge_possible"}:
            fields.append(pa.field(field, pa.bool_()))
        elif field in {"confidence", "false_positive_risk"}:
            fields.append(pa.field(field, pa.int64()))
        else:
            fields.append(pa.field(field, pa.string()))
    fields.append(pa.field("notes", pa.string()))
    return pa.schema(fields)


def table_columns() -> list[str]:
    return [*CSV_FIELDS, "notes"]


def table_rows(data: list[dict]) -> list[tuple]:
    return [tuple(row.get(column) for column in table_columns()) for row in flatten_for_tables(data)]


def table_sql(table: str) -> str:
    column_defs = []
    for column in table_columns():
        if column in {"serverless_possible", "serverless_exact", "edge_possible"}:
            column_defs.append(f"{column} integer")
        elif column in {"confidence", "false_positive_risk"}:
            column_defs.append(f"{column} integer")
        else:
            column_defs.append(f"{column} text")
    return f"create table {table} ({', '.join(column_defs)})"


def insert_sql(table: str) -> str:
    columns = table_columns()
    return f"insert into {table} ({', '.join(columns)}) values ({', '.join('?' for _ in columns)})"


def write_classified(classified_dir: Path, data: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in data:
        groups[("provider", row["provider"])].append(row)
        groups[("platform_family", row["platform_family"])].append(row)
        groups[("precision_level", row["precision_level"])].append(row)
        groups[("recommended_action", row["recommended_action"])].append(row)
        groups[("service_hint", row["service_hint"])].append(row)

    inventory: list[dict] = []
    for (kind, value), rows in sorted(groups.items()):
        safe_value = slug(value)
        base = classified_dir / kind
        base.mkdir(parents=True, exist_ok=True)
        json_path = base / f"{safe_value}.json"
        txt_path = base / f"{safe_value}.txt"
        payload = {"classification": {"kind": kind, "value": value}, "records": rows}
        write_json(json_path, payload)
        txt_path.write_text("\n".join(row["cidr"] for row in rows) + "\n", encoding="utf-8")
        inventory.append(
            {
                "kind": kind,
                "value": value,
                "json": str(json_path.relative_to(classified_dir.parent)),
                "txt": str(txt_path.relative_to(classified_dir.parent)),
                "records": len(rows),
            }
        )
    return inventory


def write_integrations(integrations_dir: Path, data: list[dict]) -> list[dict]:
    artifacts = [
        ("nginx", "geo.conf", write_nginx_geo),
        ("cloudflare", "ip-list.txt", write_plain_cidr_list),
        ("splunk", "cloud_egress_lookup.csv", write_splunk_lookup),
        ("elastic", "bulk.ndjson", write_elastic_bulk),
        ("clickhouse", "cloud_egress_ip_ranges.sql", write_clickhouse_sql),
    ]
    inventory = []
    for system, filename, writer in artifacts:
        directory = integrations_dir / system
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / filename
        writer(path, data)
        inventory.append(
            {
                "system": system,
                "path": str(path.relative_to(integrations_dir.parent)),
                "records": len(data),
            }
        )
    return inventory


def write_nginx_geo(path: Path, data: list[dict]) -> None:
    lines = [
        "# Generated by cloud-egress-ip-ranges.",
        "# Include inside http{} and use $cloud_egress_provider for policy decisions.",
        "geo $cloud_egress_provider {",
        '    default "";',
    ]
    for row in data:
        lines.append(f'    {row["cidr"]} "{row["provider"]}";')
    lines.append("}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_plain_cidr_list(path: Path, data: list[dict]) -> None:
    path.write_text("\n".join(row["cidr"] for row in data) + "\n", encoding="utf-8")


def write_splunk_lookup(path: Path, data: list[dict]) -> None:
    write_csv(path, data)


def write_elastic_bulk(path: Path, data: list[dict]) -> None:
    lines = []
    for row in data:
        doc_id = hashlib.sha256(f"{row['provider']}|{row['service_hint']}|{row['cidr']}".encode()).hexdigest()
        lines.append(json.dumps({"index": {"_index": "cloud-egress-ip-ranges", "_id": doc_id}}, sort_keys=True))
        lines.append(json.dumps(row, sort_keys=True))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_clickhouse_sql(path: Path, data: list[dict]) -> None:
    rows = []
    for row in flatten_for_tables(data):
        values = ", ".join(sql_literal(row[column]) for column in table_columns())
        rows.append(f"({values})")
    lines = [
        "CREATE TABLE IF NOT EXISTS cloud_egress_ip_ranges",
        "(",
        ",\n".join(f"    {column} String" for column in table_columns()),
        ") ENGINE = MergeTree ORDER BY (provider, service_hint, cidr);",
        "",
        "INSERT INTO cloud_egress_ip_ranges VALUES",
        ",\n".join(rows) + ";",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def sql_literal(value: object) -> str:
    if value is None:
        return "''"
    if isinstance(value, bool):
        return "'1'" if value else "'0'"
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def write_providers_yaml(path: Path, catalog: list[dict]) -> None:
    lines = [
        "# Public provider registry for cloud-egress-ip-ranges.",
        "# Source of truth for modeled provider tiers, collection method, and implementation status.",
        "providers:",
    ]
    for item in sorted(catalog, key=lambda row: (row["tier"], -row["priority"], row["provider"])):
        lines.extend(
            [
                f"  - id: {yaml_scalar(item['provider'])}",
                f"    name: {yaml_scalar(item['name'])}",
                f"    tier: {item['tier']}",
                f"    category: {yaml_scalar(item['category'])}",
                f"    priority: {item['priority']}",
                f"    collection_method: {yaml_scalar(item['collection_method'])}",
                f"    implementation_status: {yaml_scalar(item['implementation_status'])}",
                "    labels:",
            ]
        )
        labels = item.get("labels", [])
        if labels:
            for label in labels:
                lines.append(f"      - {yaml_scalar(label)}")
        else:
            lines.append("      []")
        if item.get("notes"):
            lines.append(f"    notes: {yaml_scalar(item['notes'])}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_egress_capabilities(path: Path, catalog: list[dict]) -> None:
    capabilities = []
    for item in catalog:
        labels = set(item.get("labels", []))
        capabilities.append(
            {
                "provider": item["provider"],
                "name": item["name"],
                "tier": item["tier"],
                "category": item["category"],
                "collection_method": item["collection_method"],
                "implementation_status": item["implementation_status"],
                "static_egress_supported": bool(labels & {"static_egress_supported", "managed_egress", "customer_specific"}),
                "dynamic_egress": bool(labels & {"dynamic_egress", "cloud", "cloud_vps", "hosting", "paas"}),
                "serverless_possible": any(label.endswith("possible") or "serverless" in label for label in labels),
                "edge_possible": bool(labels & {"edge", "cdn", "waf", "workers_possible"}),
                "customer_specific": "customer_specific" in labels or item["collection_method"].startswith("customer_specific"),
            }
        )
    write_json(path, {"providers": sorted(capabilities, key=lambda row: (row["tier"], row["provider"]))})


def write_latest_json(path: Path, data: list[dict], timestamp: str) -> None:
    provider_counts = Counter(row["provider"] for row in data)
    service_counts = Counter(row["service_hint"] for row in data)
    source_counts = Counter(row["source"] for row in data)
    write_json(
        path,
        {
            "schema_version": SCHEMA_VERSION,
            "generated_at": timestamp,
            "total_records": len(data),
            "providers": dict(sorted(provider_counts.items())),
            "services": dict(sorted(service_counts.items())),
            "sources": dict(sorted(source_counts.items())),
            "artifacts": {
                "json": ROOT_JSON,
                "jsonl": ROOT_JSONL,
                "csv": ROOT_CSV,
                "parquet": ROOT_PARQUET,
                "sqlite": ROOT_SQLITE,
                "duckdb": ROOT_DUCKDB,
            },
        },
    )


def build_diff(data: list[dict], previous_feed: Path | None) -> dict:
    current = {record_key(row): row for row in data}
    if not previous_feed or not previous_feed.exists():
        return {
            "base": None,
            "added": sorted(current),
            "removed": [],
            "added_count": len(current),
            "removed_count": 0,
        }
    previous_payload = json.loads(previous_feed.read_text(encoding="utf-8"))
    previous = {record_key(row): row for row in previous_payload.get("records", [])}
    added = sorted(set(current) - set(previous))
    removed = sorted(set(previous) - set(current))
    return {
        "base": str(previous_feed),
        "added": added,
        "removed": removed,
        "added_count": len(added),
        "removed_count": len(removed),
    }


def record_key(row: dict) -> str:
    return "|".join([row["provider"], row["platform_family"], row["service_hint"], row["cidr"]])


def yaml_scalar(value: object) -> str:
    text = str(value)
    if not text:
        return '""'
    safe = all(char.isalnum() or char in "._-/ " for char in text)
    return text if safe and not text.startswith(("-", "?", ":")) else json.dumps(text)


def build_manifest(
    output_dir: Path,
    data: list[dict],
    classified: list[dict],
    integrations: list[dict],
    timestamp: str,
) -> dict:
    providers = Counter(row["provider"] for row in data)
    sources = Counter(row["source"] for row in data)
    checksums = {
        ROOT_JSON: sha256_file(output_dir / ROOT_JSON),
        ROOT_CSV: sha256_file(output_dir / ROOT_CSV),
        ROOT_JSONL: sha256_file(output_dir / ROOT_JSONL),
        ROOT_PARQUET: sha256_file(output_dir / ROOT_PARQUET),
        ROOT_SQLITE: sha256_file(output_dir / ROOT_SQLITE),
        ROOT_DUCKDB: sha256_file(output_dir / ROOT_DUCKDB),
        SOURCES_MARKDOWN: sha256_file(output_dir / SOURCES_MARKDOWN),
        LATEST_JSON: sha256_file(output_dir / LATEST_JSON),
        PROVIDERS_YAML: sha256_file(output_dir / PROVIDERS_YAML),
        EGRESS_CAPABILITIES_JSON: sha256_file(output_dir / EGRESS_CAPABILITIES_JSON),
        f"diff/{LATEST_JSON}": sha256_file(output_dir / "diff" / LATEST_JSON),
        PROVIDER_CATALOG_JSON: sha256_file(output_dir / PROVIDER_CATALOG_JSON),
        PROVIDER_CATALOG_MARKDOWN: sha256_file(output_dir / PROVIDER_CATALOG_MARKDOWN),
    }
    for item in classified:
        checksums[item["json"]] = sha256_file(output_dir / item["json"])
        checksums[item["txt"]] = sha256_file(output_dir / item["txt"])
    for item in integrations:
        checksums[item["path"]] = sha256_file(output_dir / item["path"])
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": timestamp,
        "total_records": len(data),
        "provider_counts": dict(sorted(providers.items())),
        "source_counts": dict(sorted(sources.items())),
        "source_catalog": SOURCE_CATALOG,
        "provider_catalog_coverage": provider_catalog_coverage(data),
        "classified": classified,
        "integrations": integrations,
        "checksums": dict(sorted(checksums.items())),
    }


def write_sources_markdown(path: Path, data: list[dict], timestamp: str) -> None:
    provider_counts = Counter(row["provider"] for row in data)
    source_counts = Counter(row["source"] for row in data)
    lines = [
        "# cloud-egress-ip-ranges source inventory",
        "",
        f"Generated: `{timestamp}`",
        "",
        "| Provider | Feed | Source ID | Records | URL | Classification |",
        "|---|---|---:|---:|---|---|",
    ]
    for source in SOURCE_CATALOG:
        lines.append(
            "| {provider} | {feed} | `{source_id}` | {records} | {url} | {classification} |".format(
                provider=source["provider"],
                feed=source["feed"],
                source_id=source["source_id"],
                records=source_counts.get(source["source_id"], 0),
                url=source["url"],
                classification=source["classification"],
            )
        )
    lines.extend(
        [
            "",
            "## Provider totals",
            "",
            "| Provider | Records |",
            "|---|---:|",
        ]
    )
    for provider, count in sorted(provider_counts.items()):
        lines.append(f"| {provider} | {count} |")
    lines.extend(
        [
            "",
            "The inventory is generated from the same records as the JSON, CSV, and classified list artifacts.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def provider_catalog_coverage(data: list[dict]) -> dict:
    catalog = provider_catalog()
    ranged = {row["provider"] for row in data}
    statuses = Counter(item["implementation_status"] for item in catalog)
    return {
        "catalog_providers": len(catalog),
        "providers_with_cidr_records": len(ranged),
        "providers_without_cidr_records": len({item["provider"] for item in catalog} - ranged),
        "status_counts": dict(sorted(statuses.items())),
        "cidr_record_providers": sorted(ranged),
        "not_in_cidr_feed": sorted(item["provider"] for item in catalog if item["provider"] not in ranged),
    }


def write_provider_catalog_markdown(path: Path, catalog: list[dict], data: list[dict], timestamp: str) -> None:
    provider_counts = Counter(row["provider"] for row in data)
    lines = [
        "# cloud-egress-ip-ranges provider catalog",
        "",
        f"Generated: `{timestamp}`",
        "",
        "| Tier | Provider | Category | Method | Status | CIDR records | Priority |",
        "|---:|---|---|---|---|---:|---:|",
    ]
    for item in sorted(catalog, key=lambda row: (row["tier"], -row["priority"], row["provider"])):
        lines.append(
            "| {tier} | `{provider}` | {category} | {method} | {status} | {records} | {priority} |".format(
                tier=item["tier"],
                provider=item["provider"],
                category=item["category"],
                method=item["collection_method"],
                status=item["implementation_status"],
                records=provider_counts.get(item["provider"], 0),
                priority=item["priority"],
            )
        )
    coverage = provider_catalog_coverage(data)
    lines.extend(
        [
            "",
            "## Coverage summary",
            "",
            f"- Catalog providers: `{coverage['catalog_providers']}`",
            f"- Providers with CIDR records in this build: `{coverage['providers_with_cidr_records']}`",
            f"- Providers not in the CIDR feed yet: `{coverage['providers_without_cidr_records']}`",
            "",
            "Providers without CIDR records are retained in the catalog because they require docs scraping, ASN/BGP/RDAP enrichment, customer-specific data, or capability-only handling.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def slug(value: str) -> str:
    return "".join(char.lower() if char.isalnum() else "-" for char in value).strip("-")
