# Operations

## Local Offline Build

Use checked-in fixtures for deterministic local validation:

```bash
uv run --python 3.12 python scripts/build.py --offline-fixtures
```

The offline build writes root artifacts to `dist/` and classified lists to `dist/classified/`.

## Daily GitHub Release

`.github/workflows/daily-release.yml` runs every day at `03:17 UTC` and can also be started with `workflow_dispatch`.

The workflow:

- checks out the repository;
- installs `uv`;
- runs compile, unittest, and lint checks;
- resolves the current Azure Service Tags JSON URL from Microsoft Download Center;
- builds live artifacts from AWS, Google, Azure, Oracle, Cloudflare, Fastly, GitHub, GitLab, Atlassian, and Stripe official feeds/docs;
- enriches curated VPS, hosting, regional cloud, CDN, edge, and scanner providers from RIPEstat ASN/BGP announced prefixes;
- publishes stable release assets on the `daily` tag;
- deploys the static GitHub Pages dashboard from `site/`.

Release assets use stable names:

- `cloud-egress-ip-ranges.json`
- `cloud-egress-ip-ranges.csv`
- `cloud-egress-ip-ranges.jsonl`
- `cloud-egress-ip-ranges.parquet`
- `cloud-egress-ip-ranges.sqlite`
- `cloud-egress-ip-ranges.duckdb`
- `manifest.json`
- `latest.json`
- `diff-latest.json`
- `sources.md`
- `providers.yaml`
- `egress-capabilities.json`
- `provider-catalog.json`
- `provider-catalog.md`
- `cloud-egress-ip-ranges-classified.tar.gz`
- `cloud-egress-ip-ranges-integrations.tar.gz`

## Choosing Classified Lists

Consumers that do not need the full feed can use `cloud-egress-ip-ranges-classified.tar.gz`.

Inside the archive, lists are grouped by:

- `classified/provider/<provider>.json` and `.txt`
- `classified/platform_family/<family>.json` and `.txt`
- `classified/service_hint/<service>.json` and `.txt`
- `classified/precision_level/<level>.json` and `.txt`
- `classified/recommended_action/<action>.json` and `.txt`

Use provider lists when you only care about a cloud, platform-family lists for cloud versus edge network, precision-level lists for attribution strength, and recommended-action lists for WAF or rate-limit policy inputs.

## Manual Live Build

For local live refresh, provide the current Azure Service Tags JSON URL:

```bash
uv run --python 3.12 python scripts/build.py --azure-service-tags-url "$AZURE_SERVICE_TAGS_URL"
```

No local GitHub CLI authentication is required for builds. GitHub release publishing uses the standard `GITHUB_TOKEN` available inside GitHub Actions with `contents: write` permission.
