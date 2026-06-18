# Sources

The project uses official feeds as the default trust boundary.

## AWS

- Feed: `https://ip-ranges.amazonaws.com/ip-ranges.json`
- Source ID: `aws_ip_ranges_json`
- Useful fields: `ip_prefix`, `ipv6_prefix`, `region`, `service`, `network_border_group`

AWS ranges can show that traffic is from AWS address space or a published AWS service range. Public data does not prove exact Lambda origin for generic `AMAZON` or `EC2` ranges.

## Google

- Google-owned ranges: `https://www.gstatic.com/ipranges/goog.json`
- Google Cloud customer ranges: `https://www.gstatic.com/ipranges/cloud.json`
- Source IDs: `google_goog_json`, `google_cloud_json`
- Useful fields: `ipv4Prefix`, `ipv6Prefix`, `scope`

`cloud.json` is treated as customer Google Cloud resource space. Cloud Run or Cloud Functions can use configured VPC/NAT egress, so public ranges are classified as possible rather than exact.

## Azure

- Feed: Azure IP Ranges and Service Tags, Public Cloud JSON from Microsoft Download Center
- Source ID: `azure_service_tags_public_json`
- Useful fields: service tag `name`, `properties.region`, `properties.addressPrefixes`

Azure Service Tags identify Azure service and regional ranges. Exact Azure Functions attribution still requires app-owner data such as a specific Function App outbound IP list.

## Oracle Cloud

- Feed: `https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json`
- Source ID: `oracle_public_ip_ranges_json`
- Useful fields: `regions[].region`, `regions[].cidrs[].cidr`, `regions[].cidrs[].tags`

Oracle ranges are official OCI regional public IP ranges. Service tags are retained as hints, but exact workload attribution still requires customer or service-specific data.

## Cloudflare

- IPv4 list: `https://www.cloudflare.com/ips-v4`
- IPv6 list: `https://www.cloudflare.com/ips-v6`
- Source IDs: `cloudflare_ips_v4`, `cloudflare_ips_v6`

Cloudflare ranges are official edge network ranges. Workers, CDN, proxy, WAF, and other edge products can use the network, so the feed marks edge/serverless as possible without claiming a specific product origin.

## Fastly

- Feed: `https://api.fastly.com/public-ip-list`
- Source ID: `fastly_public_ip_list`
- Useful fields: `addresses`, `ipv6_addresses`

Fastly ranges are official edge/CDN ranges. Compute@Edge is treated as possible from these ranges, not exact.

## GitHub

- Feed: `https://api.github.com/meta`
- Source ID: `github_meta_api`
- Useful fields: `actions`, `hooks`, `pages`, `api`, `git`, `web`

GitHub publishes platform ranges for Actions, webhooks, Pages, API, Git, and web traffic. These are emitted with service hints matching the Meta API groups.

## GitLab

- Feed: `https://docs.gitlab.com/user/gitlab_com/`
- Source ID: `gitlab_com_docs`
- Useful fields: documented GitLab.com CIDRs for Web/API and webhooks.

GitLab.com ranges are parsed from official documentation. They identify GitLab.com source ranges, not arbitrary self-managed GitLab installations.

## Atlassian

- Feed: `https://ip-ranges.atlassian.com/`
- Source ID: `atlassian_ip_ranges_json`
- Useful fields: `items[].cidr`, `items[].direction`, `items[].product`, `items[].region`

Atlassian Cloud ranges are filtered to records where `direction` includes `egress`. Product labels are retained as service hints for Bitbucket, Jira, Confluence, Rovo crawler, and related Atlassian services.

## Stripe

- Webhook feed: `https://stripe.com/files/ips/ips_webhooks.json`
- API feed: `https://stripe.com/files/ips/ips_api.json`
- Source IDs: `stripe_webhook_ips_json`, `stripe_api_ips_json`
- Useful fields: `WEBHOOKS`, `API`

Stripe publishes single IP addresses rather than CIDR blocks. The builder normalizes IPv4 addresses to `/32` records so downstream consumers can treat all outputs as CIDRs.

## ASN/BGP

- Feed: `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<asn>`
- Source ID: `ripe_stat_announced_prefixes`
- Source type: `asn_bgp`
- Precision level: `L5`

ASN/BGP records are generated from RIPEstat announced prefixes for curated providers in `src/cloud_egress_ip_ranges/sources/asn_bgp.py`. This currently covers high-priority VPS, hosting, regional cloud, CDN, edge, and scanner networks such as Hetzner, OVHcloud, DigitalOcean, Linode, Vultr, Scaleway, IONOS, UpCloud, Leaseweb, Akamai, Bunny.net, Gcore, CDN77, Imperva, Sucuri, Censys, and Shodan.

These records prove that the prefix is announced by the mapped provider ASN. They do not prove exact product-level egress and are therefore kept separate from official feed/docs records.

## Cataloged Providers Without CIDR Records

`provider-catalog.json` and `provider-catalog.md` retain the wider tier model: serverless/PaaS, edge/CDN, CI/CD, regional cloud, VPS/hosting, managed egress, SaaS webhooks, monitoring, and scanner sources.

Providers without a defensible CIDR feed are cataloged with a collection method such as `docs_scrape`, `customer_specific_capability`, or `capability_only`. The generated range feed does not emit placeholder CIDRs for them.
