from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cloud_egress_ip_ranges.confidence import PrecisionLevel, profile_for
from cloud_egress_ip_ranges.models import EgressRangeRecord, today_utc
from cloud_egress_ip_ranges.sources.common import load_json

RIPESTAT_ANNOUNCED_PREFIXES_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"


@dataclass(frozen=True)
class AsnProviderSpec:
    provider: str
    name: str
    asns: tuple[int, ...]
    platform_family: str
    service_hint: str
    edge_possible: bool = False
    serverless_possible: bool = False


ASN_PROVIDER_SPECS: tuple[AsnProviderSpec, ...] = (
    AsnProviderSpec("akamai", "Akamai", (20940, 16625), "edge_network", "akamai_asn", True),
    AsnProviderSpec("alibaba_cloud", "Alibaba Cloud", (45102, 37963), "cloud", "alibaba_cloud_asn"),
    AsnProviderSpec("aruba_cloud", "Aruba Cloud", (31034,), "hosting_vps", "aruba_cloud_asn"),
    AsnProviderSpec("arvancloud", "ArvanCloud", (202468,), "edge_network", "arvancloud_asn", True),
    AsnProviderSpec("baidu_ai_cloud", "Baidu AI Cloud", (38365,), "cloud", "baidu_ai_cloud_asn"),
    AsnProviderSpec("bunny_net", "Bunny.net", (200325,), "edge_network", "bunny_net_asn", True),
    AsnProviderSpec("cachefly", "CacheFly", (30081,), "edge_network", "cachefly_asn", True),
    AsnProviderSpec("cdn77", "CDN77", (60068,), "edge_network", "cdn77_asn", True),
    AsnProviderSpec("censys", "Censys", (398705,), "internet_scanner", "censys_asn"),
    AsnProviderSpec("clouvider", "Clouvider", (62240,), "hosting_vps", "clouvider_asn"),
    AsnProviderSpec("contabo", "Contabo", (51167,), "hosting_vps", "contabo_asn"),
    AsnProviderSpec("digitalocean", "DigitalOcean", (14061,), "cloud_vps", "digitalocean_asn", False, True),
    AsnProviderSpec("edgio", "Edgio", (15133,), "edge_network", "edgio_asn", True),
    AsnProviderSpec("equinix_metal", "Equinix Metal", (54825,), "bare_metal_datacenter", "equinix_metal_asn"),
    AsnProviderSpec("exoscale", "Exoscale", (61098,), "cloud_vps", "exoscale_asn"),
    AsnProviderSpec("gcore", "Gcore", (199524,), "edge_network", "gcore_asn", True),
    AsnProviderSpec("godaddy", "GoDaddy Hosting", (26496,), "hosting_vps", "godaddy_asn"),
    AsnProviderSpec("hetzner", "Hetzner", (24940,), "cloud_vps", "hetzner_asn"),
    AsnProviderSpec("hivelocity", "Hivelocity", (29802,), "hosting_vps", "hivelocity_asn"),
    AsnProviderSpec("host_europe", "Host Europe", (20773,), "hosting_vps", "host_europe_asn"),
    AsnProviderSpec("hostdime", "HostDime", (33182,), "hosting_vps", "hostdime_asn"),
    AsnProviderSpec("hostinger", "Hostinger", (47583,), "hosting_vps", "hostinger_asn"),
    AsnProviderSpec("huawei_cloud", "Huawei Cloud", (136907,), "cloud", "huawei_cloud_asn"),
    AsnProviderSpec("ibm_cloud", "IBM Cloud", (36351, 13884), "cloud", "ibm_cloud_asn"),
    AsnProviderSpec("imperva", "Imperva", (19551,), "edge_network", "imperva_asn", True),
    AsnProviderSpec("infomaniak", "Infomaniak", (29222,), "cloud", "infomaniak_asn"),
    AsnProviderSpec("ionos", "IONOS", (8560,), "cloud_vps", "ionos_asn"),
    AsnProviderSpec("keycdn", "KeyCDN", (57363,), "edge_network", "keycdn_asn", True),
    AsnProviderSpec("leaseweb", "Leaseweb", (60781, 16265), "hosting_vps", "leaseweb_asn"),
    AsnProviderSpec("linode", "Akamai Connected Cloud / Linode", (63949,), "cloud_vps", "linode_asn"),
    AsnProviderSpec("liquid_web", "Liquid Web", (32244,), "hosting_vps", "liquid_web_asn"),
    AsnProviderSpec("m247", "M247", (9009,), "hosting_vps", "m247_asn"),
    AsnProviderSpec("namecheap", "Namecheap", (22612,), "hosting_vps", "namecheap_asn"),
    AsnProviderSpec("naver_cloud", "Naver Cloud", (23576,), "cloud", "naver_cloud_asn"),
    AsnProviderSpec("netcup", "netcup", (197540,), "hosting_vps", "netcup_asn"),
    AsnProviderSpec("nforce", "NForce", (43350,), "hosting_vps", "nforce_asn"),
    AsnProviderSpec("ovhcloud", "OVHcloud", (16276,), "cloud_vps", "ovhcloud_asn"),
    AsnProviderSpec("phoenixnap", "PhoenixNAP", (29791,), "hosting_vps", "phoenixnap_asn"),
    AsnProviderSpec("rackspace", "Rackspace", (19994,), "hosting_vps", "rackspace_asn"),
    AsnProviderSpec("sakura_cloud", "Sakura Cloud", (9370, 7684), "cloud", "sakura_cloud_asn"),
    AsnProviderSpec("scaleway", "Scaleway", (12876,), "cloud_vps", "scaleway_asn"),
    AsnProviderSpec("seeweb", "Seeweb", (12637,), "hosting_vps", "seeweb_asn"),
    AsnProviderSpec("selectel", "Selectel", (49505,), "cloud_vps", "selectel_asn"),
    AsnProviderSpec("serverius", "Serverius", (50673,), "hosting_vps", "serverius_asn"),
    AsnProviderSpec("shodan", "Shodan", (398324,), "internet_scanner", "shodan_asn"),
    AsnProviderSpec("strato", "Strato", (6724,), "hosting_vps", "strato_asn"),
    AsnProviderSpec("sucuri", "Sucuri", (30148,), "edge_network", "sucuri_asn", True),
    AsnProviderSpec("tencent_cloud", "Tencent Cloud", (132203, 45090), "cloud", "tencent_cloud_asn"),
    AsnProviderSpec("timeweb_cloud", "Timeweb Cloud", (9123,), "cloud_vps", "timeweb_cloud_asn"),
    AsnProviderSpec("transip", "TransIP", (20857,), "hosting_vps", "transip_asn"),
    AsnProviderSpec("upcloud", "UpCloud", (202053,), "cloud_vps", "upcloud_asn"),
    AsnProviderSpec("vultr", "Vultr", (20473,), "cloud_vps", "vultr_asn"),
    AsnProviderSpec("voxility", "Voxility", (3223,), "hosting_vps", "voxility_asn"),
    AsnProviderSpec("worldstream", "Worldstream", (49981,), "hosting_vps", "worldstream_asn"),
)


def fetch_ripe_stat_asn_records(specs: tuple[AsnProviderSpec, ...] = ASN_PROVIDER_SPECS) -> list[EgressRangeRecord]:
    records: list[EgressRangeRecord] = []
    for spec in specs:
        for asn in spec.asns:
            records.extend(parse_ripe_stat_announced_prefixes(RIPESTAT_ANNOUNCED_PREFIXES_URL.format(asn=asn), spec, asn))
    return records


def parse_ripe_stat_announced_prefixes(source: str | Path, spec: AsnProviderSpec, asn: int) -> list[EgressRangeRecord]:
    data = load_json(source)
    prefixes = data.get("data", {}).get("prefixes", [])
    if not prefixes:
        raise ValueError(f"ripe_stat_announced_prefixes: no prefixes for AS{asn}")
    return [_record(item["prefix"], spec, asn) for item in prefixes if item.get("prefix")]


def _record(cidr: str, spec: AsnProviderSpec, asn: int) -> EgressRangeRecord:
    profile = profile_for(
        PrecisionLevel.L5_WEAK_INFERENCE,
        provider=spec.provider,
        service_hint=spec.service_hint,
        serverless_possible=spec.serverless_possible,
        edge_possible=spec.edge_possible,
    )
    return EgressRangeRecord(
        cidr=cidr,
        provider=spec.provider,
        platform_family=spec.platform_family,
        service_hint=spec.service_hint,
        serverless_possible=spec.serverless_possible,
        serverless_exact=False,
        edge_possible=spec.edge_possible,
        region="global",
        country_hint=None,
        source="ripe_stat_announced_prefixes",
        source_type="asn_bgp",
        confidence=profile.confidence,
        recommended_action=profile.recommended_action,
        false_positive_risk=profile.false_positive_risk,
        last_seen=today_utc(),
        last_updated=today_utc(),
        precision_level=f"L{profile.precision_level.value}",
        network_border_group=f"AS{asn}",
        notes=[f"RIPEstat announced prefixes for AS{asn}; ASN/BGP inference, not service-exact attribution."],
    )
