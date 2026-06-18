#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cloud_egress_ip_ranges.builder import build_from_fixtures, build_from_live_sources, write_artifacts
from cloud_egress_ip_ranges.models import EgressRangeRecord


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build cloud egress IP range artifacts.")
    parser.add_argument(
        "--offline-fixtures",
        action="store_true",
        help="Use checked-in fixtures instead of live provider feeds.",
    )
    parser.add_argument("--output-dir", default="dist", help="Directory for generated artifacts.")
    parser.add_argument("--azure-service-tags-url", default="", help="Azure Service Tags JSON URL for live builds.")
    parser.add_argument("--previous-feed", default="", help="Previous root JSON feed for diff generation.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    previous_feed = Path(args.previous_feed) if args.previous_feed else None
    try:
        records = (
            build_from_fixtures()
            if args.offline_fixtures
            else build_from_live_sources(azure_service_tags_url=args.azure_service_tags_url)
        )
    except Exception as exc:
        if args.offline_fixtures or not previous_feed or not previous_feed.exists():
            print(f"build failed: {exc}")
            return 1
        print(f"warning: live build failed, reusing previous feed {previous_feed}: {exc}")
        records = load_previous_records(previous_feed)

    try:
        manifest = write_artifacts(records, Path(args.output_dir), offline=args.offline_fixtures, previous_feed=previous_feed)
    except Exception as exc:
        print(f"build failed: {exc}")
        return 1
    print(
        "wrote {total} records to {out} ({classified} classified files)".format(
            total=manifest["total_records"],
            out=args.output_dir,
            classified=len(manifest["classified"]),
        )
    )
    return 0


def load_previous_records(path: Path) -> list[EgressRangeRecord]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    records = payload.get("records", [])
    if not records:
        raise ValueError(f"previous feed has no records: {path}")
    return [EgressRangeRecord.from_dict(record) for record in records]


if __name__ == "__main__":
    raise SystemExit(main())
