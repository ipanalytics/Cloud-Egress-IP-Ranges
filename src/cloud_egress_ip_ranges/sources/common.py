from __future__ import annotations

import json
from pathlib import Path
from urllib.request import Request, urlopen

HTTP_HEADERS = {
    "User-Agent": "cloud-egress-ip-ranges/0.1 (+https://github.com/ipanalytics/cloud-egress-ip-ranges)",
    "Accept": "application/json,text/plain,*/*",
}


def build_request(url: str) -> Request:
    return Request(url, headers=HTTP_HEADERS)


def load_json(source: str | Path) -> dict:
    if str(source).startswith(("http://", "https://")):
        with urlopen(build_request(str(source)), timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    return json.loads(Path(source).read_text(encoding="utf-8"))


def load_text(source: str | Path) -> str:
    if str(source).startswith(("http://", "https://")):
        with urlopen(build_request(str(source)), timeout=30) as response:
            return response.read().decode("utf-8")
    return Path(source).read_text(encoding="utf-8")


def require(data: dict, field: str, source_name: str):
    if field not in data:
        raise ValueError(f"{source_name}: missing required field {field}")
    return data[field]
