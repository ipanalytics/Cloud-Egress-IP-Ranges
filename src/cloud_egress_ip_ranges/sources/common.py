from __future__ import annotations

import json
import re
import socket
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HTTP_HEADERS = {
    "User-Agent": "cloud-egress-ip-ranges/0.1 (+https://github.com/ipanalytics/cloud-egress-ip-ranges)",
    "Accept": "application/json,text/plain,*/*",
}
HTTP_TIMEOUT_SECONDS = 120
HTTP_RETRIES = 3
MARKDOWN_LINK_RE = re.compile(r"^\[(https?://[^\]]+)]\((https?://[^)]+)\)$")


def build_request(url: str) -> Request:
    return Request(normalize_url(url), headers=HTTP_HEADERS)


def normalize_url(url: str) -> str:
    value = url.strip().strip("'\"")
    match = MARKDOWN_LINK_RE.match(value)
    if match:
        value = match.group(2)
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1]
    return value


def read_url(url: str) -> str:
    last_error: Exception | None = None
    for attempt in range(HTTP_RETRIES):
        try:
            with urlopen(build_request(url), timeout=HTTP_TIMEOUT_SECONDS) as response:
                return response.read().decode("utf-8")
        except (HTTPError, URLError, TimeoutError, socket.timeout) as exc:
            last_error = exc
            if isinstance(exc, HTTPError) and 400 <= exc.code < 500 and exc.code != 429:
                break
            if attempt < HTTP_RETRIES - 1:
                time.sleep(2**attempt)
    raise RuntimeError(f"failed to fetch {normalize_url(url)} after {HTTP_RETRIES} attempts: {last_error}") from last_error


def load_json(source: str | Path) -> dict:
    if str(source).startswith(("http://", "https://")):
        return json.loads(read_url(str(source)))
    return json.loads(Path(source).read_text(encoding="utf-8"))


def load_text(source: str | Path) -> str:
    if str(source).startswith(("http://", "https://")):
        return read_url(str(source))
    return Path(source).read_text(encoding="utf-8")


def require(data: dict, field: str, source_name: str):
    if field not in data:
        raise ValueError(f"{source_name}: missing required field {field}")
    return data[field]
