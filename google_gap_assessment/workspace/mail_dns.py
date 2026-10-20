"""SPF, DKIM and DMARC lookups for the tenant's domains, over DNS-over-HTTPS (JSON API).

These records live in public DNS, not in the Workspace admin console, so they are read from there. **The tenant's domain names are
sent to the resolver** (Cloudflare by default; change it with --doh-endpoint, or skip DNS with --no-dns, in which case the email
authentication checks are reported as not assessed).
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from ..errors import ApiError

DEFAULT_ENDPOINT = "https://cloudflare-dns.com/dns-query"
GOOGLE_DKIM_SELECTOR = "google"


class DohResolver:
    """Minimal TXT resolver. The endpoint must be https; results are cached per run."""

    def __init__(self, endpoint: str = DEFAULT_ENDPOINT, opener: "Callable[..., Any] | None" = None, sleep: Callable[[float], None] = time.sleep):
        if urllib.parse.urlsplit(endpoint).scheme != "https":
            raise ValueError("The DNS-over-HTTPS endpoint must use https.")
        self._endpoint, self._open, self._sleep = endpoint, opener or urllib.request.urlopen, sleep
        self._cache: "dict[str, tuple[bool, Any]]" = {}

    def txt(self, name: str) -> "list[str]":
        """TXT records of a name (each record's strings joined), or [] when the name has none. Raises ApiError if the lookup failed."""
        key = name.lower()
        if key not in self._cache:
            try:
                self._cache[key] = (True, self._lookup(key))
            except Exception as exc:  # noqa: BLE001
                self._cache[key] = (False, exc)
        ok, value = self._cache[key]
        if not ok:
            raise value
        return value

    def _lookup(self, name: str) -> "list[str]":
        if not re.fullmatch(r"[a-z0-9._-]{1,253}", name):
            raise ValueError(f"Not a DNS name: {name!r}")
        url = f"{self._endpoint}?{urllib.parse.urlencode({'name': name, 'type': 'TXT'})}"
        request = urllib.request.Request(url, headers={"Accept": "application/dns-json"}, method="GET")
        for attempt in range(3):
            try:
                with self._open(request, timeout=20) as response:
                    data = json.loads(response.read().decode("utf-8"))
                break
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                if attempt == 2:
                    raise ApiError(f"DNS lookup of {name} failed: {exc}", "Transient") from exc
                self._sleep(1 + attempt)
        if data.get("Status") not in (0, 3):  # 0 = NOERROR, 3 = NXDOMAIN (no such name: not an error, just no records)
            raise ApiError(f"DNS lookup of {name} returned status {data.get('Status')}", "Other")
        records = []
        for answer in data.get("Answer") or []:
            if answer.get("type") == 16:  # TXT
                parts = re.findall(r'"((?:[^"\\]|\\.)*)"', str(answer.get("data", "")))
                records.append("".join(parts) if parts else str(answer.get("data", "")).strip('"'))
        return records


# --- interpreting the records ---------------------------------------------------------------------------------------------

def spf_records(records: "list[str]") -> "list[str]":
    return [r for r in records if re.match(r"(?i)\s*v=spf1(\s|$)", r)]


def spf_all_qualifier(record: str) -> "str | None":
    """'-', '~', '?' or '+' for the final 'all' mechanism, or None if there is none (or the record redirects instead)."""
    m = re.search(r"(?i)(?:^|\s)([+\-~?]?)all(?:\s|$)", record)
    return (m.group(1) or "+") if m else None


def dmarc_record(records: "list[str]") -> "dict[str, str] | None":
    """Tags of the DMARC record as a dict (p, sp, pct, rua, ...), or None. Several records make DMARC invalid, which callers handle."""
    found = [r for r in records if re.match(r"(?i)\s*v=DMARC1\s*;", r)]
    if len(found) != 1:
        return None
    tags = {}
    for part in found[0].split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def has_valid_dkim_key(records: "list[str]") -> bool:
    return any(re.match(r"(?i)\s*v=DKIM1", r) and re.search(r"(?i)\bp=[A-Za-z0-9+/=\s]{20,}", r) for r in records)
