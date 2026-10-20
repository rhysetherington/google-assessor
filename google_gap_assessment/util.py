"""Small helpers shared by the Google Cloud and Google Workspace checks."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable


def leaf(name: "str | None") -> str:
    """Last path segment of a resource URL or name (".../zones/europe-west2-a" -> "europe-west2-a")."""
    return str(name).rsplit("/", 1)[-1] if name else ""


def parse_time(value: "str | None") -> "datetime | None":
    """Parse a gcloud timestamp ("2024-01-01T00:00:00Z", possibly with nanoseconds) as UTC, or None."""
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)  # fromisoformat accepts at most microseconds
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def older_than(value: "str | None", days: int) -> bool:
    parsed = parse_time(value)
    if parsed is None:
        return False
    return (datetime.now(timezone.utc) - parsed).days >= days


def has_items(value: object) -> bool:
    return bool(value) and any(v is not None for v in (value if isinstance(value, (list, tuple)) else [value]))


def unique(items: Iterable[str]) -> "list[str]":
    return list(dict.fromkeys(items))


def duration_seconds(text: "str | None") -> "float | None":
    """Seconds in a Google duration such as "604800s", "12h" or "7d", or None if it is not one."""
    m = re.fullmatch(r"(?i)\s*(\d+(?:\.\d+)?)\s*([smhd])\s*", str(text or ""))
    return float(m[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m[2].lower()] if m else None
