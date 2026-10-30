"""Input validation. Anything that reaches a gcloud argument, a folder name or a report is checked first.

``re.fullmatch`` is used throughout: unlike ``$`` in a pattern it does not accept a trailing newline, and these
patterns are case-sensitive on purpose (project IDs are lower case).
"""

from __future__ import annotations

import re

_PROJECT = re.compile(r"([a-z][a-z0-9.-]{0,61}[a-z0-9]:)?[a-z][a-z0-9-]{4,28}[a-z0-9]")
_NUMERIC = re.compile(r"\d{3,20}")
_SERVICE_ACCOUNT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com")
_DOMAIN = re.compile(r"(?=.{4,253}\Z)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}")


def is_project_id(value: str) -> bool:
    """6-30 characters: lower-case letters, digits, hyphens (legacy "domain.com:name" form allowed)."""
    return bool(_PROJECT.fullmatch(value or ""))


def is_numeric_id(value: str) -> bool:
    """Organisation and folder IDs are numbers."""
    return bool(_NUMERIC.fullmatch(value or ""))


def is_service_account_email(value: str) -> bool:
    return bool(_SERVICE_ACCOUNT.fullmatch(value or ""))


def is_domain(value: str) -> bool:
    return bool(_DOMAIN.fullmatch(value or ""))


def safe_name(text: str, fallback: str = "Assessment") -> str:
    """Turn free text into a file/folder-safe token (letters, digits, dash) so user input can never add path separators."""
    clean = re.sub(r"[\W_]+", "-", text or "").strip("-")
    if len(clean) > 60:
        clean = clean[:60].strip("-")
    return clean or fallback
