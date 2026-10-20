"""Helpers shared by the check domains: run context, IAM vocabulary, timestamps."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable, Iterator, NamedTuple

from ..gcloud import Gcloud
from ...model import Options
from ...registry import Check, registrar, run_checks  # noqa: F401 - re-exported for the domain modules
from ...util import has_items, leaf, older_than, parse_time, unique  # noqa: F401 - re-exported for the domain modules


@dataclass
class Context:
    """What a check needs: the gcloud gateway and the run's options."""
    gcloud: Gcloud
    options: Options = field(default_factory=Options)


class Pair(NamedTuple):
    role: str
    member: str
    conditional: bool


def binding_pairs(policy: "dict | None") -> "Iterator[Pair]":
    """Flatten an IAM policy into (role, member) pairs.

    Deleted principals and the convenience members (projectOwner: and friends) only restate other grants, so skip them.
    """
    for b in (policy or {}).get("bindings") or []:
        for m in b.get("members") or []:
            if not m or m.startswith("deleted:") or re.match(r"project(Owner|Editor|Viewer):", m):
                continue
            yield Pair(str(b.get("role", "")), str(m), bool(b.get("condition")))


def is_public(member: str) -> bool:
    return member in ("allUsers", "allAuthenticatedUsers")


def service_account_kind(email: str) -> str:
    """DefaultCompute | DefaultAppEngine | GoogleManaged | UserManaged | Other, from a service account e-mail."""
    e = (email or "").lower()
    if re.fullmatch(r"\d+-compute@developer\.gserviceaccount\.com", e):
        return "DefaultCompute"
    if e.endswith("@appspot.gserviceaccount.com"):
        return "DefaultAppEngine"
    if (re.search(r"@(cloudservices|cloudbuild)\.gserviceaccount\.com$", e) or re.match(r"service-\d+@", e)
            or re.search(r"@gcp-sa-[^.]+\.iam\.gserviceaccount\.com$", e)
            or re.search(r"-(robot|system)\.iam\.gserviceaccount\.com$", e)):
        return "GoogleManaged"
    if re.search(r"@[a-z][a-z0-9-]*\.iam\.gserviceaccount\.com$", e):
        return "UserManaged"
    return "Other"


