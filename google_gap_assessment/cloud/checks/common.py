"""Helpers shared by the check domains: run context, IAM vocabulary, timestamps."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable, Iterator, NamedTuple

from ..gcloud import Gcloud
from ...model import Options, ProjectResult, merge_results, run_project_check


@dataclass
class Context:
    """What a check needs: the gcloud gateway and the run's options."""
    gcloud: Gcloud
    options: Options = field(default_factory=Options)


@dataclass(frozen=True)
class Check:
    """One check: a finding id and the function that evaluates it for ONE project.

    ``run(ctx, project)`` returns ProjectResults for that id (usually one; a second NotAssessed result is added when part of
    the data could not be read). Everything else (merging projects, failure containment) is done by ``run_checks``.
    """
    id: str
    run: Callable[[Context, str], Iterable[ProjectResult]]


def registrar(registry: "list[Check]"):
    """Decorator factory: ``check = registrar(CHECKS)`` then ``@check("IAM-001")`` above a function registers it."""
    def check(check_id: str):
        def decorate(fn):
            registry.append(Check(check_id, fn))
            return fn
        return decorate
    return check


def run_checks(ctx: Context, projects: "list[str]", checks: "list[Check]", only: "Iterable[str] | None" = None) -> "list[dict]":
    """Run each check for every project and merge the results into one finding per check.

    Each check is isolated: if one cannot read its data it becomes NotAssessed on its own and its neighbours still run.
    ``only`` limits the run to those finding ids, which is how a single check is redone.
    """
    wanted = None if only is None else set(only)
    findings = []
    for chk in checks:
        if wanted is not None and chk.id not in wanted:
            continue
        results: "list[ProjectResult]" = []
        for project in projects:
            results += run_project_check(project, [chk.id], lambda p, chk=chk: chk.run(ctx, p))
        findings.append(merge_results(chk.id, results))
    return findings


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
