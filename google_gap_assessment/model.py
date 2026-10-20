"""Findings, per-project results, merging and scoring.

A check runs once per project and yields ProjectResults; ``merge_results`` turns the results of all projects
into the single finding the report shows. Status is Gap | Pass | NotAssessed | NotApplicable (the service is
not enabled, so nothing can exist) per project, and Gap | Pass | NotAssessed | Accepted per finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .errors import ApiError

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def _load_mapping() -> "dict[str, dict]":
    path = Path(__file__).parent / "data" / "control_mapping.json"
    return {c["id"]: c for c in json.loads(path.read_text(encoding="utf-8"))["controls"]}


CONTROL_MAPPING = _load_mapping()


@dataclass
class Options:
    """Settings that change how a check decides."""
    corporate_domains: "list[str]" = field(default_factory=list)
    key_max_age_days: int = 90
    kms_locations: "list[str]" = field(default_factory=lambda: ["global"])


@dataclass
class ProjectResult:
    project: str
    id: str
    status: str  # Gap | Pass | NotAssessed | NotApplicable
    affected: "list[str]" = field(default_factory=list)
    detail: str = ""


def new_finding(finding_id: str, status: str = "Gap", affected: "Iterable[str]" = (), detail: str = "") -> dict:
    """A finding dict enriched from the control mapping (severity, SCF, NIST CSF, CIS, remediation)."""
    mapping = CONTROL_MAPPING[finding_id]  # a KeyError here means a check was added without a mapping entry
    affected_list = [a for a in affected if a is not None]
    return {
        "FindingId": finding_id,
        "Name": mapping["name"],
        "Domain": mapping["domain"],
        "Source": mapping.get("source", "cloud"),
        "Severity": mapping["severity"],
        "Status": status,
        "AffectedCount": len(affected_list),
        "AffectedObjects": affected_list,
        "Detail": detail,
        "ScfControl": mapping["scf"],
        "NistCsf": mapping["nistCsf"],
        "CisControl": list(mapping.get("cis") or []),
        "Remediation": list(mapping["remediation"]),
    }


def gap_or_pass(project: str, finding_id: str, affected: "Iterable[str]" = (), detail: str = "") -> ProjectResult:
    """The common case: Gap when anything is affected, otherwise Pass."""
    items = [a for a in affected if a]
    return ProjectResult(project, finding_id, "Gap" if items else "Pass", items, detail)


def run_project_check(project: str, ids: "list[str]", fn: "Callable[[str], Iterable[ProjectResult]]") -> "list[ProjectResult]":
    """Run the checks for one project.

    Any failure (missing permission, API outage, unexpected field) becomes NotAssessed for the checks that
    did not finish, so one unreadable project never aborts the assessment and is never counted as a pass.
    A disabled API becomes NotApplicable: the service is not in use, so there is nothing to misconfigure.
    """
    try:
        # Fully collected before use, so results produced before a failure are discarded rather than half reported.
        results = list(fn(project))
    except Exception as exc:  # noqa: BLE001 - deliberately broad: see docstring
        category = exc.category if isinstance(exc, ApiError) else "Other"
        if category == "ApiDisabled":
            status, detail = "NotApplicable", "The API is not enabled in this project, so there is nothing to assess."
        else:
            hint = {
                "PermissionDenied": "The signed-in account lacks a permission this check needs (see the permissions in the README).",
                "Auth": "Sign-in expired or missing; run gcloud auth login.",
            }.get(category, "")
            status, detail = "NotAssessed", f"{exc} {hint}".strip()
        return [ProjectResult(project, i, status, [], detail) for i in ids]
    # A check that returned nothing is not a pass.
    for i in ids:
        if not any(r.id == i for r in results):
            results.append(ProjectResult(project, i, "NotAssessed", [], "The check produced no result."))
    return results


def merged_status(gap: int, not_assessed: int, passed: int, not_applicable: int) -> str:
    """Single status of a check that ran in several projects, from how many project results fell in each bucket."""
    # Rule 1: any Gap wins. A real problem in one project is reported even if other projects could not be read.
    if gap:
        return "Gap"
    # Rule 2: no Gap, but at least one project could not be read. The strict choice is NotAssessed, because the
    # unreadable project might hold the gap, and the score counts NotAssessed against you. To tolerate a few
    # unreadable projects, compare not_assessed with (passed + not_assessed) and return "Pass" below a threshold.
    if not_assessed:
        return "NotAssessed"
    # Rule 3: everything readable passed, or the service is not enabled anywhere (NotApplicable): nothing to misconfigure.
    return "Pass"


def merge_results(finding_id: str, results: "Iterable[ProjectResult]") -> dict:
    """One finding from all the project results of one check."""
    rs = list(results)
    if not rs:
        return new_finding(finding_id, "NotAssessed", detail="No project was assessed for this check.")
    gap = [r for r in rs if r.status == "Gap"]
    na = [r for r in rs if r.status == "NotAssessed"]
    ok = [r for r in rs if r.status == "Pass"]
    not_applicable = [r for r in rs if r.status == "NotApplicable"]
    status = merged_status(len(gap), len(na), len(ok), len(not_applicable))

    lines: "list[str]" = []
    for d in dict.fromkeys(r.detail for r in gap + ok if r.detail):  # unique, in order
        if len(lines) < 3:
            lines.append(d)
    if na:
        shown = "; ".join(f"{r.project} ({r.detail})" for r in na[:5]) + ("; ..." if len(na) > 5 else "")
        lines.append(f"Could not be assessed in {len(na)} project(s): {shown}")
    if not_applicable:
        lines.append("Not applicable (service not enabled) in: " + ", ".join(dict.fromkeys(r.project for r in not_applicable))[:300])
    affected = [a for r in gap for a in r.affected]
    return new_finding(finding_id, status, affected, " ".join(lines))


def measure_score(findings: "Iterable[dict]") -> "float | None":
    """0-100 compliance score. Each check counts once, weighted by severity; NotAssessed counts as a failure."""
    weights = {"Critical": 10, "High": 5, "Medium": 3, "Low": 1}
    scored = [f for f in findings if f["Severity"] in weights]
    if not scored:
        return None
    total = sum(weights[f["Severity"]] for f in scored)
    passed = sum(weights[f["Severity"]] for f in scored if f["Status"] in ("Pass", "Accepted"))
    return round(100 * passed / total + 1e-9, 1)


def g(obj: Any, *names: str) -> Any:
    """First non-None value among several spellings of a key (gcloud uses camelCase, ``gcloud storage`` snake_case).

    None means "gcloud did not return it", which callers treat as "could not read", never as "off".
    """
    if not isinstance(obj, dict):
        return None
    for n in names:
        if obj.get(n) is not None:
            return obj[n]
    return None
