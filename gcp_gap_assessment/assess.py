"""The assessment run: connect, resolve scope, guard, collect every domain, score, export."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, accepted, guard, metadata, report, scope
from .checks import audit_logging, compute, iam, kms, network, orgpolicy, sql, storage
from .checks.common import Context
from .gcloud import Gcloud, GcloudError
from .model import SEVERITY_ORDER, Options, measure_score
from .validation import is_project_id, is_service_account_email

# Domain name -> collector. Kms is opt-in because it needs extra calls per key ring and key.
DOMAINS = {"Iam": iam, "Logging": audit_logging, "Network": network, "Compute": compute,
           "Storage": storage, "Sql": sql, "OrgPolicy": orgpolicy, "Kms": kms}
DEFAULT_DOMAINS = ["Iam", "Logging", "Network", "Compute", "Storage", "Sql", "OrgPolicy"]

# Every registered check id -> the domain that owns it. This is what lets one check be redone on its own.
CHECK_INDEX = {chk.id: domain for domain, module in DOMAINS.items() for chk in module.CHECKS}


def resolve_checks(check_ids) -> "tuple[list[str], set[str]]":
    """Validate requested finding ids and return (the domains that own them, in the usual order; the id set)."""
    wanted = {c.upper() for c in check_ids}
    unknown = sorted(wanted - set(CHECK_INDEX))
    if unknown:
        raise ValueError(f"Unknown check id(s): {', '.join(unknown)}. Use --list-checks to see the valid ids.")
    return [d for d in DOMAINS if any(CHECK_INDEX[c] == d for c in wanted)], wanted


def connect(gcloud: Gcloud) -> dict:
    """Check gcloud is installed and signed in, and record who the assessment runs as."""
    if not gcloud.path:
        raise RuntimeError("The Google Cloud CLI (gcloud) was not found on PATH. Install it from "
                           "https://cloud.google.com/sdk/docs/install, then run: gcloud auth login")
    if gcloud.impersonate and not is_service_account_email(gcloud.impersonate):
        raise ValueError(f"'{gcloud.impersonate}' is not a service account e-mail address (name@project-id.iam.gserviceaccount.com).")
    try:  # the account lookup asks which credentials gcloud itself holds, so it is deliberately not impersonated
        active = gcloud.run("auth list", ["--filter=status:ACTIVE"], impersonate=False) or []
    except GcloudError as exc:
        raise RuntimeError(f"gcloud could not list accounts: {exc}") from exc
    account = (active[0] if active else {}).get("account")
    if not account:
        raise RuntimeError("gcloud has no active account. Run: gcloud auth login")
    try:  # the version is informational only; `gcloud version` is not a data read, so it bypasses the read-only gate on purpose
        import json
        code, out, _ = gcloud._runner([gcloud.path, "version", "--format=json"])  # noqa: SLF001
        version = json.loads(out).get("Google Cloud SDK") if code == 0 else None
    except Exception:  # noqa: BLE001
        version = None
    return {"Account": account, "Identity": gcloud.impersonate or account, "Impersonating": bool(gcloud.impersonate), "GcloudVersion": version}


def run_assessment(gcloud: Gcloud, project_ids=(), folder_id=None, organization_id=None, domains=None, options=None,
                   accepted_risk_path=None, check_ids=None, client_name=None, assessment_name=None, assessor_name=None, assessment_date=None,
                   reference=None, prepared_by=None, no_prompt=False, allow_elevated=False, progress=None) -> dict:
    """Run the whole assessment and return the assessment dict (nothing is written here)."""
    say = progress or (lambda _msg: None)
    options = options or Options()
    only = None
    if check_ids:  # redo specific checks: run just those, and only the domains that own them (Kms needs no --domain)
        domains, only = resolve_checks(check_ids)
    domains = domains or DEFAULT_DOMAINS
    for p in project_ids:
        if not is_project_id(p):
            raise ValueError(f"'{p}' is not a project ID.")

    say("Checking gcloud")
    context = connect(gcloud)
    if not (project_ids or folder_id or organization_id):
        project_ids = scope.prompt_for_projects()
    say("Resolving projects")
    projects = scope.resolve_scope(gcloud, list(project_ids), folder_id, organization_id)
    ids = [p["ProjectId"] for p in projects]

    guard.confirm_elevated_use(gcloud, context["Identity"], ids, allow=allow_elevated)

    org_domain = None
    if organization_id:
        try:
            org_domain = str(gcloud.get_one("organizations describe", [organization_id]).get("displayName") or "") or None
        except Exception:  # noqa: BLE001 - optional metadata only
            pass
    meta = metadata.resolve_metadata(client_name, assessment_name, assessor_name, prepared_by, assessment_date, reference,
                                     projects[0]["Name"], org_domain, context["Identity"], no_prompt)

    ctx = Context(gcloud, options)
    findings: "list[dict]" = []
    for domain in domains:
        say(f"Collecting: {domain}")
        findings += DOMAINS[domain].collect(ctx, ids, only)

    accepted.apply(findings, accepted.load(accepted_risk_path))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["Severity"]], f["FindingId"]))
    gaps = [f for f in findings if f["Status"] == "Gap"]
    count = lambda status: sum(1 for f in findings if f["Status"] == status)  # noqa: E731
    return {
        "Scope": {"OrganizationId": organization_id, "FolderId": folder_id, "Projects": projects},
        "Metadata": meta,
        "AssessedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "AssessedBy": context["Identity"], "SignedInAs": context["Account"], "GcloudVersion": context["GcloudVersion"],
        "ModuleVersion": __version__, "Domains": domains, "OnlyChecks": sorted(only) if only else None,
        "Score": measure_score(findings),
        "Summary": {"TotalChecks": len(findings), "Gaps": len(gaps), "Passed": count("Pass"), "NotAssessed": count("NotAssessed"),
                    "Accepted": count("Accepted"),
                    "GapsBySeverity": {s: sum(1 for f in gaps if f["Severity"] == s) for s in ("Critical", "High", "Medium", "Low")}},
        "Findings": findings, "ExportedFiles": [],
    }


def export_assessment(assessment: dict, export_path, formats=("JSON", "Markdown"), brand_color=None, include_evidence=False) -> "list[str]":
    """Write the reports into <export_path>/<ClientName>-<date>/ (a clock suffix is added if that folder already exists)."""
    folder = Path(export_path) / metadata.base_name(assessment)
    if folder.exists():
        folder = Path(export_path) / f"{metadata.base_name(assessment)}-{datetime.now().strftime('%H%M')}"
    files = report.export(assessment, folder, formats, brand_color, include_evidence)
    assessment["ExportedFiles"] = files
    return files
