"""The assessment run: connect to each target, collect every selected domain, score, export.

Two targets can be assessed in one run, together or alone:

* **Google Workspace** (the tenant: identity, email, Drive, ...), read through Google's Admin SDK and Cloud Identity APIs;
* **Google Cloud** (projects: IAM, networking, compute, ...), read through the gcloud CLI.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, accepted, metadata, report
from .cloud import guard, scope
from .cloud.checks import audit_logging, compute, iam, kms, network, orgpolicy, sql, storage
from .cloud.checks.common import Context
from .cloud.gcloud import Gcloud, GcloudError
from .model import SEVERITY_ORDER, Options, measure_score
from .validation import is_project_id, is_service_account_email
from .workspace.checks import identity
from .workspace.session import WsSession

# Domain name -> collector module. Kms is opt-in because it needs extra calls per key ring and key.
CLOUD_DOMAINS = {"Iam": iam, "Logging": audit_logging, "Network": network, "Compute": compute,
                 "Storage": storage, "Sql": sql, "OrgPolicy": orgpolicy, "Kms": kms}
WORKSPACE_DOMAINS = {"Identity": identity}
DOMAINS = {**WORKSPACE_DOMAINS, **CLOUD_DOMAINS}
DEFAULT_CLOUD_DOMAINS = ["Iam", "Logging", "Network", "Compute", "Storage", "Sql", "OrgPolicy"]
DEFAULT_WORKSPACE_DOMAINS = list(WORKSPACE_DOMAINS)
DEFAULT_DOMAINS = DEFAULT_CLOUD_DOMAINS  # kept for callers that only know about Google Cloud

# What a run may cover. "both" is Workspace plus Cloud.
SCOPES = ("workspace", "both", "cloud")

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
    """Check gcloud is installed and signed in, and record who the Google Cloud part of the assessment runs as."""
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
        code, out, _ = gcloud._runner([gcloud.path, "version", "--format=json"])  # noqa: SLF001
        version = json.loads(out).get("Google Cloud SDK") if code == 0 else None
    except Exception:  # noqa: BLE001
        version = None
    return {"Account": account, "Identity": gcloud.impersonate or account, "Impersonating": bool(gcloud.impersonate), "GcloudVersion": version}


def run_assessment(gcloud: "Gcloud | None" = None, project_ids=(), folder_id=None, organization_id=None, domains=None, options=None,
                   accepted_risk_path=None, check_ids=None, client_name=None, assessment_name=None, assessor_name=None, assessment_date=None,
                   reference=None, prepared_by=None, no_prompt=False, allow_elevated=False, progress=None,
                   workspace: "WsSession | None" = None) -> dict:
    """Run the assessment and return the assessment dict (nothing is written here).

    Pass ``gcloud`` to assess Google Cloud projects, ``workspace`` (a connected ``WsSession``) to assess a Workspace tenant, or both.
    """
    say = progress or (lambda _msg: None)
    options = options or Options()
    only = None
    if check_ids:  # redo specific checks: run just those, and only the domains that own them (Kms needs no --domain)
        domains, only = resolve_checks(check_ids)
    if domains is None:
        domains = (DEFAULT_WORKSPACE_DOMAINS if workspace else []) + (DEFAULT_CLOUD_DOMAINS if gcloud else [])
    cloud_domains = [d for d in domains if d in CLOUD_DOMAINS]
    ws_domains = [d for d in domains if d in WORKSPACE_DOMAINS]
    if cloud_domains and gcloud is None:
        raise ValueError(f"{', '.join(cloud_domains)} need Google Cloud access. Use --scope cloud or --scope both.")
    if ws_domains and workspace is None:
        raise ValueError(f"{', '.join(ws_domains)} need a Google Workspace connection. Use --scope workspace or --scope both.")
    if not (cloud_domains or ws_domains):
        raise ValueError("Nothing to assess: no check domain was selected.")
    for p in project_ids:
        if not is_project_id(p):
            raise ValueError(f"'{p}' is not a project ID.")

    findings: "list[dict]" = []
    identities: "list[str]" = []
    scope_info: dict = {"Targets": [], "OrganizationId": organization_id, "FolderId": folder_id, "Projects": [], "Workspace": None}
    meta_args = {"project_name": None, "primary_domain": None}
    context: dict = {"Account": None, "GcloudVersion": None}

    # --- Google Workspace ------------------------------------------------------------------------------------------------
    if ws_domains:
        scope_info["Targets"].append("workspace")
        scope_info["Workspace"] = {"CustomerId": workspace.customer_id, "PrimaryDomain": workspace.primary_domain, "Domains": workspace.domains}
        identities.append(workspace.account)
        meta_args["primary_domain"] = workspace.primary_domain
        ws_findings: "list[dict]" = []
        for domain in ws_domains:
            say(f"Collecting Workspace: {domain}")
            ws_findings += WORKSPACE_DOMAINS[domain].collect(workspace.ctx, [workspace.primary_domain], only)
        findings += ws_findings

    # --- Google Cloud ----------------------------------------------------------------------------------------------------
    if cloud_domains:
        scope_info["Targets"].append("cloud")
        say("Checking gcloud")
        context = connect(gcloud)
        if not (project_ids or folder_id or organization_id):
            project_ids = scope.prompt_for_projects()
        say("Resolving projects")
        projects = scope.resolve_scope(gcloud, list(project_ids), folder_id, organization_id)
        ids = [p["ProjectId"] for p in projects]
        scope_info["Projects"] = projects
        identities.append(context["Identity"])
        guard.confirm_elevated_use(gcloud, context["Identity"], ids, allow=allow_elevated)
        meta_args["project_name"] = projects[0]["Name"]
        if organization_id and not meta_args["primary_domain"]:
            try:
                meta_args["primary_domain"] = str(gcloud.get_one("organizations describe", [organization_id]).get("displayName") or "") or None
            except Exception:  # noqa: BLE001 - optional metadata only
                pass
        ctx = Context(gcloud, options)
        for domain in cloud_domains:
            say(f"Collecting Cloud: {domain}")
            findings += CLOUD_DOMAINS[domain].collect(ctx, ids, only)

    identities = [i for i in dict.fromkeys(identities) if i]
    meta = metadata.resolve_metadata(client_name, assessment_name, assessor_name, prepared_by, assessment_date, reference,
                                     meta_args["project_name"], meta_args["primary_domain"], identities[0] if identities else None, no_prompt)

    accepted.apply(findings, accepted.load(accepted_risk_path))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["Severity"]], f["FindingId"]))
    gaps = [f for f in findings if f["Status"] == "Gap"]
    count = lambda status: sum(1 for f in findings if f["Status"] == status)  # noqa: E731
    return {
        "Scope": scope_info,
        "Metadata": meta,
        "AssessedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "AssessedBy": " / ".join(identities), "SignedInAs": context.get("Account") or (identities[0] if identities else None),
        "GcloudVersion": context.get("GcloudVersion"),
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
