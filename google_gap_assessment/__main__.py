"""Command line: ``python3 -m google_gap_assessment`` (asks what to assess) or, for example, ``--scope workspace``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .assess import (CHECK_INDEX, CLOUD_DOMAINS, DEFAULT_CLOUD_DOMAINS, DEFAULT_WORKSPACE_DOMAINS, DOMAINS, SCOPES, WORKSPACE_DOMAINS,
                     export_assessment, resolve_checks, run_assessment)
from .cloud.gcloud import Gcloud
from .model import CONTROL_MAPPING, Options
from .validation import is_numeric_id, is_project_id, is_service_account_email
from .workspace import auth
from .workspace.context import WsOptions
from .workspace.mail_dns import DEFAULT_ENDPOINT
from .workspace.session import connect_workspace

MENU = """What would you like to assess?
  1) Google Workspace only                 (identity, email, Drive, Meet, Chat, and so on)
  2) Google Workspace and Google Cloud     (the above, plus Google Cloud projects: IAM, networking, compute, storage, ...)
  3) Google Cloud only                     (projects and infrastructure)
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="google_gap_assessment", description="Read-only Google Workspace and Google Cloud security gap assessment.")
    p.add_argument("--scope", choices=SCOPES, help="what to assess: workspace, both (Workspace and Google Cloud) or cloud. Asked for when omitted.")
    p.add_argument("--setup-help", action="store_true", help="print the one-time Google Workspace sign-in setup and exit")
    g = p.add_argument_group("Google Workspace")
    g.add_argument("--quota-project", metavar="PROJECT", help="Google Cloud project (with the Admin SDK and Cloud Identity APIs enabled) that the API calls are quota'd to")
    g.add_argument("--no-dns", action="store_true", help="do not look up SPF/DKIM/DMARC records (your domain names are sent to a DNS-over-HTTPS resolver otherwise)")
    g.add_argument("--doh-endpoint", default=DEFAULT_ENDPOINT, metavar="URL", help="DNS-over-HTTPS resolver for the email authentication checks")
    g.add_argument("--stale-days", type=int, default=90, help="days without sign-in after which an active account counts as stale (default 90)")
    c = p.add_argument_group("Google Cloud")
    c.add_argument("--project-id", action="append", default=[], metavar="ID", help="project to assess (repeat for several; asked for when no scope is given)")
    c.add_argument("--folder-id", metavar="NUMBER", help="assess the active projects directly under this folder")
    c.add_argument("--organization-id", metavar="NUMBER", help="assess the active projects directly under this organisation")
    c.add_argument("--impersonate-service-account", metavar="EMAIL", help="make every gcloud call as this read-only service account")
    c.add_argument("--corporate-domain", action="append", default=[], metavar="DOMAIN", help="your e-mail domains; others are reported by IAM-007")
    c.add_argument("--key-max-age-days", type=int, default=90, help="age after which service account keys and API keys are stale (default 90)")
    c.add_argument("--kms-location", action="append", default=None, metavar="LOCATION", help="KMS locations to scan (default: global)")
    c.add_argument("--allow-elevated-account", action="store_true", help="run as a Google Cloud account holding Owner/Editor without being asked")
    r = p.add_argument_group("Report")
    r.add_argument("--export-path", default="GoogleAssessment", help="folder the reports are written under (default: ./GoogleAssessment)")
    r.add_argument("--format", nargs="+", choices=["JSON", "Markdown", "HTML"], default=["JSON", "Markdown"], help="report formats (JSON is always written)")
    r.add_argument("--domain", nargs="+", choices=list(DOMAINS), help="check domains to run (default: all for the chosen scope; Kms is opt-in)")
    r.add_argument("--check", nargs="+", metavar="ID", help="redo only these checks (e.g. GML-028 IAM-003); the owning domains run automatically")
    r.add_argument("--list-checks", action="store_true", help="list every check id with its domain, severity and name, then exit")
    r.add_argument("--accepted-risk-path", metavar="FILE", help="JSON file of knowingly accepted risks")
    for flag, dest in (("--client-name", "client_name"), ("--assessment-name", "assessment_name"), ("--assessor-name", "assessor_name"),
                       ("--assessment-date", "assessment_date"), ("--reference", "reference"), ("--prepared-by", "prepared_by")):
        r.add_argument(flag, dest=dest, metavar="TEXT")
    r.add_argument("--brand-color", metavar="#RRGGBB", help="accent colour of the HTML report")
    r.add_argument("--no-prompt", action="store_true", help="do not ask for the assessment details; use the arguments and defaults")
    r.add_argument("--include-evidence", action="store_true", help="also write evidence/<FindingId>.csv with every affected item")
    r.add_argument("--no-export", action="store_true", help="print the summary only; write no files")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def choose_scope(args, interactive: bool, ask=input) -> str:
    """workspace | both | cloud: from --scope, else from the checks or domains requested, else from which options were given, else ask."""
    if args.scope:
        return args.scope
    wanted = None
    if args.check:
        wanted, _ = resolve_checks(args.check)
    elif args.domain:
        wanted = args.domain
    if wanted:
        ws, cloud = any(d in WORKSPACE_DOMAINS for d in wanted), any(d in CLOUD_DOMAINS for d in wanted)
        return "both" if ws and cloud else ("workspace" if ws else "cloud")
    cloud_given = bool(args.project_id or args.folder_id or args.organization_id or args.impersonate_service_account)
    ws_given = bool(args.quota_project or args.no_dns)
    if cloud_given or ws_given:
        return "both" if cloud_given and ws_given else ("cloud" if cloud_given else "workspace")
    if not interactive:
        raise RuntimeError("Say what to assess with --scope workspace, --scope both or --scope cloud (the session is not interactive, so it cannot ask).")
    print(MENU)
    while True:
        answer = ask("Choose 1, 2 or 3: ").strip()
        if answer in ("1", "2", "3"):
            return {"1": "workspace", "2": "both", "3": "cloud"}[answer]
        print("Please type 1, 2 or 3.")


def main(argv: "list[str] | None" = None, gcloud: "Gcloud | None" = None, workspace=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.setup_help:
        print(auth.setup_instructions(quota_project=args.quota_project or "YOUR_PROJECT_ID"))
        return 0
    if args.list_checks:  # needs no gcloud and no sign-in
        for cid in sorted(CHECK_INDEX):
            c = CONTROL_MAPPING[cid]
            print(f"{cid}  {CHECK_INDEX[cid]:<10} {c['severity']:<9} {c['name']}")
        return 0
    for pid in args.project_id:
        if not is_project_id(pid):
            parser.error(f"'{pid}' is not a project ID.")
    for flag, value in (("--folder-id", args.folder_id), ("--organization-id", args.organization_id)):
        if value and not is_numeric_id(value):
            parser.error(f"{flag} must be a number.")
    if args.impersonate_service_account and not is_service_account_email(args.impersonate_service_account):
        parser.error("--impersonate-service-account must look like name@project-id.iam.gserviceaccount.com.")
    if args.brand_color and not (len(args.brand_color) == 7 and args.brand_color.startswith("#")):
        parser.error("--brand-color must be #RRGGBB.")

    try:
        scope = choose_scope(args, sys.stdin.isatty() and not args.no_prompt)
        # Which domains run, and therefore which targets must be connected.
        if args.check:
            domains, _ = resolve_checks(args.check)
        elif args.domain:
            domains = args.domain
        else:
            domains = (DEFAULT_WORKSPACE_DOMAINS if scope in ("workspace", "both") else []) + (DEFAULT_CLOUD_DOMAINS if scope in ("cloud", "both") else [])
        needs_ws = any(d in WORKSPACE_DOMAINS for d in domains)
        needs_cloud = any(d in CLOUD_DOMAINS for d in domains)
        if (needs_ws and scope == "cloud") or (needs_cloud and scope == "workspace"):
            raise ValueError(f"The requested checks need a different scope than --scope {scope}. Use --scope both.")

        session = workspace
        if needs_ws and session is None:
            print("... Connecting to Google Workspace", file=sys.stderr)
            session = connect_workspace(quota_project=args.quota_project, doh_endpoint=args.doh_endpoint, check_dns=not args.no_dns,
                                        options=WsOptions(check_dns=not args.no_dns, stale_days=args.stale_days))
        cloud = (gcloud or Gcloud(impersonate=args.impersonate_service_account)) if needs_cloud else None
        options = Options(args.corporate_domain, args.key_max_age_days, args.kms_location or ["global"])
        assessment = run_assessment(
            cloud, args.project_id, args.folder_id, args.organization_id, domains, options, args.accepted_risk_path, args.check,
            args.client_name, args.assessment_name, args.assessor_name, args.assessment_date, args.reference, args.prepared_by,
            args.no_prompt, args.allow_elevated_account, progress=lambda m: print(f"... {m}", file=sys.stderr), workspace=session if needs_ws else None)
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    s = assessment["Summary"]
    print(f"Score {assessment['Score']}%  |  {s['TotalChecks']} checks: {s['Passed']} passed, {s['Gaps']} gaps, "
          f"{s['NotAssessed']} not assessed, {s['Accepted']} accepted")
    if not args.no_export:
        for f in export_assessment(assessment, Path(args.export_path), args.format, args.brand_color, args.include_evidence):
            print(f"  wrote {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
