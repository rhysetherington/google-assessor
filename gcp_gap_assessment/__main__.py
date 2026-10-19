"""Command line: ``python3 -m gcp_gap_assessment --project-id my-project``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .assess import CHECK_INDEX, DEFAULT_DOMAINS, DOMAINS, export_assessment, run_assessment
from .model import CONTROL_MAPPING
from .gcloud import Gcloud
from .model import Options
from .validation import is_numeric_id, is_project_id, is_service_account_email


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gcp_gap_assessment", description="Read-only Google Cloud security gap assessment using the gcloud CLI.")
    p.add_argument("--project-id", action="append", default=[], metavar="ID", help="project to assess (repeat for several; asked for when no scope is given)")
    p.add_argument("--folder-id", metavar="NUMBER", help="assess the active projects directly under this folder")
    p.add_argument("--organization-id", metavar="NUMBER", help="assess the active projects directly under this organisation")
    p.add_argument("--export-path", default="GcpAssessment", help="folder the reports are written under (default: ./GcpAssessment)")
    p.add_argument("--format", nargs="+", choices=["JSON", "Markdown", "HTML"], default=["JSON", "Markdown"], help="report formats (JSON is always written)")
    p.add_argument("--domain", nargs="+", choices=list(DOMAINS), default=DEFAULT_DOMAINS, help="check domains to run (Kms is opt-in)")
    p.add_argument("--check", nargs="+", metavar="ID", help="redo only these checks (e.g. IAM-003 CMP-005); the owning domains run automatically")
    p.add_argument("--list-checks", action="store_true", help="list every check id with its domain, severity and name, then exit")
    p.add_argument("--impersonate-service-account", metavar="EMAIL", help="make every call as this read-only service account")
    p.add_argument("--corporate-domain", action="append", default=[], metavar="DOMAIN", help="your e-mail domains; others are reported by IAM-007")
    p.add_argument("--key-max-age-days", type=int, default=90, help="age after which service account keys and API keys are stale (default 90)")
    p.add_argument("--kms-location", action="append", default=None, metavar="LOCATION", help="KMS locations to scan (default: global)")
    p.add_argument("--accepted-risk-path", metavar="FILE", help="JSON file of knowingly accepted risks")
    for flag, dest in (("--client-name", "client_name"), ("--assessment-name", "assessment_name"), ("--assessor-name", "assessor_name"),
                       ("--assessment-date", "assessment_date"), ("--reference", "reference"), ("--prepared-by", "prepared_by")):
        p.add_argument(flag, dest=dest, metavar="TEXT")
    p.add_argument("--brand-color", metavar="#RRGGBB", help="accent colour of the HTML report")
    p.add_argument("--no-prompt", action="store_true", help="do not ask for the assessment details; use the arguments and defaults")
    p.add_argument("--include-evidence", action="store_true", help="also write evidence/<FindingId>.csv with every affected item")
    p.add_argument("--allow-elevated-account", action="store_true", help="run as an account holding Owner/Editor without being asked")
    p.add_argument("--no-export", action="store_true", help="print the summary only; write no files")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: "list[str] | None" = None, gcloud: "Gcloud | None" = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_checks:  # needs no gcloud and no sign-in
        for cid in sorted(CHECK_INDEX):
            c = CONTROL_MAPPING[cid]
            print(f"{cid}  {CHECK_INDEX[cid]:<10} {c['severity']:<9} {c['name']}")
        return 0
    for pid in args.project_id:
        if not is_project_id(pid):
            sys.exit(f"error: '{pid}' is not a project ID.")
    for flag, value in (("--folder-id", args.folder_id), ("--organization-id", args.organization_id)):
        if value and not is_numeric_id(value):
            sys.exit(f"error: {flag} must be a number.")
    if args.impersonate_service_account and not is_service_account_email(args.impersonate_service_account):
        sys.exit("error: --impersonate-service-account must look like name@project-id.iam.gserviceaccount.com.")
    if args.brand_color and not (len(args.brand_color) == 7 and args.brand_color.startswith("#")):
        sys.exit("error: --brand-color must be #RRGGBB.")

    gcloud = gcloud or Gcloud(impersonate=args.impersonate_service_account)
    options = Options(args.corporate_domain, args.key_max_age_days, args.kms_location or ["global"])
    try:
        assessment = run_assessment(
            gcloud, args.project_id, args.folder_id, args.organization_id, args.domain, options, args.accepted_risk_path, args.check,
            args.client_name, args.assessment_name, args.assessor_name, args.assessment_date, args.reference, args.prepared_by,
            args.no_prompt, args.allow_elevated_account, progress=lambda m: print(f"... {m}", file=sys.stderr))
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
