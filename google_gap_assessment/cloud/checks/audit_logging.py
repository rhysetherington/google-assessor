"""Logging (LOG-001..LOG-003): Cloud Audit Logs, a sink exporting all logs, locked retention on the export bucket.

One function per check. Reads the project's own audit configuration and sinks. Settings and aggregated sinks defined on a folder
or the organisation are not visible from a project, so a gap here can be covered higher up; accept the risk when it is.
"""

from __future__ import annotations

from ...model import ProjectResult, gap_or_pass, g
from .common import Context, has_items, registrar, run_checks

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Logging and monitoring"   # the name the control mapping and reports use for this domain


def bucket_retention(bucket: dict) -> "tuple[bool, bool | None]":
    """(has a retention policy, locked?). Locked is None when gcloud did not say."""
    policy = g(bucket, "retention_policy", "retentionPolicy")
    flag = g(bucket, "retention_policy_is_locked", "retentionPolicyIsLocked")
    if flag is not None:
        locked = bool(flag)
    elif policy:
        locked = g(policy, "isLocked", "is_locked")
    else:
        locked = None
    return bool(policy), locked


@check("LOG-001")
def audit_logs_fully_enabled(ctx: Context, project: str):
    """Admin Read, Data Read and Data Write enabled for allServices, with no exempted principals."""
    policy = ctx.gcloud.get_one("projects get-iam-policy", [project])
    configs = policy.get("auditConfigs") or []
    problems: "list[str]" = []
    all_services = [c for c in configs if c.get("service") == "allServices"]
    for log_type in ("ADMIN_READ", "DATA_READ", "DATA_WRITE"):
        if not any(lc.get("logType") == log_type for c in all_services for lc in c.get("auditLogConfigs") or []):
            problems.append(f"{project} - {log_type} is not enabled for allServices")
    # Exempted principals silently switch logging off for them.
    for c in configs:
        for lc in c.get("auditLogConfigs") or []:
            if has_items(lc.get("exemptedMembers")):
                problems.append(f"{project} - {c.get('service')} {lc.get('logType')} exempts {len(lc['exemptedMembers'])} principal(s)")
    return [gap_or_pass(project, "LOG-001", problems,
                        "Admin Read, Data Read and Data Write audit logs should be enabled for all services with no exempted principals. "
                        "Settings inherited from the folder or organisation are not visible here.")]


@check("LOG-002")
def sink_exports_all_logs(ctx: Context, project: str):
    """At least one enabled sink with no filter (so it exports every log entry)."""
    sinks = ctx.gcloud.get_list("logging sinks list", project=project)
    all_logs = [s for s in sinks if not s.get("disabled") and not str(s.get("filter") or "").strip()]
    return [gap_or_pass(project, "LOG-002", [] if all_logs else [f"{project} - no enabled sink exports all log entries ({len(sinks)} sink(s) found)"],
                        "A sink with no filter keeps a copy of every log entry outside the project. An aggregated sink on the folder "
                        "or organisation also satisfies this but is not visible from the project.")]


@check("LOG-003")
def export_bucket_retention_locked(ctx: Context, project: str):
    """Every enabled sink that exports to Cloud Storage writes to a bucket whose retention policy is locked."""
    gcs = [s for s in ctx.gcloud.get_list("logging sinks list", project=project)
           if not s.get("disabled") and str(s.get("destination", "")).startswith("storage.googleapis.com/")]
    if not gcs:
        return [ProjectResult(project, "LOG-003", "NotApplicable", [], "No sink exports to Cloud Storage.")]
    try:
        buckets = ctx.gcloud.get_list("storage buckets list", project=project)
    except Exception:  # noqa: BLE001 - fall back to describing each bucket
        buckets = []
    unlocked: "list[str]" = []
    unreadable: "list[str]" = []
    for sink in gcs:
        name = str(sink["destination"]).removeprefix("storage.googleapis.com/").split("/")[0]
        bucket = next((b for b in buckets if g(b, "name") == name), None)
        if bucket is None:
            try:
                bucket = ctx.gcloud.get_one("storage buckets describe", [f"gs://{name}"], project)
            except Exception:  # noqa: BLE001
                unreadable.append(name)
                continue
        has_policy, locked = bucket_retention(bucket)
        if locked is None and not has_policy:
            unlocked.append(f"{project}/sink {sink.get('name')} -> bucket {name} has no retention policy")
        elif locked is not True:
            unlocked.append(f"{project}/sink {sink.get('name')} -> bucket {name} retention policy is not locked")
    out = [gap_or_pass(project, "LOG-003", unlocked,
                       "A locked retention policy stops anyone, including an attacker with admin rights, from deleting exported logs early.")]
    if unreadable:
        out.append(ProjectResult(project, "LOG-003", "NotAssessed", [], f"Could not read bucket(s): {', '.join(unreadable[:3])}"))
    return out


def collect(ctx: Context, projects: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, projects, CHECKS, only)
