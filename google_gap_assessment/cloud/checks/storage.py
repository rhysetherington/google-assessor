"""Cloud Storage (STO-001, STO-002): publicly readable buckets and buckets that still use object ACLs. One function per check.

Object-level ACLs are not read: uniform bucket-level access (STO-002) is what turns them off.
A setting gcloud does not return is NotAssessed, never assumed to be on or off.
"""

from __future__ import annotations

from ...model import ProjectResult, gap_or_pass, g
from .common import Context, binding_pairs, is_public, registrar, run_checks

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Cloud Storage"   # the name the control mapping and reports use for this domain


def _buckets(ctx: Context, project: str) -> "list[dict]":
    """Named buckets of the project. Fetched once per run and shared by both checks."""
    return [b for b in ctx.gcloud.get_list("storage buckets list", project=project) if g(b, "name")]


def _uniform_access(bucket: dict):
    """True / False, or None when gcloud did not return the setting."""
    uniform = g(bucket, "uniform_bucket_level_access", "uniformBucketLevelAccess")
    return uniform.get("enabled") if isinstance(uniform, dict) else uniform  # the REST spelling nests it: {"enabled": true}


@check("STO-001")
def buckets_publicly_accessible(ctx: Context, project: str):
    """allUsers / allAuthenticatedUsers in a bucket's IAM policy. Buckets with public access prevention enforced are skipped."""
    buckets = _buckets(ctx, project)
    public, unreadable = [], []
    for b in buckets:
        name = g(b, "name")
        # Public access prevention makes public grants ineffective, so the policy read can be skipped.
        if g(b, "public_access_prevention", "publicAccessPrevention") == "enforced":
            continue
        try:
            policy = ctx.gcloud.get_one("storage buckets get-iam-policy", [f"gs://{name}"], project)
            public += [f"{project}/{name} - {p.member} has {p.role}" for p in binding_pairs(policy) if is_public(p.member)]
        except Exception:  # noqa: BLE001 - reported below as NotAssessed
            unreadable.append(name)
    out = [gap_or_pass(project, "STO-001", public,
                       f"Checked {len(buckets)} bucket(s) for allUsers / allAuthenticatedUsers grants; buckets with public access prevention enforced are skipped.")]
    if unreadable:
        out.append(ProjectResult(project, "STO-001", "NotAssessed", [], f"IAM policy of {len(unreadable)} bucket(s) could not be read: {', '.join(unreadable[:3])}"))
    return out


@check("STO-002")
def uniform_bucket_level_access(ctx: Context, project: str):
    """Uniform bucket-level access on for every bucket."""
    off, unknown = [], []
    for b in _buckets(ctx, project):
        uniform = _uniform_access(b)
        if uniform is None:
            unknown.append(g(b, "name"))
        elif not uniform:
            off.append(f"{project}/{g(b, 'name')}")
    out = [gap_or_pass(project, "STO-002", off, "With uniform bucket-level access off, object ACLs can grant access that IAM policies do not show.")]
    if unknown:
        out.append(ProjectResult(project, "STO-002", "NotAssessed", [],
                                 f"gcloud did not return the uniform bucket-level access setting for {len(unknown)} bucket(s): {', '.join(unknown[:3])}"))
    return out


def collect(ctx: Context, projects: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, projects, CHECKS, only)
