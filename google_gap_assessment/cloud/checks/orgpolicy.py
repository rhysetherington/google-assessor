"""Organization Policy (ORG-001..ORG-009): preventive guardrails that are effective for each project.

Reads the *effective* policy per project and constraint, so inherited policies count. Needs the Organization Policy
Viewer role; without it the checks are NotAssessed. A constraint with no policy at all is reported as not enforced.
"""

from __future__ import annotations

from ..gcloud import GcloudError
from ...model import ProjectResult, gap_or_pass, g
from .common import Check, Context, has_items, run_checks

# (finding id, constraint, how to evaluate it, why it matters)
CHECKS_TABLE = [
    ("ORG-001", "iam.disableServiceAccountKeyCreation", "boolean", "Stops user-managed service account keys being created."),
    ("ORG-002", "storage.publicAccessPrevention", "boolean", "Stops buckets and objects being made public."),
    ("ORG-003", "compute.requireOsLogin", "boolean", "Makes OS Login the only way to SSH into new VMs."),
    ("ORG-004", "compute.vmExternalIpAccess", "deny_all", "Stops VMs being given external IP addresses."),
    ("ORG-005", "iam.allowedPolicyMemberDomains", "allow_list", "Domain restricted sharing: IAM can only grant access to identities from approved domains."),
    ("ORG-006", "sql.restrictPublicIp", "boolean", "Stops Cloud SQL instances getting public IP addresses."),
    ("ORG-007", "compute.skipDefaultNetworkCreation", "boolean", "New projects are created without the permissive default network."),
    ("ORG-008", "compute.disableSerialPortAccess", "boolean", "Switches off the interactive serial console."),
    ("ORG-009", "iam.automaticIamGrantsForDefaultServiceAccounts", "boolean", "Stops default service accounts being granted Editor automatically."),
]


def policy_enforced(policy: "dict | None", kind: str) -> bool:
    """Reduce an effective policy to enforced / not enforced.

    Only unconditional rules count; a rule that applies only under a tag condition is not treated as enforcing.
    """
    if policy is None:
        return False
    rules = [r for r in ((policy.get("spec") or {}).get("rules") or []) if r and g(r, "condition") is None]
    if kind == "boolean":
        return any(r.get("enforce") is True for r in rules)
    if kind == "deny_all":
        return any(r.get("denyAll") is True for r in rules)
    if kind == "allow_list":
        return any(has_items((r.get("values") or {}).get("allowedValues")) for r in rules)
    raise ValueError(kind)


def policy_enforced_v1(policy: "dict | None", kind: str) -> bool:
    """Same question for the legacy ``resource-manager org-policies`` output, whose shape differs:
    {"booleanPolicy": {"enforced": true}} or {"listPolicy": {"allValues": "ALLOW" | "DENY", "allowedValues": [...]}}."""
    if not policy:
        return False
    if kind == "boolean":
        return (policy.get("booleanPolicy") or {}).get("enforced") is True
    lp = policy.get("listPolicy") or {}
    if kind == "deny_all":
        return lp.get("allValues") == "DENY"
    if kind == "allow_list":
        return lp.get("allValues") != "ALLOW" and has_items(lp.get("allowedValues"))
    raise ValueError(kind)


def _read_effective(ctx: Context, project: str, constraint: str, kind: str) -> bool:
    """True when the constraint is enforced. Raises GcloudError when it cannot be read.

    The v2 command needs the Organization Policy API enabled in the project, which a new project does not have. When
    that is the only problem, the legacy command reads the same effective policy through the Resource Manager API,
    which is always on, so the check still gets answered.
    """
    try:
        return policy_enforced(ctx.gcloud.get_one("org-policies describe", [constraint, "--effective"], project) or None, kind)
    except GcloudError as exc:
        if exc.category == "NotFound":  # no policy set is an answer: not enforced
            return False
        if exc.category != "ApiDisabled":
            raise
    try:
        return policy_enforced_v1(ctx.gcloud.get_one("resource-manager org-policies describe", [constraint, "--effective"], project), kind)
    except GcloudError as exc:
        if exc.category == "NotFound":
            return False
        raise


# One check per constraint, generated from the table above (each row is one finding; the evaluation is the same shape for all).
def _make_check(finding_id: str, constraint: str, kind: str, why: str) -> Check:
    def run(ctx: Context, project: str):
        try:
            enforced = _read_effective(ctx, project, constraint, kind)
        except GcloudError as exc:
            # Anything other than "no policy set" is "could not read": reported, never assumed enforced or not.
            return [ProjectResult(project, finding_id, "NotAssessed", [], str(exc))]
        return [gap_or_pass(project, finding_id, [] if enforced else [f"{project} - constraints/{constraint} is not enforced"], why)]
    run.__doc__ = f"constraints/{constraint} is enforced for the project. {why}"
    return Check(finding_id, run)


CHECKS: list = [_make_check(*row) for row in CHECKS_TABLE]


def collect(ctx: Context, projects: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, projects, CHECKS, only)
