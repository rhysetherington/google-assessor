"""Identity and IAM (IAM-001..IAM-011): primitive roles, public principals, service account privileges and keys, API keys.

One function per check, registered in ``CHECKS``. Reads each project's IAM policy, service accounts (and their user-managed
keys) and API keys. Only direct grants on the project are seen; roles inherited from a folder or the organisation need an
organisation-level read.
"""

from __future__ import annotations

from ...model import ProjectResult, gap_or_pass, g
from .common import (Context, Pair, binding_pairs, has_items, is_public, leaf, older_than, registrar, run_checks, service_account_kind)

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Identity and IAM"   # the name the control mapping and reports use for this domain

CONSUMER_DOMAINS = ("gmail.com", "googlemail.com")
PRIMITIVE_ROLES = ("roles/owner", "roles/editor")


def _pairs(ctx: Context, project: str) -> "list[Pair]":
    """Every (role, member) grant on the project. The policy is fetched once per run and shared by all the checks below."""
    return list(binding_pairs(ctx.gcloud.get_one("projects get-iam-policy", [project])))


def _label(project: str, p: Pair) -> str:
    return f"{project}/{p.member} - {p.role}"


def _member_kind(p: Pair) -> str:
    return p.member.split(":")[0]


def _sa_kind(p: Pair) -> str:
    return service_account_kind(p.member.split(":", 1)[1]) if p.member.startswith("serviceAccount:") else ""


# --- Policy checks: who holds which role on the project ---------------------------------------------------------------------

@check("IAM-001")
def primitive_roles_for_people(ctx: Context, project: str):
    """People (users, groups, domains) holding the broad legacy Owner / Editor roles. Service accounts are IAM-002 / IAM-008."""
    hits = [p for p in _pairs(ctx, project) if p.role in PRIMITIVE_ROLES and _member_kind(p) in ("user", "group", "domain")]
    return [gap_or_pass(project, "IAM-001", [_label(project, p) for p in hits],
                        "Owner and Editor are broad legacy roles; grant predefined or custom roles scoped to the job instead.")]


@check("IAM-002")
def service_accounts_with_admin_roles(ctx: Context, project: str):
    """User-managed service accounts holding Owner, Editor or any *admin role (default and Google-managed accounts excluded)."""
    hits = [p for p in _pairs(ctx, project) if _sa_kind(p) == "UserManaged" and (p.role in PRIMITIVE_ROLES or "admin" in p.role.lower())]
    return [gap_or_pass(project, "IAM-002", [_label(project, p) for p in hits], "User-managed service accounts holding Owner, Editor or an *admin role.")]


@check("IAM-003")
def public_principals(ctx: Context, project: str):
    """Roles granted to allUsers / allAuthenticatedUsers on the project."""
    hits = [p for p in _pairs(ctx, project) if is_public(p.member)]
    return [gap_or_pass(project, "IAM-003", [_label(project, p) for p in hits],
                        "Roles granted to allUsers or allAuthenticatedUsers make the resource reachable by anyone on the internet or any Google account.")]


@check("IAM-006")
def impersonation_roles_at_project_level(ctx: Context, project: str):
    """Users or groups holding Service Account User / Token Creator across the whole project."""
    hits = [p for p in _pairs(ctx, project) if p.role in ("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator")
            and _member_kind(p) in ("user", "group")]
    return [gap_or_pass(project, "IAM-006", [_label(project, p) for p in hits],
                        "Granted at project level these roles let the principal act as every service account in the project.")]


@check("IAM-007")
def non_corporate_accounts(ctx: Context, project: str):
    """People outside your domains. With --corporate-domain, anything else is flagged; without it only gmail.com / googlemail.com can be recognised."""
    corporate = [d.lower() for d in ctx.options.corporate_domains]
    hits = []
    for p in _pairs(ctx, project):
        if _member_kind(p) not in ("user", "group"):
            continue
        domain = p.member.rsplit("@", 1)[-1].lower()
        if (domain not in corporate) if corporate else (domain in CONSUMER_DOMAINS):
            hits.append(p)
    mode = (f"outside the corporate domain(s) {', '.join(corporate)}" if corporate
            else "on a consumer domain (gmail.com, googlemail.com); pass --corporate-domain to check against your own domains")
    return [gap_or_pass(project, "IAM-007", [_label(project, p) for p in hits], f"Principals with access {mode}.")]


@check("IAM-008")
def default_service_accounts_with_editor(ctx: Context, project: str):
    """The default Compute Engine / App Engine service accounts holding Owner or Editor."""
    hits = [p for p in _pairs(ctx, project) if p.role in PRIMITIVE_ROLES and _sa_kind(p) in ("DefaultCompute", "DefaultAppEngine")]
    return [gap_or_pass(project, "IAM-008", [_label(project, p) for p in hits],
                        "The default Compute Engine and App Engine service accounts are granted Editor automatically unless the organisation policy says otherwise.")]


@check("IAM-009")
def separation_of_duties(ctx: Context, project: str):
    """One principal that can both create service accounts (Admin) and act as them (User)."""
    pairs = _pairs(ctx, project)
    admins = {p.member for p in pairs if p.role == "roles/iam.serviceAccountAdmin" and not is_public(p.member)}
    users = {p.member for p in pairs if p.role == "roles/iam.serviceAccountUser"}
    return [gap_or_pass(project, "IAM-009", [f"{project}/{m} - Service Account Admin and Service Account User" for m in sorted(admins & users)],
                        "One principal can both create service accounts and act as them.")]


# --- Service account keys ---------------------------------------------------------------------------------------------------

def _user_managed_keys(ctx: Context, project: str) -> "tuple[list[tuple[str, dict]], list[str]]":
    """(account e-mail, key) for every user-managed key, and the accounts whose keys could not be listed. Cached per run."""
    keys, unreadable = [], []
    for sa in ctx.gcloud.get_list("iam service-accounts list", project=project):
        email = sa.get("email")
        if not email:
            continue
        try:
            for k in ctx.gcloud.get_list("iam service-accounts keys list", [f"--iam-account={email}", "--managed-by=user"], project):
                if g(k, "keyType") in (None, "USER_MANAGED"):
                    keys.append((email, k))
        except Exception:  # noqa: BLE001 - reported as NotAssessed by the callers, not hidden
            unreadable.append(email)
    return keys, unreadable


def _describe_key(project: str, item: "tuple[str, dict]") -> str:
    email, k = item
    return f"{project}/{email} - key {leaf(g(k, 'name'))} (created {str(g(k, 'validAfterTime') or '').split('T')[0]})"


def _with_unreadable(project: str, finding_id: str, results: list, unreadable: "list[str]") -> list:
    if unreadable:
        results.append(ProjectResult(project, finding_id, "NotAssessed", [],
                                     f"Keys of {len(unreadable)} service account(s) could not be listed: {', '.join(unreadable[:3])}"))
    return results


@check("IAM-004")
def user_managed_keys_exist(ctx: Context, project: str):
    """Any user-managed service account key at all."""
    keys, unreadable = _user_managed_keys(ctx, project)
    return _with_unreadable(project, "IAM-004", [gap_or_pass(
        project, "IAM-004", [_describe_key(project, i) for i in keys],
        "User-managed keys are long-lived credentials that can be copied; prefer attached service accounts, workload identity or short-lived tokens.")], unreadable)


@check("IAM-005")
def stale_user_managed_keys(ctx: Context, project: str):
    """User-managed keys older than --key-max-age-days (default 90)."""
    keys, unreadable = _user_managed_keys(ctx, project)
    days = ctx.options.key_max_age_days
    return _with_unreadable(project, "IAM-005", [gap_or_pass(
        project, "IAM-005", [_describe_key(project, i) for i in keys if older_than(g(i[1], "validAfterTime"), days)],
        f"User-managed keys older than {days} days.")], unreadable)


# --- API keys ---------------------------------------------------------------------------------------------------------------
# Key strings are never requested (that needs a different command), so no secret can reach a report.

def _api_key_name(project: str, k: dict) -> str:
    return f"{project}/{k.get('displayName') or leaf(k.get('name'))}"


@check("IAM-010")
def unrestricted_api_keys(ctx: Context, project: str):
    """API keys with neither an API target nor an application restriction."""
    def unrestricted(k: dict) -> bool:
        r = k.get("restrictions") or {}
        return not (has_items(r.get("apiTargets")) or r.get("browserKeyRestrictions") or r.get("serverKeyRestrictions")
                    or r.get("androidKeyRestrictions") or r.get("iosKeyRestrictions"))
    keys = ctx.gcloud.get_list("services api-keys list", project=project)
    return [gap_or_pass(project, "IAM-010", [_api_key_name(project, k) for k in keys if unrestricted(k)],
                        "API keys with neither an API target nor an application restriction work from anywhere for any enabled API.")]


@check("IAM-011")
def stale_api_keys(ctx: Context, project: str):
    """API keys older than --key-max-age-days (default 90)."""
    days = ctx.options.key_max_age_days
    keys = ctx.gcloud.get_list("services api-keys list", project=project)
    return [gap_or_pass(project, "IAM-011", [_api_key_name(project, k) for k in keys if older_than(k.get("createTime"), days)], f"API keys older than {days} days.")]


def collect(ctx: Context, projects: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, projects, CHECKS, only)
