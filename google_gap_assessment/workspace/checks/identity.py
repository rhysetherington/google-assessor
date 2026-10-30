"""Workspace identity and access (GID-xxx): 2-step verification, passwords, sessions, admin accounts, recovery, app access, data
regions and the other account-level controls. This is the largest area of the SCuBA "Common Controls" baseline.

Table rows (``RULES``) are single-setting questions; the functions below them need the directory, several settings, or special handling.
Everything is read-only: the Policy API for settings, the Directory API for users and admin roles, Cloud Identity for SSO assignments.
"""

from __future__ import annotations

from ...model import ProjectResult, gap_or_pass
from ...util import duration_seconds, older_than, parse_time
from ..context import WsContext
from .common import (PolicyRule, all_of, describe_fields, flag, is_in, not_in, policy_result, policy_result_many, registrar, run_checks)

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Workspace: Identity and access"   # the name the control mapping and reports use for this domain

ENROLL = "security.two_step_verification_enrollment"
ENFORCE = "security.two_step_verification_enforcement"
FACTOR = "security.two_step_verification_enforcement_factor"
GRACE = "security.two_step_verification_grace_period"
EPOCH = "1970-01-01T00:00:00"


def _active(users: "list[dict]") -> "list[dict]":
    return [u for u in users if not u.get("suspended") and not u.get("archived")]


def _enforced(view: dict, now) -> bool:
    """Enrolment is allowed and the enforcement date is a real date that has already passed."""
    when = parse_time((view[ENFORCE] or {}).get("enforcedFrom"))
    return bool((view[ENROLL] or {}).get("allowEnrollment")) and when is not None and when.year > 1970 and when <= now


# --- single-setting rules ---------------------------------------------------------------------------------------------------
RULES = [
    PolicyRule("GID-004", "security.two_step_verification_device_trust", flag("allowTrustingDevice", False), describe_fields("allowTrustingDevice"),
               "'Trust this device' lets a user skip 2-step verification on that device in future, which defeats the second factor.",
               "Users cannot mark a device as trusted to skip 2-step verification"),
    PolicyRule("GID-006", "security.session_controls", lambda s: None if duration_seconds(s.get("webSessionDuration")) is None else duration_seconds(s["webSessionDuration"]) <= 12 * 3600,
               describe_fields("webSessionDuration"),
               "Long-lived web sessions let a stolen session stay valid and let users skip 2SV on that device; 12 hours or less is the baseline.",
               "Web sessions last 12 hours or less"),
    PolicyRule("GID-007", "security.password", is_in("allowedStrength", "STRONG"), describe_fields("allowedStrength"),
               "Enforcing strong passwords makes the weakest passwords impossible to choose.", "Password strength requirement is Strong"),
    PolicyRule("GID-008", "security.password", lambda s: None if s.get("minimumLength") is None else int(s["minimumLength"]) >= 12, describe_fields("minimumLength"),
               "Length is the main factor in password strength (NIST SP 800-63B); at least 12 characters is the baseline.", "Minimum password length is at least 12"),
    PolicyRule("GID-009", "security.password", lambda s: None if s.get("minimumLength") is None else int(s["minimumLength"]) >= 16, describe_fields("minimumLength"),
               "Sixteen characters or more is the recommended length for accounts that rely on passwords.", "Minimum password length is 16 or more (recommended)"),
    PolicyRule("GID-010", "security.password", flag("enforceRequirementsAtLogin", True), describe_fields("enforceRequirementsAtLogin"),
               "Without enforcement at next sign-in, a user with an old weak password can keep using it indefinitely.", "Password requirements are enforced at the next sign-in"),
    PolicyRule("GID-011", "security.password", flag("allowReuse", False), describe_fields("allowReuse"),
               "Reused passwords widen the damage when one password is compromised.", "Users cannot reuse passwords"),
    PolicyRule("GID-012", "security.password", lambda s: None if duration_seconds(s.get("expirationDuration")) is None else duration_seconds(s["expirationDuration"]) == 0,
               describe_fields("expirationDuration"),
               "NIST and OMB advise against forced periodic password changes; they push users towards predictable passwords.", "Passwords do not expire on a schedule"),
    PolicyRule("GID-017", "provisioning.conflicting_accounts_management",
               lambda s: None if (s.get("option") or s.get("conflictingAccountsManagement")) is None else (s.get("option") or s.get("conflictingAccountsManagement")) == "REPLACE_CONFLICTING_ACCOUNT",
               lambda s: f"conflicting accounts handled by {s.get('option') or s.get('conflictingAccountsManagement')}",
               "Unmanaged accounts that conflict with managed ones cannot be controlled or monitored by administrators.",
               "Conflicting unmanaged accounts are replaced rather than preserved"),
    PolicyRule("GID-018", "security.super_admin_account_recovery", flag("enableAccountRecovery", False), describe_fields("enableAccountRecovery"),
               "Self-service recovery gives an attacker a route into a super admin account; recovery should go through another super admin.",
               "Super admins cannot recover their own accounts by self-service"),
    PolicyRule("GID-019", "security.user_account_recovery", flag("enableAccountRecovery", False), describe_fields("enableAccountRecovery"),
               "Self-service recovery lets users attach personal contact details and gives an attacker a route into the account.",
               "Users cannot recover their own accounts by self-service"),
    PolicyRule("GID-022", "api_controls.internal_apps", flag("trustInternalApps", False), describe_fields("trustInternalApps"),
               "Trusting internal apps lets code written by a compromised account reach Google data without review.", "Internal apps are not trusted automatically"),
    PolicyRule("GID-024", "security.less_secure_apps", flag("allowLessSecureApps", False), describe_fields("allowLessSecureApps"),
               "Less secure apps use passwords alone, bypassing modern authentication and 2-step verification.", "Less secure app access is not allowed"),
    PolicyRule("GID-029", "data_regions.data_processing_region", flag("limitToStorageRegion", True), describe_fields("limitToStorageRegion"),
               "Processing data in a region other than where it is stored undermines the data-residency choice.", "Data is processed only in its storage region"),
    PolicyRule("GID-030", "multi_party_approval.require_approvals", is_in("multiPartyApprovalState", "ENABLED"), describe_fields("multiPartyApprovalState"),
               "Without multi-party approval, one compromised super admin can switch off 2-step verification or other sensitive settings alone.",
               "Sensitive admin changes need approval from a second super admin"),
]
CHECKS.extend(r.as_check() for r in RULES)


# --- authentication (several settings together) -----------------------------------------------------------------------------

@check("GID-001")
def two_step_enforced(ctx: WsContext, tenant: str):
    """2-step verification is enforced: enrolment is allowed and the enforcement date has passed."""
    now = ctx.clock()
    return policy_result_many(ctx, tenant, "GID-001", [ENROLL, ENFORCE], lambda v: _enforced(v, now),
                              lambda v: f"enrolment allowed={v[ENROLL].get('allowEnrollment')}, enforced from {v[ENFORCE].get('enforcedFrom')}",
                              "Without enforced 2-step verification, a stolen password is enough to take over an account.")


@check("GID-002")
def phishing_resistant_second_factor(ctx: WsContext, tenant: str):
    """Only passkeys / security keys are accepted as the second factor (phishing-resistant MFA)."""
    now = ctx.clock()
    return policy_result_many(ctx, tenant, "GID-002", [ENROLL, ENFORCE, FACTOR],
                              lambda v: _enforced(v, now) and v[FACTOR].get("allowedSignInFactorSet") == "PASSKEY_ONLY",
                              lambda v: f"allowed second factors={v[FACTOR].get('allowedSignInFactorSet')}, enforced from {v[ENFORCE].get('enforcedFrom')}",
                              "SMS, voice and prompts can be phished; passkeys and security keys cannot. (Requires 2SV to be enforced first.)")


@check("GID-003")
def two_step_enrolment_grace_period(ctx: WsContext, tenant: str):
    """New users have at most one week to enrol in 2-step verification (and a grace period is set at all)."""
    now = ctx.clock()
    def ok(v):
        if not _enforced(v, now):
            return True  # not enforced is reported by GID-001; the grace period only matters once it is
        seconds = duration_seconds(v[GRACE].get("enrollmentGracePeriod"))
        return None if seconds is None else 0 < seconds <= 7 * 86400
    return policy_result_many(ctx, tenant, "GID-003", [ENROLL, ENFORCE, GRACE], ok,
                              lambda v: f"new-user enrolment period={v[GRACE].get('enrollmentGracePeriod')}",
                              "A short, finite enrolment window lets new staff set up their second factor without leaving accounts unprotected for long.")


# --- people: directory-based -----------------------------------------------------------------------------------------------

@check("GID-005")
def users_without_two_step(ctx: WsContext, tenant: str):
    """Active users who are not enrolled in 2-step verification."""
    hits = [f"{tenant}: {u['primaryEmail']} - not enrolled in 2-step verification" for u in _active(ctx.directory.users()) if not u.get("isEnrolledIn2Sv")]
    return [gap_or_pass(tenant, "GID-005", hits, "Each un-enrolled account is protected by a password alone.")]


@check("GID-015")
def admins_without_two_step(ctx: WsContext, tenant: str):
    """Active super admins and delegated admins who are not enrolled in 2-step verification."""
    admins = [u for u in _active(ctx.directory.users()) if u.get("isAdmin") or u.get("isDelegatedAdmin")]
    hits = [f"{tenant}: {u['primaryEmail']} - {'super admin' if u.get('isAdmin') else 'delegated admin'} without 2-step verification" for u in admins if not u.get("isEnrolledIn2Sv")]
    return [gap_or_pass(tenant, "GID-015", hits, "Administrator accounts without a second factor are the most valuable targets in the tenant.")]


@check("GID-013")
def super_admin_count(ctx: WsContext, tenant: str):
    """Between two and eight active super admin accounts."""
    admins = sorted(u["primaryEmail"] for u in _active(ctx.directory.users()) if u.get("isAdmin"))
    low, high = ctx.options.min_super_admins, ctx.options.max_super_admins
    hits: "list[str]" = []
    if len(admins) < low:
        hits.append(f"{tenant}: only {len(admins)} super admin account(s); at least {low} are needed so access is not lost")
    elif len(admins) > high:
        hits += [f"{tenant}: {a} - super admin (there are {len(admins)}; at most {high} recommended)" for a in admins]
    return [gap_or_pass(tenant, "GID-013", hits, f"Too few super admins risks losing admin access; too many widens the blast radius. Recommended: {low} to {high}.")]


@check("GID-016")
def stale_accounts(ctx: WsContext, tenant: str):
    """Active accounts that have not signed in for longer than --stale-days (default 90); never-used accounts are judged by age."""
    days = ctx.options.stale_days
    hits = []
    for u in _active(ctx.directory.users()):
        last = parse_time(u.get("lastLoginTime"))
        reference = u.get("creationTime") if (last is None or last.year <= 1970) else u.get("lastLoginTime")
        if older_than(reference, days):
            hits.append(f"{tenant}: {u['primaryEmail']} - {'never signed in' if (last is None or last.year <= 1970) else 'last sign-in ' + str(u.get('lastLoginTime'))[:10]}")
    return [gap_or_pass(tenant, "GID-016", hits, f"Dormant accounts are rarely watched and are a favourite way in; suspend or remove accounts unused for {days} days.")]


@check("GID-014")
def super_admins_use_google_sign_in(ctx: WsContext, tenant: str):
    """Super admins sign in with their Google account, not through an external identity provider."""
    admins = [u for u in _active(ctx.directory.users()) if u.get("isAdmin")]
    if not admins:
        return [ProjectResult(tenant, "GID-014", "NotAssessed", [], "No active super admin accounts were returned.")]
    ou_by_id = {str(o.get("orgUnitId", "")).removeprefix("id:"): str(o.get("orgUnitPath", "/")) for o in ctx.directory.orgunits()}
    assignments = ctx.directory.sso_assignments()

    def covers(path: str, admin_path: str) -> bool:
        return path == "/" or admin_path == path or admin_path.startswith(path.rstrip("/") + "/")

    ou_assignments = {ou_by_id.get(str(a.get("targetOrgUnit", "")).removeprefix("orgUnits/"), ""): a for a in assignments if a.get("targetOrgUnit")}
    group_assignments = [a for a in assignments if a.get("targetGroup") and a.get("ssoMode") not in (None, "SSO_OFF")]
    hits = []
    for u in admins:
        path = u.get("orgUnitPath") or "/"
        nearest = max((p for p in ou_assignments if p and covers(p, path)), key=len, default=None)  # the closest OU with its own setting wins
        mode = ou_assignments[nearest].get("ssoMode") if nearest else "SSO_OFF"
        if mode not in (None, "SSO_OFF"):
            hits.append(f"{tenant}: {u['primaryEmail']} - signs in via external SSO ({mode}) through OU {nearest}")
    out = [gap_or_pass(tenant, "GID-014", hits,
                       "If a super admin signs in through an external identity provider, compromising that provider (often on-premises) compromises the whole tenant.")]
    if group_assignments:
        out.append(ProjectResult(tenant, "GID-014", "NotAssessed", [],
                                 f"{len(group_assignments)} SSO assignment(s) target groups; group membership of super admins was not resolved, so check they are excluded."))
    return out


# --- app access and Marketplace ---------------------------------------------------------------------------------------------

# Services whose API access can be restricted, and the scope groups that restrict them (the API lists only restricted services).
SERVICE_SCOPE_GROUPS = {
    "Drive": {"DRIVE_ALL", "DRIVE_HIGH_RISK"}, "Gmail": {"GMAIL_ALL", "GMAIL_HIGH_RISK"}, "Calendar": {"CALENDAR_ALL"},
    "Contacts": {"CONTACTS_ALL"}, "Google Workspace Admin": {"GSUITE_ADMIN_ALL"}, "Vault": {"VAULT_ALL"}, "Cloud Platform": {"CLOUD_PLATFORM"},
    "Cloud Billing": {"CLOUD_BILLING"}, "Cloud Machine Learning": {"CLOUD_ML"}, "Apps Script API": {"APPS_SCRIPT_API"},
    "Apps Script Runtime": {"APPS_SCRIPT_RUNTIME"}, "Classroom": {"CLASSROOM_ALL", "CLASSROOM_HIGH_RISK"}, "Tasks": {"TASKS"}, "Groups": {"GROUPS"},
    "Chat": {"CHAT", "CHAT_HIGH_RISK"}, "Google Sign-in": {"SIGN_IN"}, "Meet": {"MEET"}, "Cloud Search": {"CLOUD_SEARCH"},
}
HIGH_RISK_GROUPS = {"DRIVE_HIGH_RISK", "GMAIL_HIGH_RISK", "CLASSROOM_HIGH_RISK", "CHAT_HIGH_RISK"}


def _restricted_groups(settings: dict) -> "set[str]":
    return {str(s.get("scopesGroup")) for s in settings.get("services") or [] if isinstance(s, dict)}


@check("GID-020")
def google_service_api_access_restricted(ctx: WsContext, tenant: str):
    """Third-party app access is restricted for every Google service that supports it (the API lists only restricted services)."""
    return policy_result(ctx, tenant, "GID-020", "api_controls.google_services",
                         lambda s: all(_restricted_groups(s) & groups for groups in SERVICE_SCOPE_GROUPS.values()),
                         lambda s: "unrestricted: " + ", ".join(name for name, groups in SERVICE_SCOPE_GROUPS.items() if not _restricted_groups(s) & groups),
                         "Unrestricted API access lets any app a user approves read their mail, files and calendar.")


@check("GID-021")
def high_risk_scopes_restricted(ctx: WsContext, tenant: str):
    """Drive, Gmail, Classroom and Chat are restricted for ALL scopes, not only the ones Google classes as high-risk."""
    return policy_result(ctx, tenant, "GID-021", "api_controls.google_services",
                         lambda s: not (_restricted_groups(s) & HIGH_RISK_GROUPS),
                         lambda s: "only high-risk scopes restricted for: " + ", ".join(sorted(g.split("_")[0].title() for g in _restricted_groups(s) & HIGH_RISK_GROUPS)),
                         "Restricting only 'high-risk' scopes still lets users approve apps for the rest of their Drive, Gmail, Classroom or Chat data.")


@check("GID-023")
def unconfigured_third_party_apps_blocked(ctx: WsContext, tenant: str):
    """Users cannot grant access to third-party apps the organisation has not reviewed."""
    return policy_result(ctx, tenant, "GID-023", "api_controls.unconfigured_third_party_apps",
                         lambda s: None if s.get("accessLevel") is None else s["accessLevel"] not in ("UNSPECIFIED_UBER_BLOCK", "ALLOW_SIGN_IN_SCOPES_ONLY"),
                         lambda s: f"unconfigured app access={s.get('accessLevel')}",
                         "Letting users approve any app is how malicious OAuth apps (consent phishing) get in.")


@check("GID-025")
def marketplace_apps_restricted(ctx: WsContext, tenant: str):
    """Marketplace apps are limited to an allowlist (or none), and internal apps are not allowed wholesale."""
    return policy_result(ctx, tenant, "GID-025", "workspace_marketplace.apps_access_options",
                         lambda s: None if s.get("accessLevel") is None else (s["accessLevel"] in ("ALLOW_LISTED_APPS", "ALLOW_NONE") and not s.get("allowAllInternalApps")),
                         describe_fields("accessLevel", "allowAllInternalApps"),
                         "Anyone could install a Marketplace app that reads company data unless installation is restricted to approved apps.")


# --- data export, alerts, residency, DLP --------------------------------------------------------------------------------------

TAKEOUT_APPS = ["blogger", "books", "location_history", "maps", "pay", "photos", "play", "play_console", "youtube"]


@check("GID-026")
def takeout_disabled(ctx: WsContext, tenant: str):
    """Google Takeout (bulk data export) is off for users, either as a whole or for every individual product."""
    ps = ctx.policies()
    if (ps.top("takeout.service_status") or {}).get("serviceState") == "DISABLED":
        return [gap_or_pass(tenant, "GID-026", [], "Takeout is a one-click bulk export of a user's data.")]
    enabled, unread = [], []
    for app in TAKEOUT_APPS:
        top = ps.top(f"{app}.user_takeout")
        if top is None:
            unread.append(app)
        elif top.get("takeoutStatus") != "DISABLED":
            enabled.append(f"{tenant}: / - Takeout for {app.replace('_', ' ')} is {top.get('takeoutStatus')}")
    out = [gap_or_pass(tenant, "GID-026", enabled, "Takeout is a one-click bulk export of a user's data, a ready-made exfiltration path.")]
    if unread and not enabled:
        out = [ProjectResult(tenant, "GID-026", "NotAssessed", [], f"Takeout status was not returned for: {', '.join(unread)}.")]
    return out


@check("GID-027")
def system_alerts_active(ctx: WsContext, tenant: str):
    """Every system-defined alert rule is active (so admins hear about suspicious logins, leaked passwords, and so on)."""
    rules = ctx.policies().top("rule.system_defined_alerts")
    if rules is None:
        return [ProjectResult(tenant, "GID-027", "NotAssessed", [], "Google returned no system-defined alert rules.")]
    off = [f"{tenant}: {r.get('displayName', '?')} - alert is {str(r.get('state', 'unknown')).lower()}" for r in rules if r.get("state") != "ACTIVE"]
    return [gap_or_pass(tenant, "GID-027", off, "A switched-off alert is an event nobody is told about. Some alerts are optional, so review each before enabling.")]


@check("GID-028")
def data_at_rest_region_pinned(ctx: WsContext, tenant: str):
    """Data at rest is pinned to a chosen region (US or Europe) rather than left to Google's global placement."""
    return policy_result(ctx, tenant, "GID-028", "data_regions.data_at_rest_region",
                         lambda s: None if s.get("region") is None else str(s["region"]).upper() in ("US", "EUROPE"),
                         describe_fields("region"),
                         "Pinning the data region keeps primary data where your regulatory and contractual obligations expect it.")


@check("GID-031")
def dlp_rules_active(ctx: WsContext, tenant: str):
    """At least one data-loss-prevention rule is active."""
    rules = ctx.policies().top("rule.dlp")
    if rules is None:
        return [gap_or_pass(tenant, "GID-031", [f"{tenant}: no data-protection rules are defined"],
                            "DLP rules detect and block sharing of sensitive data such as card numbers or national IDs.")]
    active = [r for r in rules if str(r.get("state", "")).upper() == "ACTIVE"]
    return [gap_or_pass(tenant, "GID-031", [] if active else [f"{tenant}: {len(rules)} data-protection rule(s) exist but none is active"],
                        "DLP rules detect and block sharing of sensitive data such as card numbers or national IDs.")]


def collect(ctx: WsContext, tenants: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, tenants, CHECKS, only)
