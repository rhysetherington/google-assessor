"""Workspace identity and access (GID-001..GID-031) against the fake tenant. Each case starts from a tenant that meets every check and
breaks one thing, so a failing case names the rule that regressed. An unreadable setting is NotAssessed, never a pass."""

import unittest

from google_gap_assessment.workspace.checks import identity as MODULE
from google_gap_assessment.workspace.context import WsOptions
from tests_python.workspace.helpers import healthy_passes, run_cases
from tests_python.workspace.ws_fakes import CI, DENIED, Tenant

ENROLL, ENFORCE = "security.two_step_verification_enrollment", "security.two_step_verification_enforcement"
FACTOR, GRACE = "security.two_step_verification_enforcement_factor", "security.two_step_verification_grace_period"
PW = "security.password"


def setting(name, **fields):
    def mutate(t: Tenant):
        t.settings[name] = {**t.settings.get(name, {}), **fields}
    return mutate


def drop(name):
    return lambda t: t.settings.pop(name)


def replace(name, value):
    return lambda t: t.settings.__setitem__(name, value)


def both(*fns):
    def mutate(t):
        for f in fns:
            f(t)
    return mutate


def user(email, **fields):
    return lambda t: t.user(email).update(fields)


def sso(*assignments):
    return lambda t: t.sso.extend(assignments)


def services_without(*names):
    def mutate(t):
        from google_gap_assessment.workspace.checks.identity import SERVICE_SCOPE_GROUPS
        drop_groups = set().union(*(SERVICE_SCOPE_GROUPS[n] for n in names))
        t.settings["api_controls.google_services"] = {"services": [s for s in t.settings["api_controls.google_services"]["services"] if s["scopesGroup"] not in drop_groups]}
    return mutate


def swap_scope(old, new):
    def mutate(t):
        for s in t.settings["api_controls.google_services"]["services"]:
            if s["scopesGroup"] == old:
                s["scopesGroup"] = new
    return mutate


def takeout(service="ENABLED", **apps):
    def mutate(t):
        t.settings["takeout.service_status"] = {"serviceState": service}
        for app in ("blogger", "books", "location_history", "maps", "pay", "photos", "play", "play_console", "youtube"):
            t.settings[f"{app}.user_takeout"] = {"takeoutStatus": apps.get(app, "DISABLED")}
    return mutate


def more_admins(n):
    def mutate(t):
        for i in range(n):
            t.users.append({**t.user("root.admin@contoso.com"), "primaryEmail": f"extra{i}.admin@contoso.com", "id": f"extra{i}"})
    return mutate


EPOCH, FUTURE = "1970-01-01T00:00:00Z", "2027-06-01T00:00:00Z"

# (name, finding id, expected status, mutate(tenant), options, text that must appear in affected/detail)
CASES = [
    # 2-step verification
    ("GID-001 gap: enforcement date is the epoch (never enforced)", "GID-001", "Gap", setting(ENFORCE, enforcedFrom=EPOCH), None, "1970"),
    ("GID-001 gap: enforcement starts in the future", "GID-001", "Gap", setting(ENFORCE, enforcedFrom=FUTURE), None, "2027"),
    ("GID-001 gap: users are not allowed to enrol", "GID-001", "Gap", setting(ENROLL, allowEnrollment=False), None, None),
    ("GID-001 gap: an OU turns enforcement back off", "GID-001", "Gap", lambda t: t.override("/Sales", ENFORCE, {"enforcedFrom": EPOCH}), None, "/Sales"),
    ("GID-001 gap: a group is exempted", "GID-001", "Gap", lambda t: t.override("/Sales", ENFORCE, {"enforcedFrom": EPOCH}, group="g1"), None, "group sales-team@contoso.com"),
    ("GID-001 NotAssessed (not a pass): settings cannot be read", "GID-001", "NotAssessed", lambda t: t.fail(f"{CI}/policies", DENIED), None, None),
    ("GID-002 gap: any second factor is accepted", "GID-002", "Gap", setting(FACTOR, allowedSignInFactorSet="ALL"), None, "ALL"),
    ("GID-002 gap: factor is right but 2SV is not enforced yet", "GID-002", "Gap", setting(ENFORCE, enforcedFrom=EPOCH), None, None),
    ("GID-003 gap: no enrolment window", "GID-003", "Gap", setting(GRACE, enrollmentGracePeriod="0s"), None, "0s"),
    ("GID-003 gap: two-week enrolment window", "GID-003", "Gap", setting(GRACE, enrollmentGracePeriod="1209600s"), None, None),
    ("GID-003 pass: window does not matter while 2SV is not enforced", "GID-003", "Pass", both(setting(ENFORCE, enforcedFrom=EPOCH), setting(GRACE, enrollmentGracePeriod="0s")), None, None),
    ("GID-004 gap: devices can be trusted", "GID-004", "Gap", setting("security.two_step_verification_device_trust", allowTrustingDevice=True), None, None),
    ("GID-005 gap: an active user has no 2SV", "GID-005", "Gap", user("alice@contoso.com", isEnrolledIn2Sv=False), None, "alice@contoso.com"),
    ("GID-005 pass: a suspended user without 2SV is not counted", "GID-005", "Pass", user("alice@contoso.com", isEnrolledIn2Sv=False, suspended=True), None, None),
    ("GID-005 NotAssessed (not a pass): users cannot be listed", "GID-005", "NotAssessed", lambda t: t.fail("https://admin.googleapis.com/admin/directory/v1/users", DENIED), None, None),
    # sessions and passwords
    ("GID-006 gap: 24-hour sessions", "GID-006", "Gap", setting("security.session_controls", webSessionDuration="86400s"), None, "86400s"),
    ("GID-006 pass: 10-hour sessions", "GID-006", "Pass", setting("security.session_controls", webSessionDuration="36000s"), None, None),
    ("GID-006 NotAssessed: duration not returned", "GID-006", "NotAssessed", replace("security.session_controls", {}), None, None),
    ("GID-006 gap: an OU allows longer sessions", "GID-006", "Gap", lambda t: t.override("/Sales", "security.session_controls", {"webSessionDuration": "172800s"}), None, "/Sales"),
    ("GID-007 gap: strength is not Strong", "GID-007", "Gap", setting(PW, allowedStrength="WEAK"), None, "WEAK"),
    ("GID-007 gap: weak in one OU only", "GID-007", "Gap", lambda t: t.override("/Sales", PW, {"allowedStrength": "WEAK"}), None, "/Sales"),
    ("GID-008 gap: minimum length 8", "GID-008", "Gap", setting(PW, minimumLength=8), None, "8"),
    ("GID-008 pass: minimum length exactly 12", "GID-008", "Pass", setting(PW, minimumLength=12), None, None),
    ("GID-009 gap: 12 is below the recommended 16", "GID-009", "Gap", setting(PW, minimumLength=12), None, None),
    ("GID-010 gap: not enforced at next sign-in", "GID-010", "Gap", setting(PW, enforceRequirementsAtLogin=False), None, None),
    ("GID-011 gap: reuse allowed", "GID-011", "Gap", setting(PW, allowReuse=True), None, None),
    ("GID-012 gap: 90-day expiry", "GID-012", "Gap", setting(PW, expirationDuration="7776000s"), None, "7776000s"),
    # admins
    ("GID-013 gap: only one super admin", "GID-013", "Gap", lambda t: t.users.remove(t.user("backup.admin@contoso.com")), None, "only 1"),
    ("GID-013 gap: nine super admins", "GID-013", "Gap", more_admins(7), None, "there are 9"),
    ("GID-013 pass: eight super admins", "GID-013", "Pass", more_admins(6), None, None),
    ("GID-013 pass: a suspended super admin is not counted", "GID-013", "Pass", user("backup.admin@contoso.com", suspended=True), WsOptions(min_super_admins=1), None),
    ("GID-014 gap: the admin OU signs in through SAML", "GID-014", "Gap", sso({"targetOrgUnit": "orgUnits/ou_admins", "ssoMode": "SAML_SSO"}), None, "root.admin@contoso.com"),
    ("GID-014 gap: tenant-wide SSO covers the admin OU", "GID-014", "Gap", sso({"targetOrgUnit": "orgUnits/root", "ssoMode": "SAML_SSO"}), None, "SAML_SSO"),
    ("GID-014 pass: SSO only for an OU without admins", "GID-014", "Pass", sso({"targetOrgUnit": "orgUnits/ou_sales", "ssoMode": "SAML_SSO"}), None, None),
    ("GID-014 pass: the admin OU opts out of tenant-wide SSO (nearest wins)", "GID-014", "Pass",
     sso({"targetOrgUnit": "orgUnits/root", "ssoMode": "SAML_SSO"}, {"targetOrgUnit": "orgUnits/ou_admins", "ssoMode": "SSO_OFF"}), None, None),
    ("GID-014 NotAssessed: a group-targeted SSO assignment cannot be resolved", "GID-014", "NotAssessed", sso({"targetGroup": "groups/g1", "ssoMode": "SAML_SSO"}), None, "group"),
    ("GID-015 gap: super admin without 2SV", "GID-015", "Gap", user("root.admin@contoso.com", isEnrolledIn2Sv=False), None, "super admin without"),
    ("GID-015 gap: delegated admin without 2SV", "GID-015", "Gap", user("help.desk@contoso.com", isEnrolledIn2Sv=False), None, "delegated admin"),
    ("GID-015 pass: an ordinary user without 2SV is GID-005's business", "GID-015", "Pass", user("alice@contoso.com", isEnrolledIn2Sv=False), None, None),
    ("GID-016 gap: no sign-in for more than 90 days", "GID-016", "Gap", user("alice@contoso.com", lastLoginTime="2025-01-01T00:00:00.000Z"), None, "2025-01-01"),
    ("GID-016 gap: never signed in and created long ago", "GID-016", "Gap", user("bob@contoso.com", lastLoginTime="1970-01-01T00:00:00.000Z"), None, "never signed in"),
    ("GID-016 pass: never signed in but created recently", "GID-016", "Pass", user("bob@contoso.com", lastLoginTime="1970-01-01T00:00:00.000Z", creationTime="2026-10-10T00:00:00.000Z"), None, None),
    ("GID-016 pass: window raised to 2000 days", "GID-016", "Pass", user("alice@contoso.com", lastLoginTime="2025-01-01T00:00:00.000Z"), WsOptions(stale_days=2000), None),
    # recovery, conflicting accounts
    ("GID-017 gap: conflicting account is preserved", "GID-017", "Gap", replace("provisioning.conflicting_accounts_management", {"option": "PRESERVE_CONFLICTING_ACCOUNT"}), None, "PRESERVE"),
    ("GID-017 gap: invitations are sent instead of replacing", "GID-017", "Gap", replace("provisioning.conflicting_accounts_management", {"option": "AUTOMATICALLY_SEND_INVITATIONS"}), None, None),
    ("GID-017 pass: the alternative field name is understood", "GID-017", "Pass", replace("provisioning.conflicting_accounts_management", {"conflictingAccountsManagement": "REPLACE_CONFLICTING_ACCOUNT"}), None, None),
    ("GID-018 gap: super admin self-recovery on", "GID-018", "Gap", setting("security.super_admin_account_recovery", enableAccountRecovery=True), None, None),
    ("GID-019 gap: user self-recovery on", "GID-019", "Gap", setting("security.user_account_recovery", enableAccountRecovery=True), None, None),
    # app access
    ("GID-020 gap: Drive is not restricted", "GID-020", "Gap", services_without("Drive"), None, "Drive"),
    ("GID-020 gap: nothing is restricted", "GID-020", "Gap", replace("api_controls.google_services", {"services": []}), None, "Gmail"),
    ("GID-020 gap: no API controls policy at all", "GID-020", "Gap", drop("api_controls.google_services"), None, None),
    ("GID-021 gap: Drive restricted only for high-risk scopes", "GID-021", "Gap", swap_scope("DRIVE_ALL", "DRIVE_HIGH_RISK"), None, "Drive"),
    ("GID-022 gap: internal apps trusted", "GID-022", "Gap", setting("api_controls.internal_apps", trustInternalApps=True), None, None),
    ("GID-022 NotAssessed: the setting is not returned (no default is assumed)", "GID-022", "NotAssessed", drop("api_controls.internal_apps"), None, None),
    ("GID-023 gap: any third-party app allowed", "GID-023", "Gap", setting("api_controls.unconfigured_third_party_apps", accessLevel="UNSPECIFIED_UBER_BLOCK"), None, "UNSPECIFIED"),
    ("GID-023 gap: sign-in-only apps allowed", "GID-023", "Gap", setting("api_controls.unconfigured_third_party_apps", accessLevel="ALLOW_SIGN_IN_SCOPES_ONLY"), None, None),
    ("GID-023 NotAssessed: not returned", "GID-023", "NotAssessed", drop("api_controls.unconfigured_third_party_apps"), None, None),
    ("GID-024 gap: less secure apps allowed", "GID-024", "Gap", setting("security.less_secure_apps", allowLessSecureApps=True), None, None),
    ("GID-024 pass: Google's default is off, so no policy means pass", "GID-024", "Pass", drop("security.less_secure_apps"), None, None),
    ("GID-025 gap: all Marketplace apps allowed", "GID-025", "Gap", setting("workspace_marketplace.apps_access_options", accessLevel="ALLOW_ALL"), None, "ALLOW_ALL"),
    ("GID-025 gap: allowlist but all internal apps allowed", "GID-025", "Gap", setting("workspace_marketplace.apps_access_options", allowAllInternalApps=True), None, None),
    ("GID-025 pass: no Marketplace apps at all", "GID-025", "Pass", setting("workspace_marketplace.apps_access_options", accessLevel="ALLOW_NONE"), None, None),
    # takeout, alerts, regions, approvals, DLP
    ("GID-026 gap: Takeout enabled for a product", "GID-026", "Gap", takeout(youtube="ENABLED"), None, "youtube"),
    ("GID-026 pass: service on but every product's Takeout is off", "GID-026", "Pass", takeout(), None, None),
    ("GID-026 NotAssessed: product settings not returned", "GID-026", "NotAssessed", replace("takeout.service_status", {"serviceState": "ENABLED"}), None, "Takeout status"),
    ("GID-027 gap: an alert rule is inactive", "GID-027", "Gap", lambda t: t.settings["rule.system_defined_alerts"][1].update(state="INACTIVE"), None, "User-reported phishing"),
    ("GID-027 NotAssessed: alert rules not returned", "GID-027", "NotAssessed", drop("rule.system_defined_alerts"), None, None),
    ("GID-028 gap: no region pinned", "GID-028", "Gap", setting("data_regions.data_at_rest_region", region="NO_PREFERENCE"), None, None),
    ("GID-028 pass: Europe", "GID-028", "Pass", setting("data_regions.data_at_rest_region", region="EUROPE"), None, None),
    ("GID-028 NotAssessed: edition without data regions", "GID-028", "NotAssessed", drop("data_regions.data_at_rest_region"), None, "Google returned no value"),
    ("GID-029 gap: processing not limited to the storage region", "GID-029", "Gap", setting("data_regions.data_processing_region", limitToStorageRegion=False), None, None),
    ("GID-030 gap: multi-party approval off", "GID-030", "Gap", setting("multi_party_approval.require_approvals", multiPartyApprovalState="DISABLED"), None, None),
    ("GID-031 gap: no DLP rules", "GID-031", "Gap", drop("rule.dlp"), None, "no data-protection rules"),
    ("GID-031 gap: rules exist but none active", "GID-031", "Gap", lambda t: t.settings["rule.dlp"][0].update(state="INACTIVE"), None, "none is active"),
]


class IdentityChecks(unittest.TestCase):
    def test_healthy_tenant_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)

    def test_every_identity_check_has_a_case_for_a_gap(self):
        covered = {c[1] for c in CASES if c[2] == "Gap"}
        self.assertEqual({chk.id for chk in MODULE.CHECKS}, covered)


if __name__ == "__main__":
    unittest.main()
