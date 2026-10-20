"""A fake Google Workspace tenant for the offline suite.

``Tenant`` holds plain Python data for a tenant that meets every check (settings at the top-level OU, a few users, OUs). A test breaks one
thing on it, then ``Tenant.context()`` serves it through a ``FakeWorkspace`` client, so the real reducer, directory code and checks run.
No network, no Google account.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any

from google_gap_assessment.errors import ApiError
from google_gap_assessment.workspace.client import WorkspaceClient
from google_gap_assessment.workspace.context import WsContext, WsOptions
from google_gap_assessment.workspace.directory import Directory

TENANT = "contoso.com"
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
ADMIN = "https://admin.googleapis.com/admin/directory/v1"
CI = "https://cloudidentity.googleapis.com/v1"


class Err:
    """Make a route fail the way Google does."""
    def __init__(self, category: str, message: str = "error"):
        self.category, self.message = category, message


DENIED = Err("PermissionDenied", "HTTP 403: Not Authorized to access this resource/api")
DISABLED = Err("ApiDisabled", "HTTP 403: API has not been used in project")


class FakeWorkspace(WorkspaceClient):
    """A real WorkspaceClient whose network layer is replaced by a route table (so caching and list helpers are the production code)."""

    def __init__(self, routes: "dict[str, Any]"):
        super().__init__(lambda: "fake-token")
        self.routes = routes
        self.requests: "list[str]" = []

    def get(self, url: str, params: "dict | None" = None) -> dict:
        self._build(url, params)  # applies the production host allowlist
        self.requests.append(url)
        route = self.routes.get(url)
        if route is None:
            raise ApiError(f"No fixture for {url}", "NotFound")
        if callable(route):
            route = route(params or {})
        if isinstance(route, Err):
            raise ApiError(route.message, route.category)
        return copy.deepcopy(route)


class FakeResolver:
    """DNS fixture: name -> list of TXT records. A value of Err makes the lookup fail."""
    def __init__(self, records: "dict[str, Any]"):
        self.records, self.lookups = records, []

    def txt(self, name: str) -> "list[str]":
        self.lookups.append(name.lower())
        value = self.records.get(name.lower(), [])
        if isinstance(value, Err):
            raise ApiError(value.message, value.category)
        return list(value)


def _service_groups():
    from google_gap_assessment.workspace.checks.identity import SERVICE_SCOPE_GROUPS
    return [{"scopesGroup": sorted(groups, key=lambda g: (not g.endswith("_ALL"), g))[0]} for groups in SERVICE_SCOPE_GROUPS.values()]


def healthy_settings() -> "dict[str, Any]":
    """Admin-console settings at the top-level OU for a tenant that meets every identity check."""
    return {
        "security.two_step_verification_enrollment": {"allowEnrollment": True},
        "security.two_step_verification_enforcement": {"enforcedFrom": "2024-01-01T00:00:00Z"},
        "security.two_step_verification_enforcement_factor": {"allowedSignInFactorSet": "PASSKEY_ONLY"},
        "security.two_step_verification_grace_period": {"enrollmentGracePeriod": "604800s"},
        "security.two_step_verification_device_trust": {"allowTrustingDevice": False},
        "security.session_controls": {"webSessionDuration": "43200s"},
        "security.password": {"allowedStrength": "STRONG", "minimumLength": 16, "maximumLength": 100, "enforceRequirementsAtLogin": True,
                              "allowReuse": False, "expirationDuration": "0s"},
        "provisioning.conflicting_accounts_management": {"option": "REPLACE_CONFLICTING_ACCOUNT"},
        "security.super_admin_account_recovery": {"enableAccountRecovery": False},
        "security.user_account_recovery": {"enableAccountRecovery": False},
        "api_controls.google_services": {"services": _service_groups()},
        "api_controls.internal_apps": {"trustInternalApps": False},
        "api_controls.unconfigured_third_party_apps": {"accessLevel": "BLOCK_ALL_SCOPES"},
        "security.less_secure_apps": {"allowLessSecureApps": False},
        "workspace_marketplace.apps_access_options": {"accessLevel": "ALLOW_LISTED_APPS", "allowAllInternalApps": False},
        "takeout.service_status": {"serviceState": "DISABLED"},
        "rule.system_defined_alerts": [{"displayName": "Government-backed attacks", "state": "ACTIVE"}, {"displayName": "User-reported phishing", "state": "ACTIVE"}],
        "data_regions.data_at_rest_region": {"region": "US"},
        "data_regions.data_processing_region": {"limitToStorageRegion": True},
        "multi_party_approval.require_approvals": {"multiPartyApprovalState": "ENABLED"},
        "rule.dlp": [{"displayName": "Block card numbers", "state": "ACTIVE", "triggers": ["google.workspace.drive.file.v1.share"]}],
    }


def _user(email, admin=False, delegated=False, ou="/", twosv=True, last="2026-10-18T09:00:00.000Z", created="2023-01-01T00:00:00.000Z", suspended=False):
    return {"id": email.split("@")[0], "primaryEmail": email, "isAdmin": admin, "isDelegatedAdmin": delegated, "isEnrolledIn2Sv": twosv,
            "isEnforcedIn2Sv": twosv, "suspended": suspended, "archived": False, "lastLoginTime": last, "creationTime": created, "orgUnitPath": ou}


class Tenant:
    """A healthy tenant. Mutate the attributes, then call ``context()``."""

    def __init__(self):
        self.settings: "dict[str, Any]" = healthy_settings()
        self.overrides: "list[tuple[str, str | None, str, Any, int]]" = []   # (ou path, group email, setting, value, sort order)
        self.users = [
            _user("root.admin@contoso.com", admin=True, ou="/Admins"), _user("backup.admin@contoso.com", admin=True, ou="/Admins"),
            _user("help.desk@contoso.com", delegated=True, ou="/IT"), _user("alice@contoso.com", ou="/Sales"), _user("bob@contoso.com", ou="/Sales"),
        ]
        self.ous = {"root": "/", "ou_admins": "/Admins", "ou_it": "/IT", "ou_sales": "/Sales"}
        self.groups = [{"id": "g1", "email": "sales-team@contoso.com", "directMembersCount": "5"}]
        self.domains = [{"domainName": TENANT, "isPrimary": True, "verified": True, "domainAliases": []}]
        self.sso: "list[dict]" = []
        self.errors: "dict[str, Err]" = {}          # route URL -> error
        self.dns: "dict[str, Any]" = {}

    # -- building ------------------------------------------------------------------------------------------------------
    def _raw_policies(self) -> "list[dict]":
        out = []
        for name, value in self.settings.items():
            values = value if isinstance(value, list) else [value]
            for v in values:
                out.append({"policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1}, "setting": {"type": f"settings/{name}", "value": copy.deepcopy(v)}})
        by_path = {path: ou_id for ou_id, path in self.ous.items()}
        for i, (path, group, name, value, order) in enumerate(self.overrides, 2):
            q = {"orgUnit": f"orgUnits/{by_path[path]}", "sortOrder": order or i}
            if group:
                q["group"] = f"groups/{group}"
            out.append({"policyQuery": q, "setting": {"type": f"settings/{name}", "value": copy.deepcopy(value)}})
        return out

    def routes(self) -> "dict[str, Any]":
        r: "dict[str, Any]" = {
            f"{CI}/policies": {"policies": self._raw_policies()},
            f"{ADMIN}/customer/my_customer/orgunits": {"organizationUnits": [
                {"name": ("contoso" if p == "/" else p.strip("/")), "orgUnitPath": p, "orgUnitId": f"id:{i}"} for i, p in self.ous.items()]},
            f"{ADMIN}/groups": {"groups": self.groups},
            f"{ADMIN}/users": {"users": self.users},
            f"{ADMIN}/customer/my_customer/domains": {"domains": self.domains},
            f"{ADMIN}/customers/my_customer": {"id": "C0123abcd", "customerDomain": TENANT},
            f"{ADMIN}/customer/my_customer/roles": {"items": [{"roleId": "1", "roleName": "_SEED_ADMIN_ROLE", "isSystemRole": True, "isSuperAdminRole": True}]},
            f"{ADMIN}/customer/my_customer/roleassignments": {"items": []},
            f"{CI}/inboundSsoAssignments": {"inboundSsoAssignments": self.sso},
        }
        r.update(self.errors)
        return r

    def context(self, options: "WsOptions | None" = None) -> WsContext:
        client = FakeWorkspace(self.routes())
        resolver = FakeResolver(self.dns)
        return WsContext(client=client, directory=Directory(client), resolver=resolver, options=options or WsOptions(), clock=lambda: NOW)

    # -- mutation helpers ----------------------------------------------------------------------------------------------
    def override(self, ou_path: str, setting: str, value: Any, group: "str | None" = None, order: int = 0) -> None:
        self.overrides.append((ou_path, group, setting, value, order))

    def fail(self, url: str, err: Err) -> None:
        self.errors[url] = err

    def user(self, email: str) -> dict:
        return next(u for u in self.users if u["primaryEmail"] == email)
