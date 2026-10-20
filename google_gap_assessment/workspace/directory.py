"""Admin SDK Directory API reads (users, groups, OUs, domains, admin roles). All GET, all read-only scopes.

Only the fields a check needs are requested (the API's `fields` parameter), so names, phone numbers, addresses and the like are never
downloaded, let alone written to a report.
"""

from __future__ import annotations

from typing import Any, Callable

from .client import WorkspaceClient

BASE = "https://admin.googleapis.com/admin/directory/v1"
USER_FIELDS = ("id,primaryEmail,isAdmin,isDelegatedAdmin,isEnrolledIn2Sv,isEnforcedIn2Sv,suspended,archived,"
               "lastLoginTime,creationTime,orgUnitPath")


class Directory:
    """Lazy, memoised reads. A failure is remembered too, so a missing permission is reported once, not once per check."""

    def __init__(self, client: WorkspaceClient):
        self._client = client
        self._memo: "dict[str, tuple[bool, Any]]" = {}

    def _once(self, key: str, fn: Callable[[], Any]) -> Any:
        if key not in self._memo:
            try:
                self._memo[key] = (True, fn())
            except Exception as exc:  # noqa: BLE001 - remembered and re-raised for every caller
                self._memo[key] = (False, exc)
        ok, value = self._memo[key]
        if not ok:
            raise value
        return value

    def customer(self) -> dict:
        return self._once("customer", lambda: self._client.get(f"{BASE}/customers/my_customer", {"fields": "id,customerDomain,postalAddress/countryCode"}))

    def domains(self) -> "list[dict]":
        return self._once("domains", lambda: self._client.items(
            f"{BASE}/customer/my_customer/domains", {"fields": "domains(domainName,isPrimary,verified,domainAliases/domainAliasName)"}, key="domains"))

    def orgunits(self) -> "list[dict]":
        return self._once("orgunits", lambda: self._client.items(
            f"{BASE}/customer/my_customer/orgunits", {"type": "all_including_parent", "orgUnitPath": "/"}, key="organizationUnits"))

    def users(self) -> "list[dict]":
        return self._once("users", lambda: self._client.items(
            f"{BASE}/users", {"customer": "my_customer", "maxResults": 500, "projection": "basic",
                              "fields": f"nextPageToken,users({USER_FIELDS})"}, key="users"))

    def groups(self) -> "list[dict]":
        return self._once("groups", lambda: self._client.items(
            f"{BASE}/groups", {"customer": "my_customer", "maxResults": 200, "fields": "nextPageToken,groups(id,email,directMembersCount)"}, key="groups"))

    def roles(self) -> "list[dict]":
        return self._once("roles", lambda: self._client.items(
            f"{BASE}/customer/my_customer/roles", {"maxResults": 100, "fields": "nextPageToken,items(roleId,roleName,isSystemRole,isSuperAdminRole)"}))

    def role_assignments(self) -> "list[dict]":
        return self._once("role_assignments", lambda: self._client.items(
            f"{BASE}/customer/my_customer/roleassignments", {"maxResults": 200, "fields": "nextPageToken,items(roleId,assignedTo,assigneeType,scopeType,orgUnitId)"}))

    def sso_assignments(self) -> "list[dict]":
        """Which OUs or groups sign in through an external identity provider (Cloud Identity inbound SSO assignments)."""
        return self._once("sso", lambda: self._client.items(
            "https://cloudidentity.googleapis.com/v1/inboundSsoAssignments", {"pageSize": 100}, key="inboundSsoAssignments"))
