"""Google Workspace admin-console settings, read through the Cloud Identity Policy API (read-only).

The API returns every setting once per organisational unit (OU) and per group that overrides it, each with a sort order. This module
turns that list into "the setting as it applies in each OU / group":

* the highest sort order wins for a given OU or group and setting;
* some settings *merge*: fields missing from the winning policy are filled from lower-priority ones;
* a few settings are lists of independent rules (data-protection rules, system alerts) and are kept whole;
* the top-level OU must always have a value, so Google's documented defaults fill in settings nobody ever changed.

A check then asks one question of a setting: is it compliant at the top level, and in every OU or group that overrides it?
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .client import WorkspaceClient

POLICIES_URL = "https://cloudidentity.googleapis.com/v1/policies"
ORGUNITS_URL = "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/orgunits"
GROUPS_URL = "https://admin.googleapis.com/admin/directory/v1/groups"

# Settings whose lower-priority fields fill in anything the winning policy leaves out (Google's "merge" reducer).
MERGE_SETTINGS = {
    "calendar.interoperability", "calendar.primary_calendar_max_allowed_external_sharing",
    "calendar.secondary_calendar_max_allowed_external_sharing", "chat.chat_history", "chat.external_chat_restriction",
    "drive_and_docs.drive_sdk", "gmail.imap_access", "gmail.mail_delegation", "groups_for_business.groups_sharing",
    "security.less_secure_apps", "security.super_admin_account_recovery", "security.user_account_recovery",
    "workspace_marketplace.apps_access_options",
}
# Settings that are lists of entries identified by a key. Several policies each carry part of the list, and the entries are combined:
# an entry only a lower-priority policy has is added, and fields the winning entry lacks are filled in (Google's "max map" reducer).
MAX_MAP_SETTINGS = {
    "gmail.blocked_sender_lists": ("blockedSenders", "ruleId"), "gmail.email_address_lists": ("emailAddressList", "id"),
    "gmail.rule_states": ("ruleStates", "ruleId"), "gmail.spam_override_lists": ("spamOverride", "ruleId"),
}
# Settings that are independent rules: every policy is kept, none overrides another.
LIST_SETTINGS = {"rule.dlp", "rule.system_defined_alerts"}

# Values Google documents for settings that have never been changed (they exist only at the top-level OU).
DEFAULTS: "dict[str, dict[str, Any]]" = {
    "calendar.external_invitations": {"warnOnInvite": True},
    "calendar.interoperability": {"enableInteroperability": False},
    "calendar.primary_calendar_max_allowed_external_sharing": {"maxAllowedExternalSharing": "EXTERNAL_FREE_BUSY_ONLY"},
    "calendar.secondary_calendar_max_allowed_external_sharing": {"maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_ONLY"},
    "chat.chat_history": {"allowUserModification": True, "historyOnByDefault": False},
    "chat.external_chat_restriction": {"allowExternalChat": False, "externalChatRestriction": "NO_RESTRICTION"},
    "drive_and_docs.drive_sdk": {"enableDriveSdkApiAccess": True},
    "drive_and_docs.external_sharing": {
        "accessCheckerSuggestions": "RECIPIENTS_OR_AUDIENCE_OR_PUBLIC", "allowNonGoogleInvites": True,
        "allowNonGoogleInvitesInAllowlistedDomains": False, "allowPublishingFiles": True, "allowReceivingExternalFiles": True,
        "allowReceivingFilesOutsideAllowlistedDomains": True, "allowedPartiesForDistributingContent": "ALL_ELIGIBLE_USERS",
        "externalSharingMode": "ALLOWED", "warnForExternalSharing": True, "warnForSharingOutsideAllowlistedDomains": True},
    "drive_and_docs.general_access_default": {"defaultFileAccess": "LINK_SHARING_PRIVATE"},
    "gmail.auto_forwarding": {"enableAutoForwarding": True},
    "gmail.email_spam_filter_ip_allowlist": {"allowedIpAddresses": []},
    "gmail.links_and_external_images": {"applyFutureSettingsAutomatically": True, "enableAggressiveWarningsOnUntrustedLinks": False},
    "gmail.mail_delegation": {"enableMailDelegation": False},
    # Google's help ("Allow per-user outbound gateways"): users cannot use one unless an admin enables it.
    "gmail.per_user_outbound_gateway": {"allowUsersToUseExternalSmtpServers": False},
    "gmail.spoofing_and_authentication": {"applyFutureSettingsAutomatically": True},
    "gmail.workspace_sync_for_outlook": {"enableGoogleWorkspaceSyncForMicrosoftOutlook": True},
    "groups_for_business.groups_sharing": {
        "collaborationCapability": "DOMAIN_USERS_ONLY", "createGroupsAccessLevel": "USERS_IN_DOMAIN", "newGroupsAreHidden": False,
        "ownersCanAllowExternalMembers": False, "ownersCanAllowIncomingMailFromPublic": True, "ownersCanHideGroups": False,
        "viewTopicsDefaultAccessLevel": "DOMAIN_USERS"},
    "security.less_secure_apps": {"allowLessSecureApps": False},
    "security.super_admin_account_recovery": {"enableAccountRecovery": False},
    "security.two_step_verification_device_trust": {"allowTrustingDevice": True},
    "security.two_step_verification_enforcement": {"enforcedFrom": "1970-01-01T00:00:00Z"},
    "security.two_step_verification_enforcement_factor": {"allowedSignInFactorSet": "ALL"},
    "security.two_step_verification_enrollment": {"allowEnrollment": True},
    "security.two_step_verification_grace_period": {"enrollmentGracePeriod": "0s"},
    "security.user_account_recovery": {"enableAccountRecovery": False},
    "workspace_marketplace.apps_access_options": {"accessLevel": "ALLOW_ALL", "allowAllInternalApps": False},
    # Only restricted Google services are listed by the API, so "no policy" means nothing is restricted (as CISA's reference tool reads it).
    "api_controls.google_services": {"services": []},
    "access_management.user_scoping": {"accessManagementRegime": "PREFERENCE_UNSPECIFIED"},
    "access_approval.axa_user_scoping": {"requiresCustomerApproval": False},
}

TOP = "/"


@dataclass
class PolicySet:
    """Settings as they apply per scope. A scope is an OU path ("/", "/Sales") or "<OU path> (group <email>)"."""
    scopes: "dict[str, dict[str, Any]]" = field(default_factory=dict)

    def top(self, setting: str) -> "Optional[Any]":
        """Value at the top-level OU (defaults applied), or None when Google returned nothing and has no documented default."""
        return self.scopes.get(TOP, {}).get(setting)

    def overrides(self, setting: str) -> "list[tuple[str, Any]]":
        """(scope, value) for every OU or group below the top that sets this setting itself."""
        return [(label, values[setting]) for label, values in self.scopes.items() if label != TOP and setting in values]


def _sort_order(policy: dict) -> float:
    return float((policy.get("policyQuery") or {}).get("sortOrder") or 0)


def reduce_policies(raw: "list[dict]", ou_paths: "dict[str, str]", group_emails: "dict[str, str]") -> PolicySet:
    """Reduce raw API policies to one value per (scope, setting). See the module docstring for the rules."""
    result = PolicySet()
    for policy in sorted(raw, key=_sort_order, reverse=True):  # highest sort order first, so the first seen wins
        query = policy.get("policyQuery") or {}
        ou_id = str(query.get("orgUnit", "")).removeprefix("orgUnits/")
        if ou_id:
            if ou_id not in ou_paths:  # a recently deleted OU can leave policies behind; they apply to nobody
                continue
            label = ou_paths[ou_id]
        else:
            label = TOP  # a policy with no OU belongs to the top level
        group = str(query.get("group", "")).removeprefix("groups/")
        if group:
            label = f"{label} (group {group_emails.get(group, group)})"
        setting = policy.get("setting") or {}
        name = str(setting.get("type", "")).removeprefix("settings/")
        value = setting.get("value") or {}
        scope = result.scopes.setdefault(label, {})
        if name in LIST_SETTINGS:
            scope.setdefault(name, []).append(value)
        elif name not in scope:
            scope[name] = dict(value)
        elif name in MERGE_SETTINGS:
            for k, v in value.items():
                scope[name].setdefault(k, v)
        elif name in MAX_MAP_SETTINGS:
            field, key = MAX_MAP_SETTINGS[name]
            entries = scope[name].setdefault(field, [])
            by_key = {e.get(key): e for e in entries if isinstance(e, dict)}
            for entry in value.get(field) or []:
                known = by_key.get(entry.get(key)) if isinstance(entry, dict) else None
                if known is not None:
                    for k, v in entry.items():
                        known.setdefault(k, v)
                else:
                    entries.append(dict(entry) if isinstance(entry, dict) else entry)
                    if isinstance(entry, dict):
                        by_key[entry.get(key)] = entries[-1]

    top = result.scopes.setdefault(TOP, {})
    for name, defaults in DEFAULTS.items():
        merged = top.setdefault(name, {})
        for k, v in defaults.items():
            merged.setdefault(k, v)
    return result


def load_policies(client: WorkspaceClient) -> PolicySet:
    """Fetch OUs, groups and policies and reduce them."""
    ou_paths = {}
    for ou in client.items(ORGUNITS_URL, {"orgUnitPath": "/", "type": "all_including_parent"}, key="organizationUnits"):
        ou_paths[str(ou.get("orgUnitId", "")).removeprefix("id:")] = str(ou.get("orgUnitPath", TOP))
    try:  # group names only make labels readable; the policies are still reduced without them
        group_emails = {g["id"]: g["email"] for g in client.items(GROUPS_URL, {"customer": "my_customer"}, key="groups")}
    except Exception:  # noqa: BLE001
        group_emails = {}
    raw = client.items(POLICIES_URL, {"pageSize": 100}, key="policies", page_delay=1.0)
    return reduce_policies(raw, ou_paths, group_emails)


@dataclass
class Verdict:
    """Outcome of asking one question of one setting across every scope."""
    unknown: bool = False                       # no value at the top level and no documented default
    unreadable_field: bool = False              # the setting exists but the field the question needs was not returned
    bad: "list[tuple[str, Any]]" = field(default_factory=list)   # (scope, effective value) where the answer is "not compliant"


def judge(policies: PolicySet, setting: str, compliant: Callable[[Any], "Optional[bool]"]) -> Verdict:
    """Apply ``compliant`` (True / False / None for "cannot tell") to the setting at the top level and wherever it is overridden.

    An override is judged on the top-level values with the override's own fields laid over them, because an OU or group usually
    stores only the fields that differ.
    """
    top = policies.top(setting)
    if top is None:
        return Verdict(unknown=True)
    verdict = Verdict()
    answer = compliant(top)
    if answer is None:
        verdict.unreadable_field = True
    elif answer is False:
        verdict.bad.append((TOP, top))
    if isinstance(top, list):  # rule lists have no per-scope merge; judged as a whole at each scope
        for label, value in policies.overrides(setting):
            if compliant(value) is False:
                verdict.bad.append((label, value))
        return verdict
    for label, value in policies.overrides(setting):
        if compliant({**top, **value}) is False:
            verdict.bad.append((label, {**top, **value}))
    return verdict


def judge_many(policies: PolicySet, settings: "list[str]", compliant: Callable[[dict], "Optional[bool]"]) -> Verdict:
    """Like ``judge`` for a question that needs several settings at once (e.g. "enrolment allowed AND enforcement date has passed").

    ``compliant`` receives ``{setting: values}``. It is asked at the top level and at every OU or group that overrides any of the
    settings, with that scope's own fields laid over the top-level values.
    """
    tops = {name: policies.top(name) for name in settings}
    if any(v is None for v in tops.values()):
        return Verdict(unknown=True)
    by_scope: "dict[str, dict[str, Any]]" = {}
    for name in settings:
        for label, value in policies.overrides(name):
            by_scope.setdefault(label, {})[name] = value
    verdict = Verdict()
    for label in [TOP] + sorted(by_scope):
        view = {name: {**tops[name], **by_scope.get(label, {}).get(name, {})} for name in settings}
        answer = compliant(view)
        if answer is None and label == TOP:
            verdict.unreadable_field = True
        elif answer is False:
            verdict.bad.append((label, view))
    return verdict
