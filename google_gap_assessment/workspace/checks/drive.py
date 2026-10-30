"""Workspace Drive and Docs (GDR-xxx): who files can be shared with, how sharing is warned about, default link access, shared drives,
the link-security update, Drive SDK and Drive for desktop.

Most rules depend on the external sharing mode (off / allowlisted domains / anyone), so the predicates read the mode first and ask
the question that applies to it, the same way an admin would read the console.
"""

from __future__ import annotations

from ..context import WsContext
from .common import PolicyRule, all_of, describe_fields, flag, is_in, registrar, run_checks

CHECKS: list = []
check = registrar(CHECKS)
DOMAIN_NAME = "Workspace: Drive and Docs"

SVC = "drive_and_docs.service_status"
SHARING = "drive_and_docs.external_sharing"
OFF, ALLOWLIST, ANYONE = "DISALLOWED", "ALLOWLISTED_DOMAINS", "ALLOWED"


def by_mode(*, off=True, allowlisted=None, anyone=None):
    """Predicate on the external-sharing settings: pick the question that applies to the current sharing mode.

    Each argument is True/False (a fixed answer) or a (field, wanted_value) pair. ``None`` means the question does not apply.
    """
    def ok(s):
        mode = s.get("externalSharingMode")
        if mode is None:
            return None
        rule = {OFF: off, ALLOWLIST: allowlisted, ANYONE: anyone}.get(mode)
        if rule is None or isinstance(rule, bool):
            return True if rule is None else rule
        field, wanted = rule
        return None if s.get(field) is None else s[field] == wanted
    return ok


def _rule(id_, setting, ok, fields, detail, question):
    return PolicyRule(id_, setting, ok, describe_fields(*fields), detail, question, service=SVC)


MODE = "externalSharingMode"
RULES = [
    _rule("GDR-001", SHARING, lambda s: None if s.get(MODE) is None else s[MODE] != ANYONE, [MODE],
          "Letting people share with anyone outside the organisation is how documents end up with unknown recipients; restrict it to allowlisted domains or switch it off.",
          "Sharing outside the organisation is off or limited to allowlisted domains"),
    _rule("GDR-002", SHARING, by_mode(off=("allowReceivingExternalFiles", False), allowlisted=("allowReceivingFilesOutsideAllowlistedDomains", False), anyone=None),
          [MODE, "allowReceivingExternalFiles", "allowReceivingFilesOutsideAllowlistedDomains"],
          "Accepting files from outside brings content you cannot vet into the organisation's Drive.", "Users cannot receive files from outside the sharing boundary"),
    _rule("GDR-003", SHARING, by_mode(off=True, allowlisted=("warnForSharingOutsideAllowlistedDomains", True), anyone=("warnForExternalSharing", True)),
          [MODE, "warnForExternalSharing", "warnForSharingOutsideAllowlistedDomains"],
          "A warning before sharing outside gives users a chance to stop an accidental disclosure.", "Users are warned before sharing outside the organisation"),
    _rule("GDR-004", SHARING, by_mode(off=True, allowlisted=("allowNonGoogleInvitesInAllowlistedDomains", False), anyone=("allowNonGoogleInvites", False)),
          [MODE, "allowNonGoogleInvites", "allowNonGoogleInvitesInAllowlistedDomains"],
          "Inviting people without a Google account (via a PIN) gives access to someone whose identity Google never verified.",
          "Users cannot invite people without Google accounts to view files"),
    _rule("GDR-005", SHARING, lambda s: None if s.get(MODE) is None else (True if s[MODE] == OFF else (None if s.get("allowPublishingFiles") is None else s["allowPublishingFiles"] is False)),
          [MODE, "allowPublishingFiles"], "Publishing to the web makes content readable by anyone, indexed or not.", "Users cannot publish files to the web"),
    _rule("GDR-006", SHARING, is_in("accessCheckerSuggestions", "RECIPIENTS_ONLY"), ["accessCheckerSuggestions"],
          "When a recipient lacks access, suggesting 'anyone with the link' or a wider audience quietly widens exposure.",
          "Access-checker suggestions offer only the intended recipients"),
    _rule("GDR-007", SHARING, lambda s: None if s.get(MODE) is None else (True if s[MODE] == OFF else (None if s.get("allowedPartiesForDistributingContent") is None else s["allowedPartiesForDistributingContent"] == "NONE")),
          [MODE, "allowedPartiesForDistributingContent"], "Letting people move content into shared drives owned by another organisation transfers control of it.",
          "Content cannot be distributed to shared drives outside the organisation"),
    # LINK_SHARING_PRIVATE is Google's documented default, but Google does not say what it means, so it cannot be judged (NotAssessed).
    _rule("GDR-008", "drive_and_docs.general_access_default",
          lambda s: None if s.get("defaultFileAccess") in (None, "LINK_SHARING_PRIVATE") else s["defaultFileAccess"] == "PRIVATE_TO_OWNER", ["defaultFileAccess"],
          "New files that default to link-sharing are visible to more people than their owners usually intend.", "New files are private to their owner by default"),
    _rule("GDR-009", "drive_and_docs.external_file_warning", flag("highlightingEnabled", True), ["highlightingEnabled"],
          "Marking files that come from outside helps users treat them with suspicion.", "Files from outside the organisation are highlighted"),
    _rule("GDR-010", "drive_and_docs.shared_drive_creation", flag("allowManagersToOverrideSettings", False), ["allowManagersToOverrideSettings"],
          "Shared drive managers who can override the organisation's settings can widen sharing for the whole drive.", "Shared drive managers cannot override sharing settings"),
    _rule("GDR-011", "drive_and_docs.shared_drive_creation", flag("allowExternalUserAccess", False), ["allowExternalUserAccess"],
          "Shared drives often hold whole teams' content; letting outsiders be added to them is a large exposure.", "Shared drives cannot be shared with people outside the organisation"),
    _rule("GDR-012", "drive_and_docs.file_security_update", lambda s: None if s.get("securityUpdate") is None else (s["securityUpdate"] == "APPLY_TO_IMPACTED_FILES" and not s.get("allowUsersToManageUpdate")),
          ["securityUpdate", "allowUsersToManageUpdate"],
          "Google's link-security update stops old, guessable sharing links from working; users must not be able to switch it off for their own files.",
          "The Drive link-security update is applied and users cannot remove it"),
    _rule("GDR-013", "drive_and_docs.drive_sdk", flag("enableDriveSdkApiAccess", False), ["enableDriveSdkApiAccess"],
          "The Drive SDK lets third-party apps read and write users' Drive content.", "Drive SDK access is off"),
    _rule("GDR-014", "drive_and_docs.drive_for_desktop",
          lambda s: None if s.get("allowDriveForDesktop") is None else (not s["allowDriveForDesktop"] or bool(s.get("restrictToAuthorizedDevices"))),
          ["allowDriveForDesktop", "restrictToAuthorizedDevices"],
          "Drive for desktop syncs data to the device; on an unmanaged device that data is out of your control.", "Drive for desktop works only on authorised devices"),
]
CHECKS.extend(r.as_check() for r in RULES)


def collect(ctx: WsContext, tenants: "list[str]", only=None) -> "list[dict]":
    return run_checks(ctx, tenants, CHECKS, only)
