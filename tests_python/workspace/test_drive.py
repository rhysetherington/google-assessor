"""Workspace Drive and Docs (GDR-001..GDR-014) against the fake tenant. Many rules depend on the external sharing mode."""

import unittest

from google_gap_assessment.workspace.checks import drive as MODULE
from tests_python.workspace.helpers import both, coverage_test, drop, healthy_passes, off, override, replace, run_cases, setting

# (name, finding id, expected status, mutate(tenant), options, text that must appear in affected/detail)
CASES = [
    ("GDR-001 gap: sharing with anyone outside", "GDR-001", "Gap", setting("drive_and_docs.external_sharing", externalSharingMode="ALLOWED"), None, "ALLOWED"),
    ("GDR-001 pass: sharing off entirely", "GDR-001", "Pass", setting("drive_and_docs.external_sharing", externalSharingMode="DISALLOWED"), None, None),
    ("GDR-001 gap: an OU allows sharing with anyone", "GDR-001", "Gap", override("/Sales", "drive_and_docs.external_sharing", {"externalSharingMode": "ALLOWED"}), None, "/Sales"),
    ("GDR-002 gap: allowlisted, but receiving files from outside the allowlist", "GDR-002", "Gap", setting("drive_and_docs.external_sharing", allowReceivingFilesOutsideAllowlistedDomains=True), None, None),
    ("GDR-002 gap: sharing off, but receiving external files", "GDR-002", "Gap", setting("drive_and_docs.external_sharing", externalSharingMode="DISALLOWED", allowReceivingExternalFiles=True), None, None),
    ("GDR-002 pass: sharing with anyone has no receiving rule", "GDR-002", "Pass", setting("drive_and_docs.external_sharing", externalSharingMode="ALLOWED", allowReceivingExternalFiles=True), None, None),
    ("GDR-003 gap: allowlisted without a warning", "GDR-003", "Gap", setting("drive_and_docs.external_sharing", warnForSharingOutsideAllowlistedDomains=False), None, None),
    ("GDR-003 gap: anyone-sharing without a warning", "GDR-003", "Gap", setting("drive_and_docs.external_sharing", externalSharingMode="ALLOWED", warnForExternalSharing=False), None, None),
    ("GDR-003 pass: sharing off needs no warning", "GDR-003", "Pass", setting("drive_and_docs.external_sharing", externalSharingMode="DISALLOWED", warnForExternalSharing=False), None, None),
    ("GDR-004 gap: allowlisted but non-Google invites allowed", "GDR-004", "Gap", setting("drive_and_docs.external_sharing", allowNonGoogleInvitesInAllowlistedDomains=True), None, None),
    ("GDR-004 gap: anyone-sharing with non-Google invites", "GDR-004", "Gap", setting("drive_and_docs.external_sharing", externalSharingMode="ALLOWED", allowNonGoogleInvites=True), None, None),
    ("GDR-005 gap: publishing to the web allowed", "GDR-005", "Gap", setting("drive_and_docs.external_sharing", allowPublishingFiles=True), None, "allowPublishingFiles"),
    ("GDR-005 pass: publishing flag is irrelevant when sharing is off", "GDR-005", "Pass", setting("drive_and_docs.external_sharing", externalSharingMode="DISALLOWED", allowPublishingFiles=True), None, None),
    ("GDR-006 gap: access checker suggests wider audiences", "GDR-006", "Gap", setting("drive_and_docs.external_sharing", accessCheckerSuggestions="RECIPIENTS_OR_AUDIENCE_OR_PUBLIC"), None, None),
    ("GDR-007 gap: content can be distributed to all users", "GDR-007", "Gap", setting("drive_and_docs.external_sharing", allowedPartiesForDistributingContent="ALL_ELIGIBLE_USERS"), None, None),
    ("GDR-008 gap: new files default to link sharing", "GDR-008", "Gap", setting("drive_and_docs.general_access_default", defaultFileAccess="PRIMARY_AUDIENCE_WITH_LINK"), None, None),
    ("GDR-008 NotAssessed: Google's default value (LINK_SHARING_PRIVATE) is undefined, so it cannot be judged", "GDR-008", "NotAssessed", drop("drive_and_docs.general_access_default"), None, "Check it in the Admin console"),
    ("GDR-008 pass: private to the owner", "GDR-008", "Pass", setting("drive_and_docs.general_access_default", defaultFileAccess="PRIVATE_TO_OWNER"), None, None),
    ("GDR-009 gap: external files not highlighted", "GDR-009", "Gap", setting("drive_and_docs.external_file_warning", highlightingEnabled=False), None, None),
    ("GDR-009 NotAssessed: setting not returned", "GDR-009", "NotAssessed", drop("drive_and_docs.external_file_warning"), None, None),
    ("GDR-010 gap: managers can override settings", "GDR-010", "Gap", setting("drive_and_docs.shared_drive_creation", allowManagersToOverrideSettings=True), None, None),
    ("GDR-011 gap: shared drives open to outsiders", "GDR-011", "Gap", setting("drive_and_docs.shared_drive_creation", allowExternalUserAccess=True), None, None),
    ("GDR-012 gap: security update not applied", "GDR-012", "Gap", setting("drive_and_docs.file_security_update", securityUpdate="REMOVE_FROM_IMPACTED_FILES"), None, None),
    ("GDR-012 gap: users may remove the update", "GDR-012", "Gap", setting("drive_and_docs.file_security_update", allowUsersToManageUpdate=True), None, None),
    ("GDR-013 gap: Drive SDK on", "GDR-013", "Gap", setting("drive_and_docs.drive_sdk", enableDriveSdkApiAccess=True), None, None),
    ("GDR-014 gap: Drive for desktop on any device", "GDR-014", "Gap", setting("drive_and_docs.drive_for_desktop", restrictToAuthorizedDevices=False), None, None),
    ("GDR-014 pass: Drive for desktop switched off", "GDR-014", "Pass", setting("drive_and_docs.drive_for_desktop", allowDriveForDesktop=False, restrictToAuthorizedDevices=False), None, None),
    ("GDR-001 pass (not applicable): Drive is switched off", "GDR-001", "Pass", both(off("drive_and_docs.service_status"), setting("drive_and_docs.external_sharing", externalSharingMode="ALLOWED")), None, "switched off"),
    ("GDR-001 gap: with no policy, Google's documented default allows sharing with anyone", "GDR-001", "Gap", replace("drive_and_docs.external_sharing", {}), None, "ALLOWED"),
]


class DriveChecks(unittest.TestCase):
    def test_healthy_tenant_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)

    def test_every_check_has_a_case_for_a_gap(self):
        coverage_test(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
