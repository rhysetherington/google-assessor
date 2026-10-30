"""Workspace Calendar (GCL-001..GCL-005) against the fake tenant."""

import unittest

from google_gap_assessment.workspace.checks import calendar as MODULE
from tests_python.workspace.helpers import both, coverage_test, drop, healthy_passes, off, override, replace, run_cases, setting

# (name, finding id, expected status, mutate(tenant), options, text that must appear in affected/detail)
CASES = [
    ("GCL-001 gap: primary calendars share all details", "GCL-001", "Gap", setting("calendar.primary_calendar_max_allowed_external_sharing", maxAllowedExternalSharing="EXTERNAL_ALL_INFO_READ_ONLY"), None, "READ_ONLY"),
    ("GCL-002 gap: secondary calendars share all details", "GCL-002", "Gap", setting("calendar.secondary_calendar_max_allowed_external_sharing", maxAllowedExternalSharing="EXTERNAL_ALL_INFO_READ_WRITE"), None, None),
    ("GCL-001 pass: Google's default is free/busy, so no policy means pass", "GCL-001", "Pass", drop("calendar.primary_calendar_max_allowed_external_sharing"), None, None),
    ("GCL-002 gap: Google's default for secondary calendars is not free/busy", "GCL-002", "Gap", drop("calendar.secondary_calendar_max_allowed_external_sharing"), None, "EXTERNAL_ALL_INFO_READ_ONLY"),
    ("GCL-003 gap: no invitation warning", "GCL-003", "Gap", setting("calendar.external_invitations", warnOnInvite=False), None, None),
    ("GCL-004 gap: interop on", "GCL-004", "Gap", setting("calendar.interoperability", enableInteroperability=True), None, None),
    ("GCL-005 gap: payments allowed", "GCL-005", "Gap", setting("calendar.appointment_schedules", enablePayments=True), None, None),
    ("GCL-005 NotAssessed: no Google default and no policy", "GCL-005", "NotAssessed", drop("calendar.appointment_schedules"), None, None),
    ("GCL-001 gap: one OU shares all details", "GCL-001", "Gap", override("/Sales", "calendar.primary_calendar_max_allowed_external_sharing", {"maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_WRITE"}), None, "/Sales"),
    ("GCL-003 pass (not applicable): Calendar is switched off", "GCL-003", "Pass", off("calendar.service_status"), None, "switched off"),
]


class CalendarChecks(unittest.TestCase):
    def test_healthy_tenant_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)

    def test_every_check_has_a_case_for_a_gap(self):
        coverage_test(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
