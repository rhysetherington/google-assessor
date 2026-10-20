"""Workspace Google Meet (GMT-001..GMT-006) against the fake tenant."""

import unittest

from google_gap_assessment.workspace.checks import meet as MODULE
from tests_python.workspace.helpers import both, coverage_test, drop, healthy_passes, off, override, replace, run_cases, setting

# (name, finding id, expected status, mutate(tenant), options, text that must appear in affected/detail)
CASES = [
    ("GMT-001 gap: anyone can join without asking", "GMT-001", "Gap", setting("meet.meet_joining", allowedAudience="OPEN"), None, "OPEN"),
    ("GMT-001 pass: restricted", "GMT-001", "Pass", setting("meet.meet_joining", allowedAudience="RESTRICTED"), None, None),
    ("GMT-002 gap: any meeting can be joined", "GMT-002", "Gap", setting("meet.safety_access", meetingsAllowedToJoin="ALL"), None, "ALL"),
    ("GMT-002 pass: any Workspace organisation", "GMT-002", "Pass", setting("meet.safety_access", meetingsAllowedToJoin="ANY_WORKSPACE_ORGANIZATION"), None, None),
    ("GMT-003 gap: host management off", "GMT-003", "Gap", setting("meet.safety_host_management", enableHostManagement=False), None, None),
    ("GMT-004 gap: external label off", "GMT-004", "Gap", setting("meet.safety_external_participants", enableExternalLabel=False), None, None),
    ("GMT-005 gap: automatic recording on", "GMT-005", "Gap", setting("meet.automatic_recording", enabled=True), None, None),
    ("GMT-006 gap: automatic transcription on", "GMT-006", "Gap", setting("meet.automatic_transcription", enabled=True), None, None),
    ("GMT-001 NotAssessed (not a pass): setting not returned", "GMT-001", "NotAssessed", drop("meet.meet_joining"), None, None),
    ("GMT-005 gap: one OU records automatically", "GMT-005", "Gap", override("/Sales", "meet.automatic_recording", {"enabled": True}), None, "/Sales"),
    ("GMT-003 pass (not applicable): Meet is switched off", "GMT-003", "Pass", off("meet.service_status"), None, "switched off"),
]


class MeetChecks(unittest.TestCase):
    def test_healthy_tenant_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)

    def test_every_check_has_a_case_for_a_gap(self):
        coverage_test(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
