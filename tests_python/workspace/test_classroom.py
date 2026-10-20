"""Workspace Classroom (GCR-001..GCR-006) against the fake tenant."""

import unittest

from google_gap_assessment.workspace.checks import classroom as MODULE
from tests_python.workspace.helpers import both, coverage_test, drop, healthy_passes, off, override, replace, run_cases, setting

# (name, finding id, expected status, mutate(tenant), options, text that must appear in affected/detail)
CASES = [
    ("GCR-001 gap: anyone can join", "GCR-001", "Gap", setting("classroom.class_membership", whoCanJoinClasses="ANYONE"), None, "ANYONE"),
    ("GCR-001 pass: allowlisted domains", "GCR-001", "Pass", setting("classroom.class_membership", whoCanJoinClasses="ANYONE_IN_ALLOWLISTED_DOMAINS"), None, None),
    ("GCR-002 gap: any Workspace class", "GCR-002", "Gap", setting("classroom.class_membership", whichClassesCanUsersJoin="ANY_GOOGLE_WORKSPACE_CLASS"), None, None),
    ("GCR-003 gap: apps can use Classroom data", "GCR-003", "Gap", setting("classroom.api_data_access", enableApiAccess=True), None, None),
    ("GCR-004 gap: Clever roster import on", "GCR-004", "Gap", setting("classroom.roster_import", rosterImportOption="ON_CLEVER"), None, "ON_CLEVER"),
    ("GCR-005 gap: students can unenrol", "GCR-005", "Gap", setting("classroom.student_unenrollment", whoCanUnenrollStudents="STUDENTS_AND_TEACHERS"), None, None),
    ("GCR-006 gap: anyone in the domain can create classes", "GCR-006", "Gap", setting("classroom.teacher_permissions", whoCanCreateClasses="ANYONE_IN_DOMAIN"), None, None),
    ("GCR-006 gap: one OU lets anyone create classes", "GCR-006", "Gap", override("/Sales", "classroom.teacher_permissions", {"whoCanCreateClasses": "ANYONE_IN_DOMAIN"}), None, "/Sales"),
    ("GCR-003 NotAssessed: setting not returned", "GCR-003", "NotAssessed", drop("classroom.api_data_access"), None, None),
    ("GCR-001 pass (not applicable): Classroom is switched off", "GCR-001", "Pass", both(off("classroom.service_status"), setting("classroom.class_membership", whoCanJoinClasses="ANYONE")), None, "switched off"),
]


class ClassroomChecks(unittest.TestCase):
    def test_healthy_tenant_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)

    def test_every_check_has_a_case_for_a_gap(self):
        coverage_test(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
