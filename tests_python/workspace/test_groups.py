"""Workspace Groups for Business (GGR-001..GGR-006) against the fake tenant."""

import unittest

from google_gap_assessment.workspace.checks import groups as MODULE
from tests_python.workspace.helpers import both, coverage_test, drop, healthy_passes, off, override, replace, run_cases, setting

# (name, finding id, expected status, mutate(tenant), options, text that must appear in affected/detail)
CASES = [
    ("GGR-001 gap: groups open to outsiders", "GGR-001", "Gap", setting("groups_for_business.groups_sharing", collaborationCapability="ANYONE_CAN_ACCESS"), None, "ANYONE_CAN_ACCESS"),
    ("GGR-002 gap: owners can add external members", "GGR-002", "Gap", setting("groups_for_business.groups_sharing", ownersCanAllowExternalMembers=True), None, None),
    ("GGR-003 gap: owners can let the public post", "GGR-003", "Gap", setting("groups_for_business.groups_sharing", ownersCanAllowIncomingMailFromPublic=True), None, None),
    ("GGR-004 gap: anyone can create groups", "GGR-004", "Gap", setting("groups_for_business.groups_sharing", createGroupsAccessLevel="ANYONE_CAN_CREATE"), None, None),
    ("GGR-005 gap: conversations visible to the whole domain", "GGR-005", "Gap", setting("groups_for_business.groups_sharing", viewTopicsDefaultAccessLevel="DOMAIN_USERS"), None, None),
    ("GGR-006 gap: owners can hide groups", "GGR-006", "Gap", setting("groups_for_business.groups_sharing", ownersCanHideGroups=True), None, None),
    ("GGR-006 gap: new groups hidden by default", "GGR-006", "Gap", setting("groups_for_business.groups_sharing", newGroupsAreHidden=True), None, None),
    ("GGR-001 gap: one OU lets outsiders in", "GGR-001", "Gap", override("/Sales", "groups_for_business.groups_sharing", {"collaborationCapability": "ANYONE_CAN_ACCESS"}), None, "/Sales"),
    ("GGR-001 pass (not applicable): Groups is switched off", "GGR-001", "Pass", off("groups_for_business.service_status"), None, "switched off"),
    ("GGR-001 pass: documented defaults already meet it", "GGR-001", "Pass", drop("groups_for_business.groups_sharing"), None, None),
]


class GroupsChecks(unittest.TestCase):
    def test_healthy_tenant_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)

    def test_every_check_has_a_case_for_a_gap(self):
        coverage_test(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
