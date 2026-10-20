"""Workspace Google Chat (GCH-001..GCH-005) against the fake tenant."""

import unittest

from google_gap_assessment.workspace.checks import chat as MODULE
from tests_python.workspace.helpers import both, coverage_test, drop, healthy_passes, off, override, replace, run_cases, setting

# (name, finding id, expected status, mutate(tenant), options, text that must appear in affected/detail)
CASES = [
    ("GCH-001 gap: history off by default", "GCH-001", "Gap", setting("chat.chat_history", historyOnByDefault=False), None, None),
    ("GCH-002 gap: users can change history", "GCH-002", "Gap", setting("chat.chat_history", allowUserModification=True), None, None),
    ("GCH-003 gap: files can be shared externally", "GCH-003", "Gap", setting("chat.chat_file_sharing", externalFileSharing="ALL_FILES"), None, "ALL_FILES"),
    ("GCH-003 gap: images only is still sharing", "GCH-003", "Gap", setting("chat.chat_file_sharing", externalFileSharing="IMAGES_ONLY"), None, None),
    ("GCH-004 gap: space history can be turned off", "GCH-004", "Gap", setting("chat.space_history", historyState="DEFAULT_HISTORY_ON"), None, None),
    ("GCH-005 gap: external chat open to anyone", "GCH-005", "Gap", setting("chat.external_chat_restriction", allowExternalChat=True, externalChatRestriction="NO_RESTRICTION"), None, None),
    ("GCH-005 pass: external chat off", "GCH-005", "Pass", setting("chat.external_chat_restriction", allowExternalChat=False, externalChatRestriction="NO_RESTRICTION"), None, None),
    ("GCH-004 NotAssessed: setting not returned", "GCH-004", "NotAssessed", drop("chat.space_history"), None, None),
    ("GCH-001 gap: one OU turns history off", "GCH-001", "Gap", override("/Sales", "chat.chat_history", {"historyOnByDefault": False}), None, "/Sales"),
    ("GCH-001 pass (not applicable): Chat is switched off", "GCH-001", "Pass", off("chat.service_status"), None, "switched off"),
]


class ChatChecks(unittest.TestCase):
    def test_healthy_tenant_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)

    def test_every_check_has_a_case_for_a_gap(self):
        coverage_test(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
