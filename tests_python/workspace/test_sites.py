"""Workspace Google Sites (GST-001) against the fake tenant."""

import unittest

from google_gap_assessment.workspace.checks import sites as MODULE
from tests_python.workspace.helpers import both, coverage_test, drop, healthy_passes, off, override, replace, run_cases, setting

# (name, finding id, expected status, mutate(tenant), options, text that must appear in affected/detail)
CASES = [
    ("GST-001 gap: Sites is enabled", "GST-001", "Gap", setting("sites.service_status", serviceState="ENABLED"), None, "ENABLED"),
    ("GST-001 gap: enabled for one OU", "GST-001", "Gap", override("/Sales", "sites.service_status", {"serviceState": "ENABLED"}), None, "/Sales"),
    ("GST-001 NotAssessed: no service status returned", "GST-001", "NotAssessed", drop("sites.service_status"), None, None),
]


class SitesChecks(unittest.TestCase):
    def test_healthy_tenant_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)

    def test_every_check_has_a_case_for_a_gap(self):
        coverage_test(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
