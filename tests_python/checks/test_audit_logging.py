"""Logging (LOG-001..LOG-003) against the fake gcloud. Each case starts from a project that meets every check and breaks one setting, so a
failing case names the rule that regressed. An unreadable setting is NotAssessed, never a pass.

To redo or extend one check, find its id below. The check itself is the function registered for that id in
gcp_gap_assessment/checks/audit_logging.py."""

import unittest

from gcp_gap_assessment.checks import audit_logging as MODULE
from tests_python.helpers import healthy_passes, run_cases, DENIED

# (name, finding id, expected status, mutate(fixtures), options, text that must appear in affected/detail)
CASES = [
    ("LOG-001 gap: Data Read missing", "LOG-001", "Gap",
     lambda f: f["projects get-iam-policy"]["auditConfigs"][0].__setitem__("auditLogConfigs", [{"logType": "ADMIN_READ"}, {"logType": "DATA_WRITE"}]), None, "DATA_READ"),
    ("LOG-001 gap: no audit configuration", "LOG-001", "Gap", lambda f: f["projects get-iam-policy"].__setitem__("auditConfigs", []), None, None),
    ("LOG-001 gap: exempted principal", "LOG-001", "Gap",
     lambda f: f["projects get-iam-policy"]["auditConfigs"][0]["auditLogConfigs"][1].__setitem__("exemptedMembers", ["user:svc@contoso.com"]), None, "exempts"),
    ("LOG-002 gap: only sink has a filter", "LOG-002", "Gap", lambda f: f["logging sinks list"][0].__setitem__("filter", "severity>=ERROR"), None, None),
    ("LOG-002 gap: no sinks", "LOG-002", "Gap", lambda f: f.__setitem__("logging sinks list", []), None, None),
    ("LOG-002 gap: sink disabled", "LOG-002", "Gap", lambda f: f["logging sinks list"][0].__setitem__("disabled", True), None, None),
    ("LOG-003 gap: retention not locked", "LOG-003", "Gap", lambda f: f["storage buckets list"][0]["retention_policy"].__setitem__("isLocked", False), None, None),
    ("LOG-003 gap: no retention policy", "LOG-003", "Gap", lambda f: f["storage buckets list"][0].pop("retention_policy"), None, None),
    ("LOG-003 pass: no sink exports to Cloud Storage", "LOG-003", "Pass",
     lambda f: f["logging sinks list"][0].__setitem__("destination", "bigquery.googleapis.com/projects/p/datasets/d"), None, None),
    ("LOG-003 NotAssessed: export bucket unreadable", "LOG-003", "NotAssessed",
     lambda f: (f["logging sinks list"][0].__setitem__("destination", "storage.googleapis.com/elsewhere-bucket"),
                f.__setitem__("storage buckets describe gs://elsewhere-bucket", DENIED)), None, None),
]


class LoggingChecks(unittest.TestCase):
    def test_healthy_project_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
