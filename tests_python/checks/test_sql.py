"""Cloud SQL (SQL-001..SQL-004) against the fake gcloud. Each case starts from a project that meets every check and breaks one setting, so a
failing case names the rule that regressed. An unreadable setting is NotAssessed, never a pass.

To redo or extend one check, find its id below. The check itself is the function registered for that id in
google_gap_assessment/checks/sql.py."""

import unittest

from google_gap_assessment.cloud.checks import sql as MODULE
from tests_python.helpers import healthy_passes, run_cases, DISABLED

# (name, finding id, expected status, mutate(fixtures), options, text that must appear in affected/detail)
CASES = [
    ("SQL-001 gap: public IP", "SQL-001", "Gap", lambda f: f["sql instances list"][0]["settings"]["ipConfiguration"].__setitem__("ipv4Enabled", True), None, None),
    ("SQL-002 gap: 0.0.0.0/0 authorized", "SQL-002", "Gap",
     lambda f: f["sql instances list"][0]["settings"]["ipConfiguration"].__setitem__("authorizedNetworks", [{"value": "0.0.0.0/0"}]), None, None),
    ("SQL-003 gap: sslMode allows plaintext", "SQL-003", "Gap",
     lambda f: f["sql instances list"][0]["settings"]["ipConfiguration"].__setitem__("sslMode", "ALLOW_UNENCRYPTED_AND_ENCRYPTED"), None, None),
    ("SQL-003 gap: legacy requireSsl false", "SQL-003", "Gap",
     lambda f: (f["sql instances list"][0]["settings"]["ipConfiguration"].pop("sslMode"), f["sql instances list"][0]["settings"]["ipConfiguration"].__setitem__("requireSsl", False)), None, None),
    ("SQL-003 pass: legacy requireSsl true", "SQL-003", "Pass",
     lambda f: (f["sql instances list"][0]["settings"]["ipConfiguration"].pop("sslMode"), f["sql instances list"][0]["settings"]["ipConfiguration"].__setitem__("requireSsl", True)), None, None),
    ("SQL-004 gap: backups off", "SQL-004", "Gap", lambda f: f["sql instances list"][0]["settings"]["backupConfiguration"].__setitem__("enabled", False), None, None),
    ("SQL-004 pass: read replica", "SQL-004", "Pass",
     lambda f: (f["sql instances list"][0].__setitem__("instanceType", "READ_REPLICA_INSTANCE"), f["sql instances list"][0]["settings"]["backupConfiguration"].__setitem__("enabled", False)), None, None),
    ("SQL-001 NotAssessed: no network settings", "SQL-001", "NotAssessed", lambda f: f["sql instances list"][0]["settings"].pop("ipConfiguration"), None, None),
    ("SQL-001 pass (not applicable): Cloud SQL API disabled", "SQL-001", "Pass", lambda f: f.__setitem__("sql instances list", DISABLED), None, "Not applicable"),
]


class SqlChecks(unittest.TestCase):
    def test_healthy_project_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
