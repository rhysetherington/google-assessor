"""Cloud Storage (STO-001, STO-002) against the fake gcloud. Each case starts from a project that meets every check and breaks one setting, so a
failing case names the rule that regressed. An unreadable setting is NotAssessed, never a pass.

To redo or extend one check, find its id below. The check itself is the function registered for that id in
google_gap_assessment/checks/storage.py."""

import unittest

from google_gap_assessment.cloud.checks import storage as MODULE
from tests_python.helpers import healthy_passes, run_cases, DENIED

# (name, finding id, expected status, mutate(fixtures), options, text that must appear in affected/detail)
CASES = [
    ("STO-001 gap: bucket readable by allUsers", "STO-001", "Gap",
     lambda f: f["storage buckets get-iam-policy gs://data-bucket"]["bindings"].append({"role": "roles/storage.objectViewer", "members": ["allUsers"]}), None, "data-bucket"),
    ("STO-001 pass: public access prevention enforced", "STO-001", "Pass",
     lambda f: (f["storage buckets list"][1].__setitem__("public_access_prevention", "enforced"),
                f["storage buckets get-iam-policy gs://data-bucket"]["bindings"].append({"role": "r", "members": ["allUsers"]})), None, None),
    ("STO-001 NotAssessed: bucket policy unreadable", "STO-001", "NotAssessed", lambda f: f.__setitem__("storage buckets get-iam-policy gs://data-bucket", DENIED), None, None),
    ("STO-002 gap: uniform access off", "STO-002", "Gap", lambda f: f["storage buckets list"][1].__setitem__("uniform_bucket_level_access", False), None, None),
    ("STO-002 NotAssessed: setting not returned", "STO-002", "NotAssessed", lambda f: f["storage buckets list"][1].pop("uniform_bucket_level_access"), None, None),
    ("STO-002 gap: camelCase nested enabled=false", "STO-002", "Gap",
     lambda f: (f["storage buckets list"][1].pop("uniform_bucket_level_access"), f["storage buckets list"][1].__setitem__("uniformBucketLevelAccess", {"enabled": False})), None, None),
]


class StorageChecks(unittest.TestCase):
    def test_healthy_project_passes_every_check(self):
        healthy_passes(self, MODULE)

    def test_individual_cases(self):
        run_cases(self, MODULE, CASES)


if __name__ == "__main__":
    unittest.main()
